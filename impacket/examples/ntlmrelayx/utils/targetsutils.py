# Impacket - Collection of Python classes for working with network protocols.
#
# SECUREAUTH LABS. Copyright (C) 2021 SecureAuth Corporation. All rights reserved.
#
# This software is provided under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Description:
#   Target utilities
#
#   Classes for handling specified targets and keeping state of which targets have been processed
#   Format of targets are based in URI syntax
#       scheme://netloc/path
#   where:
#       scheme: the protocol to target (e.g. 'smb', 'mssql', 'all')
#       netloc: int the form of domain\username@host:port (domain\username and port are optional, and don't forget
#               to escape the '\')
#       path: only used by specific attacks (e.g. HTTP attack).
#
#   Some examples:
#       smb://1.1.1.1: It will target host 1.1.1.1 (protocol SMB) with any user connecting
#       mssql://contoso.com\joe@10.1.1.1: It will target host 10.1.1.1 (protocol MSSQL) only when contoso.com\joe is
#       connecting.
#
# Author:
#   Alberto Solino (@agsolino)
#   Dirk-jan Mollema / Fox-IT (https://www.fox-it.com)
#
# ToDo:
#   [ ]: Expand the ALL:// to all the supported protocols
#
import os
import random
import time
try:
    from urllib.parse import urlparse
except ImportError:
    from urlparse import urlparse
from impacket import LOG
from threading import Thread


class TargetsProcessor:
    def __init__(self, targetListFile=None, singleTarget=None, protocolClients=None, randomize=False):
        # Here we store the attacks that already finished, mostly the ones that have usernames, since the
        # other ones will never finish.
        self.finishedAttacks = []
        self.protocolClients = protocolClients
        if targetListFile is None:
            self.filename = None
            self.originalTargets = self.processTarget(singleTarget, protocolClients)
        else:
            self.filename = targetListFile
            self.originalTargets = []
            self.readTargets()

        if randomize is True:
            # Randomize the targets based
            random.shuffle(self.originalTargets)

        self.generalCandidates = [x for x in self.originalTargets if x.username is None]
        self.namedCandidates = [x for x in self.originalTargets if x.username is not None]

    @staticmethod
    def processTarget(target, protocolClients):
        # Check if we have a single target, with no URI form
        if target.find('://') <= 0:
            # Target is a single IP, assuming it's SMB.
            return [urlparse('smb://%s' % target)]

        # Checks if it needs to expand the list if there's a all://*
        retVals = []
        if target[:3].upper() == 'ALL':
            strippedTarget = target[3:]
            for protocol in protocolClients:
                retVals.append(urlparse('%s%s' % (protocol, strippedTarget)))
            return retVals
        else:
            return [urlparse(target)]

    def readTargets(self):
        try:
            with open(self.filename,'r') as f:
                self.originalTargets = []
                for line in f:
                    target = line.strip()
                    if target != '' and target[0] != '#':
                        self.originalTargets.extend(self.processTarget(target, self.protocolClients))
        except IOError as e:
            LOG.error("Could not open file: %s - %s", self.filename, str(e))

        if len(self.originalTargets) == 0:
            LOG.critical("Warning: no valid targets specified!")

        self.generalCandidates = [x for x in self.originalTargets if x not in self.finishedAttacks and x.username is None]
        self.namedCandidates = [x for x in self.originalTargets if x not in self.finishedAttacks and x.username is not None]

    def logTarget(self, target, gotRelay = False, gotUsername = None):
        # If the target has a username, we can safely remove it from the list. Mission accomplished.
        if gotRelay is True:
            if target.username is not None:
                self.finishedAttacks.append(target)
            elif gotUsername is not None:
                # We have data about the username we relayed the connection for,
                # for a target that didn't have username specified.
                # Let's log it
                newTarget = urlparse('%s://%s@%s%s' % (target.scheme, gotUsername.replace('/','\\'), target.netloc, target.path))
                self.finishedAttacks.append(newTarget)

    def getTarget(self, identity=None):
        # ToDo: We should have another list of failed attempts (with user) and check that inside this method so we do not
        # retry those targets.
        if identity is not None and len(self.namedCandidates) > 0:
            # We've been asked to match a username that is connected to us
            # Do we have an explicit request for it?
            for target in self.namedCandidates:
                if target.username is not None:
                    if target.username.upper() == identity.replace('/', '\\'):
                        self.namedCandidates.remove(target)
                        return target
                    if target.username.find('\\') < 0:
                        # Username with no domain, let's compare that way
                        if target.username.upper() == identity.split('/')[1]:
                            self.namedCandidates.remove(target)
                            return target

        # No identity match, let's just grab something from the generalCandidates list
        # Assuming it hasn't been relayed already
        if len(self.generalCandidates) > 0:
            if identity is not None:
                for target in self.generalCandidates:
                    tmpTarget = '%s://%s@%s' % (target.scheme, identity.replace('/', '\\'), target.netloc)
                    match = [x for x in self.finishedAttacks if x.geturl().upper() == tmpTarget.upper()]
                    if len(match) == 0:
                        self.generalCandidates.remove(target)
                        return target
                LOG.debug("No more targets for user %s" % identity)
                return None
            else:
                return self.generalCandidates.pop()
        else:
            if len(self.originalTargets) > 0:
                self.generalCandidates = [x for x in self.originalTargets if
                                          x not in self.finishedAttacks and x.username is None]

        if len(self.generalCandidates) == 0:
            if len(self.namedCandidates) == 0:
                # We are here, which means all the targets are already exhausted by the client
                LOG.info("All targets processed!")
            elif identity is not None:
                # This user has no more targets
                LOG.debug("No more targets for user %s" % identity)
            return None
        else:
            return self.getTarget(identity)

class TargetsFileWatcher(Thread):
    def __init__(self,targetprocessor):
        Thread.__init__(self)
        self.targetprocessor = targetprocessor
        self.lastmtime = os.stat(self.targetprocessor.filename).st_mtime

    def run(self):
        while True:
            mtime = os.stat(self.targetprocessor.filename).st_mtime
            if mtime > self.lastmtime:
                LOG.info('Targets file modified - refreshing')
                self.lastmtime = mtime
                self.targetprocessor.readTargets()
            time.sleep(1.0)
