# SECUREAUTH LABS. Copyright 2018 SecureAuth Corporation. All rights reserved.
#
# This software is provided under under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Target utilities
#
# Author:
#  Alberto Solino (@agsolino)
#  Dirk-jan Mollema / Fox-IT (https://www.fox-it.com)
#
# Description:
#     Classes for handling specified targets and keeping state of which targets have been processed
#     Format of targets are based in URI syntax
#         scheme://netloc/path
#     where:
#         scheme: the protocol to target (e.g. 'smb', 'mssql', 'all')
#         netloc: int the form of domain\username@host:port (domain\username and port are optional, and don't forget
#                 to escape the '\')
#         path: only used by specific attacks (e.g. HTTP attack).
#
#     Some examples:
#
#         smb://1.1.1.1: It will target host 1.1.1.1 (protocol SMB) with any user connecting
#         mssql://contoso.com\joe@10.1.1.1: It will target host 10.1.1.1 (protocol MSSQL) only when contoso.com\joe is
#         connecting.
#
#  ToDo:
# [ ]: Expand the ALL:// to all the supported protocols


import os
import random
import time
from urlparse import urlparse
from impacket import LOG
from threading import Thread


class TargetsProcessor:
    def __init__(self, targetListFile=None, singleTarget=None, protocolClients=None):
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

        self.candidates = [x for x in self.originalTargets]

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
                    if target is not None:
                        self.originalTargets.extend(self.processTarget(target, self.protocolClients))
        except IOError, e:
            LOG.error("Could not open file: %s - " % (self.filename, str(e)))

        if len(self.originalTargets) == 0:
            LOG.critical("Warning: no valid targets specified!")

        self.candidates = [x for x in self.originalTargets if x not in self.finishedAttacks]

    def logTarget(self, target, gotRelay = False):
        # If the target has a username, we can safely remove it from the list. Mission accomplished.
        if gotRelay is True:
            if target.username is not None:
                self.finishedAttacks.append(target)

    def getTarget(self, choose_random=False):
        if len(self.candidates) > 0:
            if choose_random is True:
                return random.choice(self.candidates)
            else:
                return self.candidates.pop()
        else:
            if len(self.originalTargets) > 0:
                self.candidates = [x for x in self.originalTargets if x not in self.finishedAttacks]
            else:
                #We are here, which means all the targets are already exhausted by the client
                LOG.info("All targets processed!")

        return self.candidates.pop()

class TargetsFileWatcher(Thread):
    def __init__(self,targetprocessor):
        Thread.__init__(self)
        self.targetprocessor = targetprocessor
        self.lastmtime = os.stat(self.targetprocessor.filename).st_mtime
        #print self.lastmtime

    def run(self):
        while True:
            mtime = os.stat(self.targetprocessor.filename).st_mtime
            if mtime > self.lastmtime:
                LOG.info('Targets file modified - refreshing')
                self.lastmtime = mtime
                self.targetprocessor.readTargets()
            time.sleep(1.0)
