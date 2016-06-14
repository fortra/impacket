#!/usr/bin/python
# Copyright (c) 2013-2016 CORE Security Technologies
#
# This software is provided under under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Target utilities
#
# Author:
#  Dirk-jan Mollema / Fox-IT (https://www.fox-it.com)
#
# Description:
#     Classes for handling specified targets and keeping 
# state of which targets have been processed
import logging
import os
import random
import re
import time
from threading import Thread


class TargetsProcessor():
    supported_protocols = ['SMB','HTTP','LDAP','MSSQL','LDAPS']
    def __init__(self,targetlistfile=None,singletarget=None):        
        self.targetregex = re.compile(r'([a-zA-Z]+)://([a-zA-Z0-9\.\-_]+)(:[0-9]+)?/?(.*)?')
        self.targetipregex = re.compile(r'[a-zA-Z\.\-_0-9]+')
        self.clients_targets = {}
        if targetlistfile is None:
            self.filename = None
            self.targets = [self.parse_target(singletarget)]
        else:
            self.filename = targetlistfile
            self.targets = []
            self.read_targets()

    def read_targets(self):
        try:
            with open(self.filename,'r') as f:
                self.targets = []
                for line in f:
                    target = self.parse_target(line.strip())
                    if target is not None:
                        self.targets.append(target)
        except IOError, e:
            logging.error("Could not open file: %s" % self.filename)
            logging.error(str(e))
        if len(self.targets) == 0:
            logging.critical("Warning: no valid targets specified!")

    def parse_target(self,targetline):
        #Try a full target match in the form of protocol://target:port/path first
        ftm = self.targetregex.match(targetline)
        if ftm is not None:
            if ftm.group(1).upper() not in self.supported_protocols:
                logging.error("Unsupported protocol: %s" % ftm.group(1))
                return None
            #Check if the port was specified
            if ftm.group(3) is None:
                port = self.get_default_port(ftm.group(1))
            else:
                #Port regex includes the : remove this
                port = int(ftm.group(3)[1:])
            #Check if the path was specified
            if ftm.group(4) is None:
                path = ''
            else:
                path = ftm.group(4)
            #Targets are always a tuple (protocol,host,port)
            #TODO: Change this to an object so we can have proper representation as string?
            return (ftm.group(1).upper(),ftm.group(2),port,path)
        #Maybe the target is just an IP, this assumes its an SMB target
        itm = self.targetipregex.match(targetline)
        if itm is not None:
            return ('SMB',itm.group(0),445,'')
        #If both dont match, it is probably an invalid target
        logging.error("Invalid target specification: " % targetline)
        return None

    def log_target(self,client,target):
        try:
            self.clients_targets[client].add(target)
        except KeyError:
            self.clients_targets[client] = set([target])
        #print self.clients_targets

    def get_target(self,client):
        try:
            targetlist = self.clients_targets[client]
        except KeyError:
            #Client is probably new
            return self.targets[0]
        for target in self.targets:
            #Check if the target is already in the target list
            if target not in targetlist:
                return target
        #We are here, which means all the targets are already exhausted by the client
        logging.info("All targets processed for client %s" % client)
        return random.choice(self.targets)

    def get_default_port(self,protocol):
        if protocol.upper() == 'SMB':
            return 445
        if protocol.upper() == 'HTTP':
            return 80
        if protocol.upper() == 'HTTPS':
            return 443
        if protocol.upper() == 'LDAP':
            return 389
        if protocol.upper() == 'LDAPS':
            return 636
        if protocol.upper() == 'MSSQL':
            return 1433
        return None

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
                logging.info('Targets file modified - refreshing')
                self.lastmtime = mtime
                self.targetprocessor.read_targets()
            time.sleep(1.0)

class ProxyIpTranslator(Thread):
    def __init__(self):
        Thread.__init__(self)
        self.regex = re.compile(r'SRC=([0-9\.]+) DST=([0-9\.]+) .*SPT=([0-9]+)')
        self.iptranslations = {}
    #-A POSTROUTING -o eth0 -j LOG --log-prefix="SMBrelay"
    def run(self):
        logging.info("Setting up Proxy translator - reading from kernel log")
        for line in tail("-f", "/var/log/kern.log", _iter=True):
            if "SMBrelay" in line:
                m = self.regex.search(line)
                if m is not None:
                    self.iptranslations[(m.group(1),m.group(3))] = m.group(2)
                    #logging.info('Found translation from ip: %s port: %s to IP: %s' % (m.group(1),m.group(3),m.group(2)))

    #Look up the destination IP based on source IP and port
    def translate(self,source_ip,source_port):
        try:
            return self.iptranslations[(source_ip,str(source_port))]
        except KeyError:
            return None

