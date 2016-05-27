#!/usr/bin/python
# Copyright (c) 2013-2016 CORE Security Technologies
#
# This software is provided under under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Config utilities
#
# Author:
#  Dirk-jan Mollema / Fox-IT (https://www.fox-it.com)
#
# Description:
#     Configuration class which holds the config specified on the 
# command line, this can be passed to the tools' servers and clients
class NTLMRelayxConfig:
    def __init__(self):
        self.daemon = True
        self.domainIp = None
        self.machineAccount = None
        self.machineHashes = None
        self.exeFile = None
        self.command = None
        self.target = None
        self.mode = None
        self.redirecthost = None
        self.outputFile = None
        self.attacks = None
        self.lootdir = None

    def setOutputFile(self,outputFile):
        self.outputFile = outputFile

    def setTargets(self, target):
        self.target = target

    def setExeFile(self, filename):
        self.exeFile = filename

    def setCommand(self, command):
        self.command = command

    def setMode(self,mode):
        self.mode = mode

    def setAttacks(self,attacks):
        self.attacks = attacks

    def setLootdir(self,lootdir):
        self.lootdir = lootdir

    def setRedirectHost(self,redirecthost):
        self.redirecthost = redirecthost

    def setDomainAccount( self, machineAccount,  machineHashes, domainIp):
        self.machineAccount = machineAccount
        self.machineHashes = machineHashes
        self.domainIp = domainIp