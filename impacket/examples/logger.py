#!/usr/bin/python
# Copyright (c) 2003-2013 CORE Security Technologies
#
# This software is provided under under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Description: This logger is intended to be used by impacket instead
# of printing directly. This will allow other libraries to use their
# custom logging implementation.
#

class ImpacketLogger:        
    def logMessage(self,message):
        print message
        
    
