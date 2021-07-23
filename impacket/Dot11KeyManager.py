# Impacket - Collection of Python classes for working with network protocols.
#
# SECUREAUTH LABS. Copyright (C) 2021 SecureAuth Corporation. All rights reserved.
#
# This software is provided under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Description:
#   IEEE 802.11 Network packet codecs.
#
# Author:
#   Gustavo Moreira

from array import array
class KeyManager:
    def __init__(self):
        self.keys = {}
        
    def __get_bssid_hasheable_type(self, bssid):
        # List is an unhashable type
        if not isinstance(bssid, (list,tuple,array)):
            raise Exception('BSSID datatype must be a tuple, list or array')
        return tuple(bssid) 

    def add_key(self, bssid, key):
        bssid=self.__get_bssid_hasheable_type(bssid)
        if bssid not in self.keys:
            self.keys[bssid] = key
            return True
        else:
            return False
        
    def replace_key(self, bssid, key):
        bssid=self.__get_bssid_hasheable_type(bssid)
        self.keys[bssid] = key
        
        return True
        
    def get_key(self, bssid):
        bssid=self.__get_bssid_hasheable_type(bssid)
        if bssid in self.keys:
            return self.keys[bssid]
        else:
            return False
        
    def delete_key(self, bssid):
        bssid=self.__get_bssid_hasheable_type(bssid)
        if not isinstance(bssid, list):
            raise Exception('BSSID datatype must be a list')
        
        if bssid in self.keys:
            del self.keys[bssid] 
            return True
        
        return False
