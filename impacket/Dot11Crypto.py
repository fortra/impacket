# Impacket - Collection of Python classes for working with network protocols.
#
# SECUREAUTH LABS. Copyright (C) 2018 SecureAuth Corporation. All rights reserved.
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
#

class RC4():
    def __init__(self, key):
        bkey = bytearray(key)
        j = 0
        self.state = bytearray(range(256))
        for i in range(256):
            j = (j + self.state[i] + bkey[i % len(key)]) & 0xff
            self.state[i],self.state[j] = self.state[j],self.state[i] # SSWAP(i,j)

    def encrypt(self, data):
        i = j = 0
        out=bytearray()
        for char in bytearray(data):
            i = (i+1) & 0xff
            j = (j+self.state[i]) & 0xff
            self.state[i],self.state[j] = self.state[j],self.state[i] # SSWAP(i,j)
            out.append(char ^ self.state[(self.state[i] + self.state[j]) & 0xff])
        
        return bytes(out)
    
    def decrypt(self, data):
        # It's symmetric
        return self.encrypt(data)
