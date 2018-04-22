# Copyright (c) 2003-2016 CORE Security Technologies
#
# This software is provided under under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Description:
#  IEEE 802.11 Network packet codecs.
#
# Author:
#  Gustavo Moreira
import binascii
import codecs
class RC4():
    def __init__(self, key):
        if isinstance(key, bytes):
            key = key.decode("latin1")

        j = 0
        self.state = list(range(256))
        for i in range(256):
            j = (j + self.state[i] + ord(key[i % len(key)])) & 0xff
            self.state[i],self.state[j] = self.state[j],self.state[i] # SSWAP(i,j)

    def encrypt(self, data):
        if isinstance(data, bytes):
            data = data.decode("latin1")

        i = j = 0
        out=''
        for char in data:
            i = (i+1) & 0xff
            j = (j+self.state[i]) & 0xff
            self.state[i],self.state[j] = self.state[j],self.state[i] # SSWAP(i,j)
            out+=chr(ord(char) ^ self.state[(self.state[i] + self.state[j]) & 0xff])

        return out
    
    def decrypt(self, data):
        # It's symmetric
        return self.encrypt(data)
