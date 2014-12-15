# Copyright (c) 2003-2014 CORE Security Technologies
#
# This software is provided under under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# $Id$
#
# Author: Alberto Solino (bethus@gmail.com, @agsolino)
#
# Description:
#   Kerberos Credential Cache format implementation
#   based on file format described at:
#   http://repo.or.cz/w/krb5dissect.git/blob_plain/HEAD:/ccache.txt
#

import sys
from datetime import datetime
from struct import pack, unpack, calcsize
from impacket.winregistry import hexdump
from impacket.structure import Structure
from impacket.krb5 import crypto, constants, types
from impacket.krb5.asn1 import AS_REP, seq_set, EncryptedData, TGS_REP
from pyasn1.codec.der import decoder, encoder


DELTA_TIME = 1

class Header(Structure):
    structure = (
        ('tag','!H=0'),
        ('taglen','!H=0'),
        ('_tagdata','_-tagdata','self["taglen"]'),
        ('tagdata',':'),
    )

class DeltaTime(Structure):
    structure = (
        ('time_offset','!L=0'),
        ('usec_offset','!L=0'),
    )

class CountedOctetString(Structure):
    structure = (
        ('length','!L=0'),
        ('_data','_-data','self["length"]'),
        ('data',':'),
    )

    def prettyPrint(self, indent=''):
        return "%s%s" % (indent, self['data'].encode('hex'))

class KeyBlock(Structure):
    structure = (
        ('keytype','!H=0'),
        ('etype','!H=0'),
        ('keylen','!H=0'),
        ('_keyvalue','_-keyvalue','self["keylen"]'),
        ('keyvalue',':'),
    )

    def prettyPrint(self):
        return "Key: (0x%x)%s" % (self['keytype'], self['keyvalue'].encode('hex'))

class Times(Structure):
    structure = (
        ('authtime','!L=0'),
        ('starttime','!L=0'),
        ('endtime','!L=0'),
        ('renew_till','!L=0'),
    )
    def prettyPrint(self, indent = ''):
        print "%sAuth : %s" % (indent, datetime.fromtimestamp(self['authtime']).isoformat())
        print "%sStart: %s" % (indent, datetime.fromtimestamp(self['starttime']).isoformat())
        print "%sEnd  : %s" % (indent, datetime.fromtimestamp(self['endtime']).isoformat())
        print "%sRenew: %s" % (indent, datetime.fromtimestamp(self['renew_till']).isoformat())

class Address(Structure):
    structure = (
        ('addrtype','!H=0'),
        ('addrdata',':', CountedOctetString),
    )

class AuthData(Structure):
    structure = (
        ('authtype','!H=0'),
        ('authdata',':', CountedOctetString),
    )

class Principal():
    class PrincipalHeader(Structure):
        structure = (
            ('name_type','!L=0'),
            ('num_components','!L=0'),
        )
    components = None
    realm = None
    def __init__(self, data=None):
        if data is not None:
            self.header = self.PrincipalHeader(data)
            data = data[len(self.header):]
            self.realm = CountedOctetString(data)
            data = data[len(self.realm):]
            self.components = []
            for component in range(self.header['num_components']):
                comp = CountedOctetString(data)
                data = data[len(comp):]
                self.components.append(comp)

    def __len__(self):
        totalLen = len(self.header) + len(self.realm)
        for i in self.components:
            totalLen += len(i)
        return totalLen
 
    def getData(self):
        data = self.header.getData() + self.realm.getData()
        for component in self.components:
            data += component.getData()
        return data

    def __str__(self):
        return self.getData()

    def prettyPrint(self):
        principal = ''
        for component in self.components:
            principal += component['data'] + '/'
        
        principal = principal[:-1]
        principal += '@' + self.realm['data']
        return principal

    def toPrincipal(self):
        return types.Principal(self.prettyPrint(), type=self.header['name_type'])

class Credential():
    class CredentialHeader(Structure):
        structure = (
            ('client',':', Principal),
            ('server',':', Principal),
            ('key',':', KeyBlock),
            ('time',':', Times),
            ('is_skey','B=0'),
            ('tktflags','!L=0'),
            ('num_address','!L=0'),
        )

    addresses = ()
    authData = ()
    header = None
 
    def __init__(self, data=None):
        if data is not None:
            self.header = self.CredentialHeader(data)
            data = data[len(self.header):]
            self.addresses = []
            for address in range(self.header['num_address']):
                ad = Address(data)
                data = data[len(ad):]
                self.addresses.append(ad)
            num_authdata = unpack('!L', data[:4])[0]
            data = data[calcsize('!L'):]
            for authdata in range(num_authdata):
                ad = AuthData(data)
                data = data[len(ad):]
                self.authData.append(ad)
            self.ticket = CountedOctetString(data)
            data = data[len(self.ticket):]
            self.secondTicket = CountedOctetString(data)
            data = data[len( self.secondTicket):]

    def __getitem__(self, key):
        return self.header[key] 

    def getServerPrincipal(self):
        return self.header['server'].prettyPrint()

    def __len__(self):
        totalLen = len(self.header) 
        for i in self.addresses:
            totalLen += len(i)
        totalLen += calcsize('!L')
        for i in self.authData:
            totalLen += len(i)
        totalLen += len(self.ticket)
        totalLen += len(self.secondTicket)
        return totalLen
 
    def getData(self):
        data = self.header.getData()
        for i in self.addresses:
            data += i.getData()
        data += pack('!L', len(self.authData))
        for i in self.authData:
            data += i.getData()
        data += self.ticket.getData()
        data += self.secondTicket.getData()
        return data

    def __str__(self):
        return self.getData()

    def prettyPrint(self, indent=''):
        print "%sClient: %s" % (indent, self.header['client'].prettyPrint())
        print "%sServer: %s" % (indent, self.header['server'].prettyPrint())
        print "%s%s" % (indent, self.header['key'].prettyPrint())
        print "%sTimes: " % indent
        self.header['time'].prettyPrint('\t\t')
        print "%sSubKey: %s" % (indent, self.header['is_skey'])
        print "%sFlags: 0x%x" % (indent, self.header['tktflags'])
        print "%sAddresses: %d" % (indent, self.header['num_address'])
        for address in self.addresses:
            address.prettyPrint('\t\t')
        print "%sAuth Data: %d" % (indent, len(self.authData))
        for ad in self.authData:
            ad.prettyPrint('\t\t')
        print "%sTicket: %s" % (indent, self.ticket.prettyPrint())
        print "%sSecond Ticket: %s" % (indent, self.secondTicket.prettyPrint())

    def toTGT(self):
        tgt_rep = AS_REP()
        tgt_rep['pvno'] = 5
        tgt_rep['msg-type'] = int(constants.ApplicationTagNumbers.AP_REP.value)
        tgt_rep['crealm'] = self['server'].realm['data']

        # Fake EncryptedData
        tgt_rep['enc-part'] = None
        tgt_rep['enc-part']['etype'] = 1 
        tgt_rep['enc-part']['cipher'] = '' 
        seq_set(tgt_rep, 'cname', self['client'].toPrincipal().components_to_asn1)
        ticket = types.Ticket()
        ticket.from_asn1(self.ticket['data'])
        seq_set(tgt_rep,'ticket', ticket.to_asn1)

        cipher = crypto._enctype_table[self['key']['keytype']]()

        tgt = dict()
        tgt['KDC_REP'] = encoder.encode(tgt_rep)
        tgt['cipher'] = cipher
        tgt['sessionKey'] = crypto.Key(cipher.enctype, str(self['key']['keyvalue']))
        return tgt
        
    def toTGS(self):
        tgs_rep = TGS_REP()
        tgs_rep['pvno'] = 5
        tgs_rep['msg-type'] = int(constants.ApplicationTagNumbers.TGS_REP.value)
        tgs_rep['crealm'] = self['server'].realm['data']

        # Fake EncryptedData
        tgs_rep['enc-part'] = None
        tgs_rep['enc-part']['etype'] = 1 
        tgs_rep['enc-part']['cipher'] = '' 
        seq_set(tgs_rep, 'cname', self['client'].toPrincipal().components_to_asn1)
        ticket = types.Ticket()
        ticket.from_asn1(self.ticket['data'])
        seq_set(tgs_rep,'ticket', ticket.to_asn1)

        cipher = crypto._enctype_table[self['key']['keytype']]()

        tgs = dict()
        tgs['KDC_REP'] = encoder.encode(tgs_rep)
        tgs['cipher'] = cipher
        tgs['sessionKey'] = crypto.Key(cipher.enctype, str(self['key']['keyvalue']))
        return tgs
        
class CCache():
    headers = None
    principal = None
    credentials = None
    class MiniHeader(Structure):
        structure = (
            ('file_format_version','!H=0x0504'),
            ('headerlen','!H=0'),
        )

    def __init__(self, data = None):
        miniHeader = self.MiniHeader(data)

        data = data[len(str(miniHeader)):]

        headerLen = miniHeader['headerlen']

        self.headers = []
        while headerLen > 0:
            header = Header(data)
            self.headers.append(header)
            headerLen -= len(header)
            data = data[len(header):]

        # Now the primary_principal
        self.principal = Principal(data)
    
        data = data[len(self.principal):]
        
        # Now let's parse the credentials
        self.credentials = []
        while len(data) > 0:
            cred = Credential(data)
            self.credentials.append(cred)
            data = data[len(cred):]

    def getCredential(self, server):
        for c in self.credentials:
            if c['server'].prettyPrint() == server:
                return c
        return None

    @classmethod
    def loadFile(cls, fileName):
        f = open(fileName)
        data = f.read()
        f.close()
        return cls(data)

    def saveFile(self, fileName):
        pass

    def prettyPrint(self):
        print "Primary Principal: %s" % self.principal.prettyPrint()
        print "Credentials: "
        for i, credential in enumerate(self.credentials):
            print "[%d]" % i
            credential.prettyPrint('\t') 


if __name__ == '__main__':
    import os
    ccache = CCache.loadFile(os.getenv('KRB5CCNAME'))
    ccache.prettyPrint()
