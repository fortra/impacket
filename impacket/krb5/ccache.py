# Copyright (c) 2003-2016 CORE Security Technologies
#
# This software is provided under under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Author: Alberto Solino (@agsolino)
#
# Description:
#   Kerberos Credential Cache format implementation
#   based on file format described at:
#   http://repo.or.cz/w/krb5dissect.git/blob_plain/HEAD:/ccache.txt
#   Pretty lame and quick implementation, not a fun thing to do
#   Contribution is welcome to make it the right way
#

from datetime import datetime
from struct import pack, unpack, calcsize

from pyasn1.codec.der import decoder, encoder
from binascii import hexlify

from impacket.structure import Structure
from impacket.krb5 import crypto, constants, types
from impacket.krb5.asn1 import AS_REP, seq_set, TGS_REP, EncTGSRepPart, EncASRepPart, Ticket

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
        return "%s%s" % (indent, hexlify(self['data']))

class KeyBlock(Structure):
    structure = (
        ('keytype','!H=0'),
        ('etype','!H=0'),
        ('keylen','!H=0'),
        ('_keyvalue','_-keyvalue','self["keylen"]'),
        ('keyvalue',':'),
    )

    def prettyPrint(self):
        return "Key: (0x%x)%s" % (self['keytype'], hexlify(self['keyvalue']))

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

class Principal:
    class PrincipalHeader(Structure):
        structure = (
            ('name_type','!L=0'),
            ('num_components','!L=0'),
        )
    def __init__(self, data=None):
        self.components = []
        self.realm = None
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
        else:
            self.header = self.PrincipalHeader()

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

    def fromPrincipal(self, principal):
        self.header['name_type'] = principal.type
        self.header['num_components'] = len(principal.components)
        octetString = CountedOctetString()
        octetString['length'] = len(principal.realm)
        octetString['data'] = principal.realm
        self.realm = octetString
        self.components = []
        for c in principal.components:
            octetString = CountedOctetString()
            octetString['length'] = len(c)
            octetString['data'] = c
            self.components.append(octetString)

    def toPrincipal(self):
        return types.Principal(self.prettyPrint(), type=self.header['name_type'])

class Credential:
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

    def __init__(self, data=None):
        self.addresses = ()
        self.authData = ()
        self.header = None
        self.ticket = None
        self.secondTicket = None

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
        else:
            self.header = self.CredentialHeader()

    def __getitem__(self, key):
        return self.header[key] 

    def __setitem__(self, item, value):
        self.header[item] = value

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
 
    def dump(self):
        self.header.dump()

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
        
class CCache:
    class MiniHeader(Structure):
        structure = (
            ('file_format_version','!H=0x0504'),
            ('headerlen','!H=12'),
        )

    def __init__(self, data = None):
        self.headers = None
        self.principal = None
        self.credentials = []
        self.miniHeader = None
        if data is not None:
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
                data = data[len(cred.getData()):]

    def getData(self):
        data = self.MiniHeader().getData()
        for header in self.headers:
            data += header.getData()
        data += self.principal.getData()
        for credential in self.credentials:
            data += credential.getData()
        return data

    def getCredential(self, server):
        for c in self.credentials:
            if c['server'].prettyPrint().upper() == server.upper():
                return c
        return None

    def toTimeStamp(self, dt, epoch=datetime(1970,1,1)):
        td = dt - epoch
        # return td.total_seconds()
        return (td.microseconds + (td.seconds + td.days * 24 * 3600) * 10**6) / 1e6

    def reverseFlags(self, flags):
        result = 0
        if isinstance(flags, str):
            flags = flags[1:-2]
        for i,j in enumerate(reversed(flags)):
            if j != 0:
                result += j << i
        return result

    def fromTGT(self, tgt, oldSessionKey, sessionKey):
        self.headers = []
        header = Header()
        header['tag'] = 1
        header['taglen'] = 8
        header['tagdata'] = '\xff\xff\xff\xff\x00\x00\x00\x00'
        self.headers.append(header)

        decodedTGT = decoder.decode(tgt, asn1Spec = AS_REP())[0]

        tmpPrincipal = types.Principal()
        tmpPrincipal.from_asn1(decodedTGT, 'crealm', 'cname')
        self.principal = Principal()
        self.principal.fromPrincipal(tmpPrincipal)

        # Now let's add the credential
        cipherText = decodedTGT['enc-part']['cipher']

        cipher = crypto._enctype_table[decodedTGT['enc-part']['etype']]

        # Key Usage 3
        # AS-REP encrypted part (includes TGS session key or
        # application session key), encrypted with the client key
        # (Section 5.4.2)
        plainText = cipher.decrypt(oldSessionKey, 3, str(cipherText))

        encASRepPart = decoder.decode(plainText, asn1Spec = EncASRepPart())[0]

        credential = Credential()
        server = types.Principal()
        server.from_asn1(encASRepPart, 'srealm', 'sname')
        tmpServer = Principal()
        tmpServer.fromPrincipal(server)
        
        credential['client'] = self.principal
        credential['server'] = tmpServer
        credential['is_skey'] = 0

        credential['key'] = KeyBlock()
        credential['key']['keytype'] = int(encASRepPart['key']['keytype'])
        credential['key']['keyvalue'] = str(encASRepPart['key']['keyvalue'])
        credential['key']['keylen'] = len(credential['key']['keyvalue'])

        credential['time'] = Times()
        credential['time']['authtime'] = self.toTimeStamp(types.KerberosTime.from_asn1(encASRepPart['authtime']))
        credential['time']['starttime'] = self.toTimeStamp(types.KerberosTime.from_asn1(encASRepPart['starttime'])) 
        credential['time']['endtime'] = self.toTimeStamp(types.KerberosTime.from_asn1(encASRepPart['endtime']))
        credential['time']['renew_till'] = self.toTimeStamp(types.KerberosTime.from_asn1(encASRepPart['renew-till'])) 

        flags = self.reverseFlags(encASRepPart['flags'])
        credential['tktflags'] = flags

        credential['num_address'] = 0
        credential.ticket = CountedOctetString()
        credential.ticket['data'] = encoder.encode(decodedTGT['ticket'].clone(tagSet=Ticket.tagSet, cloneValueFlag=True))
        credential.ticket['length'] = len(credential.ticket['data'])
        credential.secondTicket = CountedOctetString()
        credential.secondTicket['data'] = ''
        credential.secondTicket['length'] = 0
        self.credentials.append(credential)

    def fromTGS(self, tgs, oldSessionKey, sessionKey):
        self.headers = []
        header = Header()
        header['tag'] = 1
        header['taglen'] = 8
        header['tagdata'] = '\xff\xff\xff\xff\x00\x00\x00\x00'
        self.headers.append(header)

        decodedTGS = decoder.decode(tgs, asn1Spec = TGS_REP())[0]

        tmpPrincipal = types.Principal()
        tmpPrincipal.from_asn1(decodedTGS, 'crealm', 'cname')
        self.principal = Principal()
        self.principal.fromPrincipal(tmpPrincipal)

        # Now let's add the credential
        cipherText = decodedTGS['enc-part']['cipher']

        cipher = crypto._enctype_table[decodedTGS['enc-part']['etype']]

        # Key Usage 8
        # TGS-REP encrypted part (includes application session
        # key), encrypted with the TGS session key (Section 5.4.2)
        plainText = cipher.decrypt(oldSessionKey, 8, str(cipherText))

        encTGSRepPart = decoder.decode(plainText, asn1Spec = EncTGSRepPart())[0]

        credential = Credential()
        server = types.Principal()
        server.from_asn1(encTGSRepPart, 'srealm', 'sname')
        tmpServer = Principal()
        tmpServer.fromPrincipal(server)
        
        credential['client'] = self.principal
        credential['server'] = tmpServer
        credential['is_skey'] = 0 

        credential['key'] = KeyBlock()
        credential['key']['keytype'] = int(encTGSRepPart['key']['keytype'])
        credential['key']['keyvalue'] = str(encTGSRepPart['key']['keyvalue'])
        credential['key']['keylen'] = len(credential['key']['keyvalue'])

        credential['time'] = Times()
        credential['time']['authtime'] = self.toTimeStamp(types.KerberosTime.from_asn1(encTGSRepPart['authtime']))
        credential['time']['starttime'] = self.toTimeStamp(types.KerberosTime.from_asn1(encTGSRepPart['starttime'])) 
        credential['time']['endtime'] = self.toTimeStamp(types.KerberosTime.from_asn1(encTGSRepPart['endtime']))
        credential['time']['renew_till'] = self.toTimeStamp(types.KerberosTime.from_asn1(encTGSRepPart['renew-till'])) 

        flags = self.reverseFlags(encTGSRepPart['flags'])
        credential['tktflags'] = flags

        credential['num_address'] = 0

        credential.ticket = CountedOctetString()
        credential.ticket['data'] = encoder.encode(decodedTGS['ticket'].clone(tagSet=Ticket.tagSet, cloneValueFlag=True))
        credential.ticket['length'] = len(credential.ticket['data'])
        credential.secondTicket = CountedOctetString()
        credential.secondTicket['data'] = ''
        credential.secondTicket['length'] = 0
        self.credentials.append(credential)

    @classmethod
    def loadFile(cls, fileName):
        f = open(fileName,'rb')
        data = f.read()
        f.close()
        return cls(data)

    def saveFile(self, fileName):
        f = open(fileName,'wb+')
        f.write(self.getData())
        f.close()

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
