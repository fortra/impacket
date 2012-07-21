#!/usr/bin/python
# Copyright (c) 2003-2012 CORE Security Technologies
#
# This software is provided under under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# $Id$
#
# Description: [MS-TDS] & [MC-SQLR] implementation. 
#
# ToDo:
# [ ] Add all the tokens left 
# [ ] parseRow should be rewritten and add support for all the SQL types in a 
#     good way. Right now it just supports a few types.
# [ ] printRows is crappy, just an easy way to print the rows. It should be 
#     rewritten to output like a normal SQL client
#
# Author:
#  Alberto Solino (beto@coresecurity.com)
#


from impacket import ntlm, uuid
from impacket.structure import Structure
import random
import string
import struct
import socket, select
import random
import binascii 


# MC-SQLR Constants and Structures
SQLR_PORT           = 1434
SQLR_CLNT_BCAST_EX  = 0x02
SQLR_CLNT_UCAST_EX  = 0x03
SQLR_CLNT_UCAST_INST= 0x04
SQLR_CLNT_UCAST_DAC = 0x0f


class SQLR(Structure):
    commonHdr = (
        ('OpCode','B'),
    )

class SQLR_UCAST_INST(SQLR):
    structure = (
        ('Instance',':')
    )
    def __init__(self, data = None):
        SQLR.__init__(self,data)
        if data is not None:
            self['OpCode'] = SQLR_CLNT_UCAST_INST

class SQLR_UCAST_DAC(SQLR):
    structure = (
        ('Protocol', 'B=1'),
        ('Instance', ':'),
    )
    def __init__(self, data = None):
        SQLR.__init__(self,data)
        if data is not None:
            self['OpCode'] = SQLR_CLNT_UCAST_DAC

class SQLR_Response(SQLR):
    structure = (
        ('Size','<H'),
        ('_Data','_-Data','self["Size"]'),
        ('Data',':'),
    )

# TDS Constants and Structures

# TYPE constants
TDS_SQL_BATCH       = 1
TDS_PRE_TDS_LOGIN   = 2
TDS_RPC             = 3
TDS_TABULAR         = 4
TDS_ATTENTION       = 6
TDS_BULK_LOAD_DATA  = 7
TDS_TRANSACTION     = 14
TDS_LOGIN7          = 16
TDS_SSPI            = 17
TDS_PRE_LOGIN       = 18

# Status constants
TDS_STATUS_NORMAL            = 0
TDS_STATUS_EOM               = 1 
TDS_STATUS_RESET_CONNECTION  = 8
TDS_STATUS_RESET_SKIPTRANS   = 16

# Encryption
TDS_ENCRYPT_OFF              = 0
TDS_ENCRYPT_ON               = 1
TDS_ENCRYPT_NOT_SUP          = 2
TDS_ENCRYPT_REQ              = 3

# Option 2 Flags
TDS_INTEGRATED_SECURITY_ON   = 0x80
TDS_INIT_LANG_FATAL          = 0x01
TDS_ODBC_ON                  = 0x02

# Token Types
TDS_ALTMETADATA_TOKEN        = 0x88
TDS_ALTROW_TOKEN             = 0xD3
TDS_COLMETADATA_TOKEN        = 0x81
TDS_COLINFO_TOKEN            = 0xA5
TDS_DONE_TOKEN               = 0xFD
TDS_DONEPROC_TOKEN           = 0xFE
TDS_DONEINPROC_TOKEN         = 0xFF
TDS_ENVCHANGE_TOKEN          = 0xE3
TDS_ERROR_TOKEN              = 0xAA
TDS_INFO_TOKEN               = 0xAB
TDS_LOGINACK_TOKEN           = 0xAD
TDS_NBCROW_TOKEN             = 0xD2
TDS_OFFSET_TOKEN             = 0x78
TDS_ORDER_TOKEN              = 0xA9
TDS_RETURNSTATUS_TOKEN       = 0x79
TDS_RETURNVALUE_TOKEN        = 0xAC
TDS_ROW_TOKEN                = 0xD1
TDS_SSPI_TOKEN               = 0xED
TDS_TABNAME_TOKEN            = 0xA4

# ENVCHANGE Types
TDS_ENVCHANGE_DATABASE       = 1
TDS_ENVCHANGE_LANGUAGE       = 2
TDS_ENVCHANGE_CHARSET        = 3
TDS_ENVCHANGE_PACKETSIZE     = 4
TDS_ENVCHANGE_UNICODE        = 5
TDS_ENVCHANGE_UNICODE_DS     = 6
TDS_ENVCHANGE_COLLATION      = 7
TDS_ENVCHANGE_TRANS_START    = 8
TDS_ENVCHANGE_TRANS_COMMIT   = 9
TDS_ENVCHANGE_ROLLBACK       = 10
TDS_ENVCHANGE_DTC            = 11

# Column types
# FIXED-LEN Data Types
TDS_NULL_TYPE                = 0x1F
TDS_INT1TYPE                 = 0x30
TDS_BITTYPE                  = 0x32
TDS_INT2TYPE                 = 0x34
TDS_INT4TYPE                 = 0x38
TDS_DATETIM4TYPE             = 0x3A
TDS_FLT4TYPE                 = 0x3B
TDS_MONEYTYPE                = 0x3C
TDS_DATETIMETYPE             = 0x3D
TDS_FLT8TYPE                 = 0x3E
TDS_MONEY4TYPE               = 0x7A
TDS_INT8TYPE                 = 0x7F

# VARIABLE-Len Data Types
TDS_GUIDTYPE                 = 0x24
TDS_INTNTYPE                 = 0x26
TDS_DECIMALTYPE              = 0x37
TDS_NUMERICTYPE              = 0x3F
TDS_BITNTYPE                 = 0x68
TDS_DECIMALNTYPE             = 0x6A
TDS_NUMERICNTYPE             = 0x6C
TDS_FLTNTYPE                 = 0x6D
TDS_MONEYNTYPE               = 0x6E
TDS_DATETIMNTYPE             = 0x6F
TDS_DATENTYPE                = 0x28
TDS_TIMENTYPE                = 0x29
TDS_DATETIME2NTYPE           = 0x2A
TDS_DATETIMEOFFSETNTYPE      = 0x2B
TDS_CHARTYPE                 = 0x2F
TDS_VARCHARTYPE              = 0x27
TDS_BINARYTYPE               = 0x2D
TDS_VARBINARYTYPE            = 0x25
TDS_BIGVARBINTYPE            = 0xA5
TDS_BIGVARCHRTYPE            = 0xA7
TDS_BIGBINARYTYPE            = 0xAD
TDS_BIGCHARTYPE              = 0xAF
TDS_NVARCHARTYPE             = 0xE7
TDS_NCHARTYPE                = 0xEF
TDS_XMLTYPE                  = 0xF1
TDS_UDTTYPE                  = 0xF0
TDS_TEXTTYPE                 = 0x23
TDS_IMAGETYPE                = 0x22
TDS_NTEXTTYPE                = 0x63
TDS_SSVARIANTTYPE            = 0x62

class TDSPacket(Structure):
    structure = (
        ('Type','<B'),
        ('Status','<B=1'),
        ('Length','>H=8+len(Data)'),
        ('SPID','>H=0'),
        ('PacketID','<B=0'),
        ('Window','<B=0'),
        ('Data',':'),
    )

class TDS_PRELOGIN(Structure):
    structure = (
        ('VersionToken','>B=0'),
        ('VersionOffset','>H'),
        ('VersionLength','>H=len(self["Version"])'),
        ('EncryptionToken','>B=0x1'),
        ('EncryptionOffset','>H'),
        ('EncryptionLength','>H=1'),
        ('InstanceToken','>B=2'),
        ('InstanceOffset','>H'),
        ('InstanceLength','>H=len(self["Instance"])'),
        ('ThreadIDToken','>B=3'),
        ('ThreadIDOffset','>H'),
        ('ThreadIDLength','>H=4'),
        ('EndToken','>B=0xff'),
        ('_Version','_-Version','self["VersionLength"]'),
        ('Version',':'),
        ('Encryption','B'),
        ('_Instance','_-Instance','self["InstanceLength"]-1'),
        ('Instance',':'),
        ('ThreadID',':'),
    )

    def __str__(self):
        self['VersionOffset']=21
        self['EncryptionOffset']=self['VersionOffset'] + len(self['Version'])
        self['InstanceOffset']=self['EncryptionOffset'] + 1
        self['ThreadIDOffset']=self['InstanceOffset'] + len(self['Instance'])
        return Structure.__str__(self)

class TDS_LOGIN(Structure):
    structure = (
        ('Length','<L=0'),
        ('TDSVersion','>L=0x71'),
        ('PacketSize','>L=32766'),
        ('ClientProgVer','>L=7'),
        ('ClientPID','<L=0'),
        ('ConnectionID','<L=0'),
        ('OptionFlags1','<B=0xe0'),
        ('OptionFlags2','<B'),
        ('TypeFlags','<B=0'),
        ('OptionFlags3','<B=0'),
        ('ClientTimeZone','<L=0'),
        ('ClientLCID','<L=0'),
        ('HostNameOffset','<H'),
        ('HostNameLength','<H=len(self["HostName"])/2'),
        ('UserNameOffset','<H=0'),
        ('UserNameLength','<H=len(self["UserName"])/2'),
        ('PasswordOffset','<H=0'),
        ('PasswordLength','<H=len(self["Password"])/2'),
        ('AppNameOffset','<H'),
        ('AppNameLength','<H=len(self["AppName"])/2'),
        ('ServerNameOffset','<H'),
        ('ServerNameLength','<H=len(self["ServerName"])/2'),
        ('UnusedOffset','<H=0'),
        ('UnusedLength','<H=0'),
        ('CltIntNameOffset','<H'),
        ('CltIntNameLength','<H=len(self["CltIntName"])/2'),
        ('LanguageOffset','<H=0'),
        ('LanguageLength','<H=0'),
        ('DatabaseOffset','<H=0'),
        ('DatabaseLength','<H=len(self["Database"])/2'),
        ('ClientID','6s="\x01\x02\x03\x04\x05\x06"'),
        ('SSPIOffset','<H'),
        ('SSPILength','<H=len(self["SSPI"])'),
        ('AtchDBFileOffset','<H'),
        ('AtchDBFileLength','<H=len(self["AtchDBFile"])/2'),
        ('HostName',':'),
        ('UserName',':'),
        ('Password',':'),
        ('AppName',':'),
        ('ServerName',':'),
        ('CltIntName',':'),
        ('Database',':'),
        ('SSPI',':'),
        ('AtchDBFile',':'),
    )
    def __init__(self,data=None):
        Structure.__init__(self,data)
        if data is None:
            self['UserName'] = ''
            self['Password'] = ''
            self['Database'] = ''
            self['AtchDBFile'] = ''

    def __str__(self):
        index = 36+50
        self['HostNameOffset']= index

        index += len(self['HostName'])

        if self['UserName'] != '':
            self['UserNameOffset'] = index
        else:
            self['UserNameOffset'] = 0

        index += len(self['UserName'])

        if self['Password'] != '':
            self['PasswordOffset'] = index
        else:
            self['PasswordOffset'] = 0

        index += len(self['Password'])

        self['AppNameOffset']= index
        self['ServerNameOffset']=self['AppNameOffset'] + len(self['AppName'])
        self['CltIntNameOffset']=self['ServerNameOffset'] + len(self['ServerName'])
        self['LanguageOffset']=self['CltIntNameOffset'] + len(self['CltIntName'])
        self['DatabaseOffset']=self['LanguageOffset'] 
        self['SSPIOffset']=self['DatabaseOffset'] + len(self['Database'])
        self['AtchDBFileOffset']=self['SSPIOffset'] + len(self['SSPI'])
        return Structure.__str__(self)

class TDS_LOGIN_ACK(Structure):
    structure = (
        ('TokenType','<B'),
        ('Length','<H'),
        ('Interface','<B'),
        ('TDSVersion','<L'),
        ('ProgNameLen','<B'),
        ('_ProgNameLen','_-ProgName','self["ProgNameLen"]*2'),
        ('ProgName',':'),
        ('MajorVer','<B'),
        ('MinorVer','<B'),
        ('BuildNumHi','<B'),
        ('BuildNumLow','<B'),
    )

class TDS_RETURNSTATUS(Structure):
    structure = (
        ('TokenType','<B'),
        ('Value','<L'),
    )

class TDS_INFO_ERROR(Structure):
    structure = (
        ('TokenType','<B'),
        ('Length','<H'),
        ('Number','<L'),
        ('State','<B'),
        ('Class','<B'),
        ('MsgTextLen','<H'),
        ('_MsgTextLen','_-MsgText','self["MsgTextLen"]*2'),
        ('MsgText',':'),
        ('ServerNameLen','<B'),
        ('_ServerNameLen','_-ServerName','self["ServerNameLen"]*2'),
        ('ServerName',':'),
        ('ProcNameLen','<B'),
        ('_ProcNameLen','_-ProcName','self["ProcNameLen"]*2'),
        ('ProcName',':'),
        ('LineNumber','<H'),
    )

class TDS_ENVCHANGE(Structure):
    structure = (
        ('TokenType','<B'),
        ('Length','<H=4+len(Data)'),
        ('Type','<B'),
        ('_Data','_-Data','self["Length"]-1'),
        ('Data',':'),
    )

class TDS_DONEINPROC(Structure):
    structure = (
        ('TokenType','<B'),
        ('Status','<H'),
        ('CurCmd','<H'),
        ('DoneRowCount','<L'),
    )

class TDS_ORDER(Structure):
    structure = (
        ('TokenType','<B'),
        ('Length','<H'),
        ('_Data','_-Data','self["Length"]'),
        ('Data',':'),
    )


class TDS_ENVCHANGE_VARCHAR(Structure):
    structure = (
        ('NewValueLen','<B=len(NewValue)'),
        ('_NewValue','_-NewValue','self["NewValueLen"]*2'),
        ('NewValue',':'),
        ('OldValueLen','<B=len(OldValue)'),
        ('_OldValue','_-OldValue','self["OldValueLen"]*2'),
        ('OldValue',':'),
    )
    
class TDS_ROW(Structure):
    structure = (
        ('TokenType','<B'),
        ('Data',':'),
    )

class TDS_DONE(Structure):
    structure = (
        ('TokenType','<B'),
        ('Status','<H'),
        ('CurCmd','<H'),
        ('DoneRowCount','<L'),
    )

class TDS_COLMETADATA(Structure):
    structure = (
        ('TokenType','<B'),
        ('Count','<H'),
        ('Data',':'),
    )

class MSSQL():
    def __init__(self, address, port=1433):
        self.packetSize = 32766
        self.server = address
        self.port = port
        self.socket = 0
        self.replies = {}
        self.colMeta = []
        self.rows = []
        self.currentDB = ''

    def getInstances(self, timeout = 5):
        packet = SQLR()
        packet['OpCode'] = SQLR_CLNT_UCAST_EX

        # Open the connection
        af, socktype, proto, canonname, sa = socket.getaddrinfo(self.server, SQLR_PORT, 0, socket.SOCK_DGRAM)[0]
        s = socket.socket(af, socktype, proto)

        s.sendto(str(packet), 0, ( self.server, SQLR_PORT ))
        ready, _, _ = select.select([ s.fileno() ], [ ] , [ ], timeout)
        if not ready:
            return []
        else:
            data, _ = s.recvfrom(65536, 0)
   
        s.close()
        resp = SQLR_Response(data)

        # Now parse the results
        entries = resp['Data'].split(';;')

        # We don't want the last one, it's empty
        entries.pop()
 
        # the answer to send back
        resp = []

        for i, entry in enumerate(entries):
            fields = entry.split(';')
            ret = {}
            for i, field in enumerate(fields):
                if (i & 0x1) == 0:
                    ret[field] = fields[i+1]
            resp.append(ret)

        return resp
        

    def preLogin(self):
        prelogin = TDS_PRELOGIN()
        prelogin['Version'] = "\x08\x00\x01\x55\x00\x00"
        prelogin['Encryption'] = TDS_ENCRYPT_NOT_SUP
        prelogin['ThreadID'] = struct.pack('<L',random.randint(0,65535))
        prelogin['Instance'] = 'MSSQLServer\x00'

        self.sendTDS(TDS_PRE_LOGIN, str(prelogin), 0)
        tds = self.recvTDS()

        return TDS_PRELOGIN(tds['Data'])
    
    def encryptPassword(self, password ):

        return ''.join(map(lambda x: chr(((ord(x) & 0x0f) << 4) + ((ord(x) & 0xf0) >> 4) ^ 0xa5) , password))

    def connect(self):
        af, socktype, proto, canonname, sa = socket.getaddrinfo(self.server, self.port, 0, socket.SOCK_STREAM)[0]
        sock = socket.socket(af, socktype, proto)
        sock.connect(sa)
        self.socket = sock
        return sock

    def disconnect(self):
        return self.socket.close()

    def setPacketSize(self, packetSize):
        self.packetSize = packetSize

    def getPacketSize(self):
        return self.packetSize
    
    def sendTDS(self, packetType, data, packetID = 1):
        if (len(data)-8) > self.packetSize:
            remaining = data[self.packetSize-8:]
            tds = TDSPacket()
            tds['Type'] = packetType
            tds['Status'] = TDS_STATUS_NORMAL
            tds['PacketID'] = packetID
            tds['Data'] = data[:self.packetSize-8]
            self.socket.sendall(str(tds))
            while len(remaining) > (self.packetSize-8):
                packetID += 1
                tds['PacketID'] = packetID
                tds['Data'] = remaining[:self.packetSize-8]
                self.socket.sendall(str(tds))
                remaining = remaining[self.packetSize-8:]
            data = remaining
            packetID+=1

        tds = TDSPacket()
        tds['Type'] = packetType
        tds['Status'] = TDS_STATUS_EOM
        tds['PacketID'] = packetID
        tds['Data'] = data
        self.socket.sendall(str(tds))

    def recvTDS(self, packetSize = None):
        # Do reassembly here
        if packetSize is None:
            packetSize = self.packetSize
        packet = TDSPacket(self.socket.recv(packetSize))
        status = packet['Status']
        packetLen = packet['Length']-8
        while packetLen > len(packet['Data']):
            data = self.socket.recv(packetSize)
            packet['Data'] += data
        
        remaining = None
        if packetLen <  len(packet['Data']):
            remaining = packet['Data'][packetLen:]
            packet['Data'] = packet['Data'][:packetLen]

        #print "REMAINING ", 
        #if remaining is None: 
        #   print None 
        #else: 
        #   print len(remaining)

        while status != TDS_STATUS_EOM:
            if remaining is not None:
                tmpPacket = TDSPacket(remaining)
                remaining = None
            else: 
                tmpPacket = TDSPacket(self.socket.recv(packetSize))

            packetLen = tmpPacket['Length'] - 8
            while packetLen > len(tmpPacket['Data']):
                data = self.socket.recv(packetSize)
                tmpPacket['Data'] += data

            remaining = None
            if packetLen <  len(tmpPacket['Data']):
                remaining = tmpPacket['Data'][packetLen:]
                tmpPacket['Data'] = tmpPacket['Data'][:packetLen]

            status = tmpPacket['Status']
            packet['Data'] += tmpPacket['Data']
            packet['Length'] += tmpPacket['Length'] - 8
            
        #print packet['Length']
        return packet

    def login(self, database, username, password='', domain='', hashes = None, useWindowsAuth = False):

        if hashes is not None:
            lmhash, nthash = hashes.split(':')
        else:
            lmhash = ''
            nthash = ''

        resp = self.preLogin()

        # Test this!
        if resp['Encryption'] != TDS_ENCRYPT_NOT_SUP:
            print "Encryption not supported"

        login = TDS_LOGIN()

        login['HostName'] = (''.join([random.choice(string.letters) for i in range(8)])).encode('utf-16le')
        login['AppName']  = (''.join([random.choice(string.letters) for i in range(8)])).encode('utf-16le')
        login['ServerName'] = self.server.encode('utf-16le')
        login['CltIntName']  = login['AppName']
        login['ClientPID'] = random.randint(0,1024)
        if database is not None:
            login['Database'] = database.encode('utf-16le')
        login['OptionFlags2'] = TDS_INIT_LANG_FATAL | TDS_ODBC_ON

        if useWindowsAuth is True:
            login['OptionFlags2'] |= TDS_INTEGRATED_SECURITY_ON
            # NTLMSSP Negotiate
            auth = ntlm.getNTLMSSPType1('WORKSTATION','DEVEL')
            login['SSPI'] = str(auth)
        else:
            login['UserName'] = username.encode('utf-16le')
            login['Password'] = self.encryptPassword(password.encode('utf-16le'))
            login['SSPI'] = ''

        login['Length'] = len(str(login))

        self.sendTDS(TDS_LOGIN7, str(login))
        # Send the NTLMSSP Negotiate or SQL Auth Packet
        tds = self.recvTDS()

        if useWindowsAuth is True:
            serverChallenge = tds['Data'][3:]

            #User: devel\pruebasql        Pwd:Unpassword1
            #User: devel\Administrator    Pwd: Admin123
            #user = 'pruebasql'
            #user = 'Administrator'
            #password = 'Unpassword1'
            #password = 'Admin123'
            #domain = 'DEVEL'
            #domain = 'DEVEL'
            #lmhash = ''
            #nthash = ''

            # Generate the NTLM ChallengeResponse AUTH 
            type3, exportedSessionKey = ntlm.getNTLMSSPType3(auth, serverChallenge, username, password, domain, lmhash, nthash)

            self.sendTDS(TDS_SSPI, str(type3))
            tds = self.recvTDS()

        self.replies = self.parseReply(tds['Data'])

        if self.replies.has_key(TDS_LOGINACK_TOKEN):
            return True
        else:
            return False

    def printRows(self):
        for i, row in enumerate(self.rows):
            print "ROW %d" % i
            for j in range(len(self.colMeta)):
               print self.colMeta[j]['Name']," : ", row[self.colMeta[j]['Name']]
            print "======================================================"


    def printReplies(self):
       for keys in self.replies.keys():
           for i, key in enumerate(self.replies[keys]):
               if key['TokenType'] == TDS_ERROR_TOKEN:
                   print "[!] ERROR(%s): Line %d: %s" % (key['ServerName'].decode('utf-16le'), key['LineNumber'], key['MsgText'].decode('utf-16le'))

               elif key['TokenType'] == TDS_INFO_TOKEN:
                   print "[*] INFO(%s): Line %d: %s" % (key['ServerName'].decode('utf-16le'), key['LineNumber'], key['MsgText'].decode('utf-16le'))

               elif key['TokenType'] == TDS_LOGINACK_TOKEN:
                   print "[*] ACK: Result: %s - %s (%d%d %d%d) " % (key['Interface'], key['ProgName'].decode('utf-16le'), key['MajorVer'], key['MinorVer'], key['BuildNumHi'], key['BuildNumLow'])

               elif key['TokenType'] == TDS_ENVCHANGE_TOKEN:
                   if key['Type'] in (TDS_ENVCHANGE_DATABASE, TDS_ENVCHANGE_LANGUAGE, TDS_ENVCHANGE_CHARSET, TDS_ENVCHANGE_PACKETSIZE):
                      record = TDS_ENVCHANGE_VARCHAR(key['Data'])
                      print "[*] ENVCHANGE(%d): Old Value: %s, New Value: %s" % (key['Type'],record['OldValue'].decode('utf-16le'), record['NewValue'].decode('utf-16le'))

       
    def parseRow(self,token):
        # TODO: This REALLY needs to be improved. Right now we don't support correctly all the data types
        # help would be appreciated ;) 
        if len(token) == 1:
           return 0
        row = {}
        origDataLen = len(token['Data'])
        data = token['Data']
        for i in range(len(self.colMeta)):
            type = self.colMeta[i]['Type']
            if (type == TDS_NVARCHARTYPE) |\
               (type == TDS_NCHARTYPE):
                #print "NVAR 0x%x" % type
                charLen = struct.unpack('<H',data[:struct.calcsize('<H')])[0]
                data = data[struct.calcsize('<H'):]
                if charLen != 0xFFFF:
                    value = data[:charLen].decode('utf-16le')
                    data = data[charLen:]
                else:
                    value = 'NULL'

            elif (type == TDS_BIGVARCHRTYPE): 
                charLen = struct.unpack('<H',data[:struct.calcsize('<H')])[0]
                data = data[struct.calcsize('<H'):]
                if charLen != 0xFFFF:
                    value = data[:charLen]
                    data = data[charLen:]
                else:
                    value = 'NULL'

            elif (type == TDS_GUIDTYPE):
                uuidLen = ord(data[0])
                data = data[1:]
                if uuidLen > 0:
                    uu = data[:uuidLen]
                    value = uuid.bin_to_string(uu)
                    data = data[uuidLen:]
                else:
                    value = 'NULL'
                
            elif (type == TDS_NTEXTTYPE) |\
                 (type == TDS_IMAGETYPE) :
                # Skip the pointer data
                charLen = ord(data[0])
                data = data[1+charLen+8:]
                charLen = struct.unpack('<L',data[:struct.calcsize('<L')])[0]
                data = data[struct.calcsize('<L'):]
                if charLen != 0xFFFF:
                    if type == TDS_NTEXTTYPE:
                        value = data[:charLen].decode('utf-16le')
                    else:
                        value = binascii.b2a_hex(data[:charLen])
                    data = data[charLen:]
                else:
                    value = 'NULL'
                
            elif (type == TDS_TEXTTYPE): 
                # Skip the pointer data
                charLen = ord(data[0])
                data = data[1+charLen+8:]
                charLen = struct.unpack('<L',data[:struct.calcsize('<L')])[0]
                data = data[struct.calcsize('<H'):]
                if charLen != 0xFFFF:
                    value = data[:charLen]
                    data = data[charLen:]
                else:
                    value = 'NULL'

            elif (type == TDS_BIGVARBINTYPE) |\
                 (type == TDS_BIGBINARYTYPE):
                charLen = struct.unpack('<H',data[:struct.calcsize('<H')])[0]
                data = data[struct.calcsize('<H'):]
                if charLen != 0xFFFF:
                    value = binascii.b2a_hex(data[:charLen])
                    data = data[charLen:]
                else:
                    value = 'NULL'

            elif (type == TDS_INT4TYPE) |\
                 (type == TDS_DATETIM4TYPE) |\
                 (type == TDS_MONEY4TYPE) |\
                 (type == TDS_FLT4TYPE):
                #print "INT4"
                value = struct.unpack('<L',data[:struct.calcsize('<L')])[0]
                data = data[struct.calcsize('<L'):]

            elif (type == TDS_FLTNTYPE):
                valueSize = ord(data[:1])
                if valueSize == 4:
                    fmt = '<f'
                elif valueSize == 8:
                    fmt = '<d'

                data = data[1:]

                if valueSize > 0:
                    value = struct.unpack(fmt,data[:valueSize])[0]
                    data = data[valueSize:]
                else:
                    value = 'NULL'


            elif type == TDS_MONEYNTYPE:
                valueSize = ord(data[:1])
                if valueSize == 4:
                    fmt = '<l'
                elif valueSize == 8:
                    fmt = '<q'

                data = data[1:]

                if valueSize > 0:
                    value = struct.unpack(fmt,data[:valueSize])[0]
                    data = data[valueSize:]
                else:
                    value = 'NULL'

                
            elif type == TDS_BIGCHARTYPE:
                #print "BIGC"
                charLen = struct.unpack('<H',data[:struct.calcsize('<H')])[0]
                data = data[struct.calcsize('<H'):]
                value = data[:charLen]
                data = data[charLen:]

            elif (type == TDS_DATETIMETYPE) |\
                 (type == TDS_INT8TYPE) |\
                 (type == TDS_FLT8TYPE) |\
                 (type == TDS_MONEYTYPE):
                #print "DATETIME"
                value = struct.unpack('<q',data[:struct.calcsize('<q')])[0]
                data = data[struct.calcsize('<q'):]

            elif (type == TDS_INT2TYPE):
                #print "INT2TYPE"
                value = struct.unpack('<H',(data[:2]))[0]
                data = data[2:]

            elif (type == TDS_DATENTYPE):
                valueSize = ord(data[:1])
                data = data[1:]
                if valueSize > 0:
                    value = binascii.b2a_hex(data[:valueSize])
                    data = data[valueSize:]
                else:
                    value = 'NULL'

            elif (type == TDS_BITTYPE) |\
                 (type == TDS_INT1TYPE):
                #print "BITTYPE"
                value = ord(data[:1])
                data = data[1:]

            elif (type == TDS_NUMERICNTYPE):
                valueLen = ord(data[:1])
                data = data[1:]
                value = data[:valueLen]
                value = "TODO: Interpret TDS_NUMERICNTYPE correctly"
                data = data[valueLen:]

            elif (type == TDS_BITNTYPE) |\
                 (type == TDS_DECIMALNTYPE):
                #print "BITNTYPE"
                valueSize = ord(data[:1])
                data = data[1:]
                if valueSize > 0:
                    if valueSize == 1:
                        value = ord(data[:valueSize])
                    else:
                        value = data[:valueSize]
                else:
                    value = 'NULL'
                data = data[valueSize:]

            elif (type == TDS_INTNTYPE)     |\
               (type == TDS_DATETIMNTYPE):
                valueSize = ord(data[:1])
                if valueSize == 1:
                    fmt = '<B'
                elif valueSize == 2:
                    fmt = '<h'
                elif valueSize == 4:
                    fmt = '<l'
                elif valueSize == 8:
                    fmt = '<q'
                else:
                    fmt = ''

                data = data[1:]

                if valueSize > 0:
                    value = struct.unpack(fmt,data[:valueSize])[0]
                    data = data[valueSize:]
                else:
                    value = 'NULL'
            else:
                print "ParseROW: Unsupported data type: 0%x" % type
                raise
            row[self.colMeta[i]['Name']] = value


        self.rows.append(row)

        return (origDataLen - len(data))

    def parseColMetaData(self, token):
        # TODO Add support for more data types!
        count = token['Count']
        if count == 0xFFFF:
            return 0

        self.colMeta = []
        origDataLen = len(token['Data'])
        data = token['Data']
        for i in range(count):
            column = {}
            userType = struct.unpack('<H',data[:struct.calcsize('<H')])[0]
            data = data[struct.calcsize('<H'):]
            flags = struct.unpack('<H',data[:struct.calcsize('<H')])[0]
            data = data[struct.calcsize('<H'):]
            colType = struct.unpack('<B',data[:struct.calcsize('<B')])[0]
            data = data[struct.calcsize('<B'):]
            if (colType == TDS_BITTYPE)    |\
                 (colType == TDS_INT1TYPE)   |\
                 (colType == TDS_INT2TYPE)   |\
                 (colType == TDS_INT8TYPE)   |\
                 (colType == TDS_DATETIMETYPE) |\
                 (colType == TDS_DATETIM4TYPE) |\
                 (colType == TDS_FLT4TYPE)   |\
                 (colType == TDS_FLT8TYPE)   |\
                 (colType == TDS_MONEYTYPE)  |\
                 (colType == TDS_MONEY4TYPE) |\
                 (colType == TDS_DATENTYPE)  |\
                 (colType == TDS_INT4TYPE):
                typeData = ''
            elif (colType == TDS_INTNTYPE) |\
                 (colType == TDS_TIMENTYPE) |\
                 (colType == TDS_DATETIME2NTYPE) |\
                 (colType == TDS_DATETIMNTYPE) |\
                 (colType == TDS_DATETIMEOFFSETNTYPE) |\
                 (colType == TDS_FLTNTYPE) |\
                 (colType == TDS_MONEYNTYPE) |\
                 (colType == TDS_GUIDTYPE) |\
                 (colType == TDS_BITNTYPE):
                typeData = data[0]
                data = data[1:]
            elif (colType == TDS_BIGVARBINTYPE) |\
                 (colType == TDS_BIGBINARYTYPE) |\
                 (colType == TDS_NCHARTYPE)     |\
                 (colType == TDS_NVARCHARTYPE)  |\
                 (colType == TDS_BIGVARCHRTYPE) |\
                 (colType == TDS_BIGCHARTYPE):
                typeData = data[:2]
                data = data[2:]
            elif (colType == TDS_DECIMALNTYPE) |\
                 (colType == TDS_NUMERICNTYPE) |\
                 (colType == TDS_DECIMALTYPE):
                typeData = data[:3]
                data = data[3:]
            elif (colType == TDS_IMAGETYPE) |\
                 (colType == TDS_TEXTTYPE) |\
                 (colType == TDS_XMLTYPE)  |\
                 (colType == TDS_SSVARIANTTYPE) |\
                 (colType == TDS_NTEXTTYPE):
                typeData = data[:4]
                data = data[4:]
            else:
                print "Unsupported data type: 0x%x" % colType
                raise

            # Collation exceptions:
            if (colType == TDS_NTEXTTYPE) |\
               (colType == TDS_BIGCHARTYPE)  |\
               (colType == TDS_BIGVARCHRTYPE)  |\
               (colType == TDS_NCHARTYPE)  |\
               (colType == TDS_NVARCHARTYPE)  |\
               (colType == TDS_TEXTTYPE):
                # Skip collation
                data = data[5:]

            # PartTableName exceptions:
            if (colType == TDS_IMAGETYPE) |\
                 (colType == TDS_TEXTTYPE) |\
                 (colType == TDS_NTEXTTYPE):
                # This types have Table Elements, we just discard them for now.
                # ToDo parse this correctly!
                # Get the Length
                dataLen = struct.unpack('<H',data[:2])[0]
                data = data[2:]
                # skip the text
                data = data[dataLen*2:]

            colNameLength = struct.unpack('<B',data[:struct.calcsize('<B')])[0]
            data = data[struct.calcsize('<B'):]
            colName = data[:colNameLength*2].decode('utf-16le')
            data = data[colNameLength*2:]
            column['Name'] = colName
            column['Type'] = colType
            column['TypeData'] = typeData
            column['Flags'] = flags
            self.colMeta.append(column)

        return (origDataLen - len(data))

    def parseReply(self, tokens):
        if len(tokens) == 0:
            return False

        replies = {} 
        while len(tokens) > 0:
            tokenID = struct.unpack('B',tokens[0])[0]
            if tokenID == TDS_ERROR_TOKEN:
                token = TDS_INFO_ERROR(tokens)
            elif tokenID == TDS_RETURNSTATUS_TOKEN:
                token = TDS_RETURNSTATUS(tokens)
            elif tokenID == TDS_INFO_TOKEN:
                token = TDS_INFO_ERROR(tokens)
            elif tokenID == TDS_LOGINACK_TOKEN:
                token = TDS_LOGIN_ACK(tokens)
            elif tokenID == TDS_ENVCHANGE_TOKEN:
                token = TDS_ENVCHANGE(tokens)
                if token['Type'] is TDS_ENVCHANGE_PACKETSIZE:
                      record = TDS_ENVCHANGE_VARCHAR(token['Data'])
                      self.packetSize = string.atoi( record['NewValue'].decode('utf-16le') )
                elif token['Type'] is TDS_ENVCHANGE_DATABASE:
                      record = TDS_ENVCHANGE_VARCHAR(token['Data'])
                      self.currentDB =  record['NewValue'].decode('utf-16le') 

            elif (tokenID == TDS_DONEINPROC_TOKEN) |\
                 (tokenID == TDS_DONEPROC_TOKEN): 
                token = TDS_DONEINPROC(tokens)
            elif tokenID == TDS_ORDER_TOKEN:
                token = TDS_ORDER(tokens)
            elif tokenID == TDS_ROW_TOKEN:
                #print "ROW"
                token = TDS_ROW(tokens)
                tokenLen = self.parseRow(token)
                token['Data'] = token['Data'][:tokenLen]
            elif tokenID == TDS_COLMETADATA_TOKEN:
                #print "COLMETA"
                token = TDS_COLMETADATA(tokens)
                tokenLen = self.parseColMetaData(token)
                token['Data'] = token['Data'][:tokenLen]
            elif tokenID == TDS_DONE_TOKEN:
                token = TDS_DONE(tokens)
            else:
                print "Unknown Token %x" % tokenID
                return replies

            if replies.has_key(tokenID) is not True:
                replies[tokenID] = list()

            replies[tokenID].append(token)
            tokens = tokens[len(token):]
            #print "TYPE 0x%x, LEN: %d" %(tokenID, len(token))
            #print repr(tokens[:10])

        return replies

    def batch(self, cmd):
        # First of all we clear the rows, and colMeta
        self.rows = []
        self.colMeta = []
        self.sendTDS(TDS_SQL_BATCH, (cmd+'\r\n').encode('utf-16le'))
        tds = self.recvTDS()
        self.replies = self.parseReply(tds['Data'])
        return self.rows

    # Handy alias
    sql_query = batch

    def changeDB(self, db):
        if db != self.currentDB:
            self.batch('use %s' % db)
            self.printReplies()

    def RunSQL(self,db,sql_query, **kwArgs):
        self.changeDB(db)
        self.printReplies() 
        ret = self.batch(sql_query)
        self.printReplies()

        return ret
