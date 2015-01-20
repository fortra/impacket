################################################################################
# DEPRECATION WARNING!                                                         #
# This library will be deprecated soon. You should use impacket.dcerpc.v5      #
# classes instead                                                              #
################################################################################
# Copyright (c) 2003-2012 CORE Security Technologies
#
# This software is provided under under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# $Id$
#
# Author: Alberto Solino
#
# Description:
#   A minimalist DCE RPC Server, just for the purpose (for now) 
#   of making smbserver to work better with Windows 7, when being asked
#   for shares
#


import array
import logging
from impacket.dcerpc import dcerpc
from impacket.dcerpc.dcerpc import SEC_TRAILER
from impacket import ntlm
from impacket import uuid
from impacket.uuid import uuidtup_to_bin, generate, stringver_to_bin, bin_to_uuidtup
from impacket import structure
from impacket.structure import Structure
import socket
import struct

class DCERPCServer():
    def __init__(self):
        self._listenPort    = 0
        self._listenAddress = '127.0.0.1'
        self._listenUUIDS   = []
        self._callbacks     = {}
        self._boundUUID     = ''
        self._sock          = None
        self._clientSock    = None
        self._callid        = 1
        self._max_frag       = None
        self._max_xmit_size = 4280
        self.__log = logging.getLogger()
        self._sock = socket.socket()
        self._sock.bind((self._listenAddress,self._listenPort))

    def log(self, msg, level=logging.INFO):
        self.__log.log(level,msg)

    def addCallbacks(self, UUID, callbacks):
        # Format is [opnum] =  callback
        self._callbacks[uuidtup_to_bin(UUID)] = callbacks
        self._listenUUIDS.append(uuidtup_to_bin(UUID))
        self.log("Callback added for UUID %s V:%s" % UUID)

    def setListenPort(self, portNum):
        self._listenPort = portNum
        self._sock = socket.socket()
        self._sock.bind((self._listenAddress,self._listenPort))

    def getListenPort(self):
        return self._sock.getsockname()[1]

    def recv(self):
        finished = False
        forceRecv = 0
        retAnswer = ''
        while not finished:
            # At least give me the MSRPCRespHeader, especially important for TCP/UDP Transports
            self.response_data = self._clientSock.recv(dcerpc.MSRPCRespHeader._SIZE)
            # No data?, connection might have closed
            if self.response_data == '':
                return None
            self.response_header = dcerpc.MSRPCRespHeader(self.response_data)
            # Ok, there might be situation, especially with large packets, that the transport layer didn't send us the full packet's contents
            # So we gotta check we received it all
            while ( len(self.response_data) < self.response_header['frag_len'] ):
               self.response_data += self._clientSock.recv(self.response_header['frag_len']-len(self.response_data))
            self.response_header = dcerpc.MSRPCRespHeader(self.response_data)
            if self.response_header['flags'] & dcerpc.MSRPC_LASTFRAG:
                # No need to reassembly DCERPC
                finished = True
            else:
                # Forcing Read Recv, we need more packets!
                forceRecv = 1
            answer = self.response_header['pduData']
            auth_len = self.response_header['auth_len']
            if auth_len:
                auth_len += 8
                auth_data = answer[-auth_len:]
                sec_trailer = SEC_TRAILER(data = auth_data)
                answer = answer[:-auth_len]
                if sec_trailer['auth_pad_len']:
                    answer = answer[:-sec_trailer['auth_pad_len']]
              
            retAnswer += answer
        return self.response_data
    
    def run(self):
        self._sock.listen(10)
        while True:
            self._clientSock, address = self._sock.accept()
            try:
                while True:
                    data = self.recv()
                    if data is None:
                        # No data.. connection closed
                        break
                    answer = self.processRequest(data)
                    if answer != None:
                        self.send(answer)
            except Exception, e:
                #print e 
                pass
            self._clientSock.close()

    def send(self, data):
        max_frag       = self._max_frag
        if len(data['pduData']) > self._max_xmit_size - 32:
            max_frag   = self._max_xmit_size - 32    # XXX: 32 is a safe margin for auth data

        if self._max_frag:
            max_frag   = min(max_frag, self._max_frag)
        if max_frag and len(data['pduData']) > 0:
            packet     = data['pduData']
            offset     = 0
            while 1:
                toSend = packet[offset:offset+max_frag]
                if not toSend:
                    break
                flags  = 0
                if offset == 0:
                    flags |= dcerpc.MSRPC_FIRSTFRAG
                offset += len(toSend)
                if offset == len(packet):
                    flags |= dcerpc.MSRPC_LASTFRAG
                data['flags']   = flags
                data['pduData'] = toSend
                self._clientSock.send(data.get_packet())
        else:
            self._clientSock.send(data.get_packet())
        self._callid += 1

    def bind(self,packet, bind):
        # Standard NDR Representation
        NDRSyntax   = ('8a885d04-1ceb-11c9-9fe8-08002b104860', '2.0')
        resp = dcerpc.MSRPCBindAck()

        resp['type']             = dcerpc.MSRPC_BINDACK
        resp['flags']            = packet['flags']
        resp['frag_len']         = 0
        resp['auth_len']         = 0
        resp['auth_data']        = ''
        resp['call_id']          = packet['call_id'] 
        resp['max_tfrag']        = bind['max_tfrag']
        resp['max_rfrag']        = bind['max_rfrag']
        resp['assoc_group']      = 0x1234
        resp['SecondaryAddrLen'] = 13
        resp['SecondaryAddr']    = '\\PIPE\\srvsvc'
        resp['Pad']              ='A'*((4-((resp["SecondaryAddrLen"]+dcerpc.MSRPCBindAck._SIZE) % 4))%4)
        resp['ctx_num']          = 0

        data      = bind['ctx_items']
        ctx_items = ''
        for i in range(bind['ctx_num']):
            result = dcerpc.MSRPC_CONT_RESULT_USER_REJECT
            item   = dcerpc.CtxItem(data)
            data   = data[len(item):]

            # First we check the Transfer Syntax is NDR32, what we support
            #print "Trying to bind to: %s %s / %s %s" % (bin_to_uuidtup(item['AbstractSyntax']) + bin_to_uuidtup(item['TransferSyntax'])),

            if item['TransferSyntax'] == uuidtup_to_bin(NDRSyntax):
                # Now Check if the interface is what we listen
                reason = 1 # Default, Abstract Syntax not supported
                for i in self._listenUUIDS:
                    if item['AbstractSyntax'] == i:
                        # Match, we accept the bind request
                        reason           = 0
                        self._boundUUID = i
            else:
                # Fail the bind request for this context
                reason = 2 # Transfer Syntax not supported
            if reason == 0:
               result = dcerpc.MSRPC_CONT_RESULT_ACCEPT
               #print "... OK!"
            #else:
            #   print "... ERROR!"

            resp['ctx_num']             += 1
            itemResult                   = dcerpc.CtxItemResult()
            itemResult['Result']         = result
            itemResult['Reason']         = reason
            itemResult['TransferSyntax'] = uuidtup_to_bin(NDRSyntax)
            ctx_items                   += str(itemResult)

        resp['ctx_items'] = ctx_items
        resp['frag_len']  = len(str(resp))

        self._clientSock.send(str(resp)) 
        return None

    def processRequest(self,data):
        packet = dcerpc.MSRPCHeader(data)
        if packet['type'] == dcerpc.MSRPC_BIND:
            bind   = dcerpc.MSRPCBind(packet['pduData'])
            packet = self.bind(packet, bind)
        elif packet['type'] == dcerpc.MSRPC_REQUEST:
            request          = dcerpc.MSRPCRequestHeader(data)
            response         = dcerpc.MSRPCRespHeader(data)
            response['type'] = dcerpc.MSRPC_RESPONSE
            # Serve the opnum requested, if not, fails
            if self._callbacks[self._boundUUID].has_key(request['op_num']):
                # Call the function 
                returnData          = self._callbacks[self._boundUUID][request['op_num']](request['pduData'])
                response['pduData'] = returnData
            else:
                response['type']    = dcerpc.MSRPC_FAULT
                response['pduData'] = struct.pack('<L',0x000006E4L)
            response['frag_len'] = len(response)
            return response
        else:
            # Defaults to a fault
            packet         = dcerpc.MSRPCRespHeader(data)
            packet['type'] = dcerpc.MSRPC_FAULT

        return packet

from impacket.dcerpc import srvsvc
import ConfigParser
import struct

class SRVSVCShareInfo1(Structure):
    alignment = 4
    structure = (
        ('pNetName','<L'),
        ('Type','<L'),
        ('pRemark','<L'),
    )

class SRVSVCShareGetInfo(Structure):
    opnum = 16
    alignment = 4
    structure = (
       ('RefID','<L&ServerName'),
       ('ServerName','w'),
       ('NetName','w'),
       ('Level','<L=2'),
    )

class SRVSVCShareInfo2(Structure):
    alignment = 4
    structure = (
	('pNetName','<L&NetName'),
	('Type','<L'),
	('pRemark','<L&Remark'),
	('Permissions','<L'),
	('Max_Uses','<L'),
	('Current_Uses','<L'),
	('pPath','<L&Path'),
	('pPassword','<L&Password'),
	('NetName','w'),
	('Remark','w'),
	('Path','w'),
	('Password','w'),
)

class SRVSVCSwitchpShareInfo2(Structure):
    alignment = 4
    structure = (
	('Level','<L'),
	('pInfo','<L&InfoStruct'),
	('InfoStruct',':',SRVSVCShareInfo2),
    )

class SRVSVCServerGetInfo(Structure):
    opnum = 21
    alignment = 4
    structure = (
       ('RefID','<L&ServerName'),
       ('ServerName','w'),
       ('Level','<L=102'),
    )

class SRVSVCServerInfo101(Structure):
    alignment = 4
    structure = (
       ('PlatFormID','<L=500'),
       ('pName','<L&Name'),
       ('VersionMajor','<L=5'),
       ('VersionMinor','<L=0'),
       ('Type','<L=1'),
       ('pComment','<L&Comment'),
       ('Name','w'),
       ('Comment','w'),
    )

class SRVSVCServerpInfo101(Structure):
    alignment = 4
    structure = (
       ('Level','<L=101'),
       ('pInfo','<L&ServerInfo'),
       ('ServerInfo',':',SRVSVCServerInfo101),
    )

class SRVSVCNetrShareEnum(Structure):
    opnum = 15
    alignment = 4
    structure = (
       ('RefID','<L&ServerName'),
       ('ServerName','w'),
       ('Level','<L=0x1'),
       ('pShareEnum','<L=0x1'),
       ('p2','<L=0x5678'),
       ('count','<L=0'),
       ('NullP','<L=0'),
       ('PreferedMaximumLength','<L=0xffffffff'),
       ('pResumeHandler',':'),
    )

    def getData(self):
       self['pResumeHandler'] = '\xbc\x9a\x00\x00\x00\x00\x00\x00'
       return Structure.getData(self)

class SRVSVCShareEnumStruct(Structure):
    alignment = 4
    structure = (
        ('Level','<L'),
        ('pCount','<L=1'),
        ('Count','<L'),
        ('pMaxCount','<L&MaxCount'),
        ('MaxCount','<L'),
    )
class SRVSVCNetrShareEnum1_answer(Structure):
    alignment = 4
    structure = (
        ('pLevel','<L=1'),
        ('Info',':',SRVSVCShareEnumStruct),
# Not catched by the unpacker - just for doc purposed.
#       ('pTotalEntries','<L=&TotalEntries'),
#       ('TotalEntries','<L'),
#       ('pResumeHandler','<L=&ResumeHandler'),
#       ('ResumeHandler','<L'),
    )

class SRVSVCServer(DCERPCServer):
    def __init__(self):
        DCERPCServer.__init__(self)

        self._shares = {}

        self.srvsvcCallBacks = {
            15: self.NetShareEnumAll,
            16: self.NetrGetShareInfo,
            21: self.NetrServerGetInfo,
        }

        self.addCallbacks(('4B324FC8-1670-01D3-1278-5A47BF6EE188', '3.0'), self.srvsvcCallBacks)

    def setServerConfig(self, config):
        self.__serverConfig = config

    def processConfigFile(self, configFile=None):
       if configFile is not None:
           self.__serverConfig = ConfigParser.ConfigParser()
           self.__serverConfig.read(configFile)
       sections = self.__serverConfig.sections()
       # Let's check the log file
       self.__logFile      = self.__serverConfig.get('global','log_file')
       if self.__logFile != 'None':
            logging.basicConfig(filename = self.__logFile, 
                             level = logging.DEBUG, 
                             format="%(asctime)s: %(levelname)s: %(message)s", 
                             datefmt = '%m/%d/%Y %I:%M:%S %p')

       # Remove the global one
       del(sections[sections.index('global')])
       self._shares = {}
       for i in sections:
           self._shares[i] = dict(self.__serverConfig.items(i))

    def NetrGetShareInfo(self,data):
       request = SRVSVCShareGetInfo(data)
       self.log("NetrGetShareInfo Level: %d" % request['Level'])
       s = request['NetName'].decode('utf-16le')[:-1].upper().strip()
       share  = self._shares[s]
       answer = SRVSVCSwitchpShareInfo2()
       answer['Level']      = 1
       answer['InfoStruct'] = SRVSVCShareInfo1()
       answer['InfoStruct']['pNetName'] = id(share) & 0xffffffff
       answer['InfoStruct']['Type']     = int(share['share type'])
       answer['InfoStruct']['pRemark']  = (id(share) & 0xffffffff) + 1
       answer = str(answer)
       netName = srvsvc.NDRString()
       remark  = srvsvc.NDRString()
       netName['sName'] = request['NetName']
       remark['sName']  = (share['comment']+'\x00').encode('utf-16le')
       answer += str(netName) + str(remark)
       answer += struct.pack('<L',0)
       return answer

    def NetrServerGetInfo(self,data):
       request = SRVSVCServerGetInfo(data)
       self.log("NetrServerGetInfo Level: %d" % request['Level'])
       answer = SRVSVCServerpInfo101()
       answer['ServerInfo'] = SRVSVCServerInfo101()
       answer['ServerInfo']['Name']    = request['ServerName']
       answer['ServerInfo']['Comment'] = '\x00\x00'
       answer = str(answer) + '\x00'*4
       return answer

    def NetShareEnumAll(self, data):
       request = SRVSVCNetrShareEnum(data)
       self.log("NetrShareEnumAll Level: %d" % request['Level'])
       shareEnum = SRVSVCNetrShareEnum1_answer()
       shareEnum['Info'] = SRVSVCShareEnumStruct()
       shareEnum['Info']['Level']    = 1
       shareEnum['Info']['Count']    = len(self._shares)
       shareEnum['Info']['MaxCount'] = len(self._shares)
       answer = str(shareEnum) 
       for i in self._shares:
          shareInfo = SRVSVCShareInfo1()
          shareInfo['pNetName'] = id(i) & 0xffffffff
          shareInfo['Type']     = int(self._shares[i]['share type'])
          shareInfo['pRemark']  = (id(i) & 0xffffffff)+1
          answer += str(shareInfo)

       for i in self._shares:
          netName = srvsvc.NDRString()
          remark = srvsvc.NDRString()
          netName['sName'] = (i+'\x00').encode('utf-16le')
          remark['sName']  = (self._shares[i]['comment']+'\x00').encode('utf-16le')
          answer += str(netName) + str(remark)

       # and the answer
       answer += struct.pack('<LLL',len(self._shares),0,0)
       return answer
