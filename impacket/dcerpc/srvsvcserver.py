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
from impacket.dcerpc import dcerpc
from impacket import ntlm
from impacket import uuid
from impacket.uuid import uuidtup_to_bin, generate, stringver_to_bin, bin_to_uuidtup
import socket
import struct

class DCERPCServer():
    def __init__(self):
        self.__listenPort    = 4343
        self.__listenAddress = '0.0.0.0'
        self.__listenUUIDS   = []
        self.__callbacks     = {}
        self.__boundUUID     = ''
        self.__sock          = None
        self.__clientSock    = None
        self.__callid        = 1
        self._max_frag       = None
        self.__max_xmit_size = 4280
 

    def addCallbacks(self, UUID, callbacks):
        # Format is [opnum] =  callback
        self.__callbacks[uuidtup_to_bin(UUID)] = callbacks
        self.__listenUUIDS.append(uuidtup_to_bin(UUID))
        print "Callback added for UUID %s V:%s" % UUID

    def setListenPort(self, portNum):
        self.__listenPort = portNum

    def recv(self):
        finished = False
        forceRecv = 0
        retAnswer = ''
        while not finished:
            # At least give me the MSRPCRespHeader, especially important for TCP/UDP Transports
            self.response_data = self.__clientSock.recv(dcerpc.MSRPCRespHeader._SIZE)
            self.response_header = dcerpc.MSRPCRespHeader(self.response_data)
            # Ok, there might be situation, especially with large packets, that the transport layer didn't send us the full packet's contents
            # So we gotta check we received it all
            while ( len(self.response_data) < self.response_header['frag_len'] ):
               self.response_data += self.__clientSock.recv(self.response_header['frag_len']-len(self.response_data))
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
                ntlmssp   = ntlm.DCERPC_NTLMAuthHeader(data = auth_data)
                answer = answer[:-auth_len]
                if ntlmssp['auth_pad_len']:
                    answer = answer[:-ntlmssp['auth_pad_len']]
              
            retAnswer += answer
        return self.response_data
    
    def run(self):
        self.__sock = socket.socket()
        self.__sock.bind((self.__listenAddress,self.__listenPort))
        self.__sock.listen(10)
        while True:
            self.__clientSock, address = self.__sock.accept()
            print "Connected from ", address
            try:
                while True:
                    data = self.recv()
                    answer = self.processRequest(data)
                    if answer != None:
                        self.send(answer)
            except Exception, e:
                #print e 
                print "Connection Finished!"

    def send(self, data):
        max_frag       = self._max_frag
        if len(data['pduData']) > self.__max_xmit_size - 32:
            max_frag   = self.__max_xmit_size - 32    # XXX: 32 is a safe margin for auth data

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
                self.__clientSock.send(data.get_packet())
        else:
            self.__clientSock.send(data.get_packet())
        self.__callid += 1

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
        resp['SecondaryAddrLen'] = 4
        resp['SecondaryAddr']    = '135'
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
                for i in self.__listenUUIDS:
                    if item['AbstractSyntax'] == i:
                        # Match, we accept the bind request
                        reason           = 0
                        self.__boundUUID = i
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

        self.__clientSock.send(str(resp)) 
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
            if self.__callbacks[self.__boundUUID].has_key(request['op_num']):
                # Call the function 
                returnData          = self.__callbacks[self.__boundUUID][request['op_num']](request['pduData'])
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
from impacket import smbserver
import ConfigParser
import struct

class SRVSVCServer(DCERPCServer):
    def __init__(self):
        DCERPCServer.__init__(self)

        self.__shares = {}

        self.srvsvcCallBacks = {
            15: self.NetShareEnumAll,
            16: self.NetrGetShareInfo,
            21: self.NetrServerGetInfo,
        }

        self.addCallbacks(('4B324FC8-1670-01D3-1278-5A47BF6EE188', '3.0'), self.srvsvcCallBacks)

    def processConfigFile(self, configFile):
       serverConfig = ConfigParser.ConfigParser()
       serverConfig.read(configFile)
       sections = serverConfig.sections()
       # Remove the global one
       del(sections[sections.index('global')])
       for i in sections:
           self.__shares[i] = dict(serverConfig.items(i))

    def NetrGetShareInfo(self,data):
       request = srvsvc.SRVSVCNetrShareGetInfo(data)
       print "NetrGetShareInfo Level: %d" % request['Level']
       s = request['NetName'].decode('utf-16le')[:-1].upper().strip()
       share  = self.__shares[s]
       answer = srvsvc.SRVSVCSwitchpShareInfo2()
       answer['Level']      = 1
       answer['InfoStruct'] = srvsvc.SRVSVCShareInfo1()
       answer['InfoStruct']['pNetName'] = id(share)
       answer['InfoStruct']['Type']     = int(share['share type'])
       answer['InfoStruct']['pRemark']  = id(share)+1
       answer = str(answer)
       netName = srvsvc.NDRString()
       remark  = srvsvc.NDRString()
       netName['sName'] = request['NetName']
       remark['sName']  = (share['comment']+'\x00').encode('utf-16le')
       answer += str(netName) + str(remark)
       answer += struct.pack('<L',0)
       return answer

    def NetrServerGetInfo(self,data):
       request = srvsvc.SRVSVCNetrServerGetInfo(data)
       print "NetrServerGetInfo Level: %d" % request['Level']
       answer = srvsvc.SRVSVCServerpInfo101()
       answer['ServerInfo'] = srvsvc.SRVSVCServerInfo101()
       answer['ServerInfo']['Name']    = request['ServerName']
       answer['ServerInfo']['Comment'] = '\x00\x00'
       answer = str(answer) + '\x00'*4
       return answer

    def NetShareEnumAll(self, data):
       request = srvsvc.SRVSVCNetrShareEnum(data)
       print "NetrShareEnumAll Level: %d" % request['Level']
       shareEnum = srvsvc.SRVSVCNetrShareEnum1_answer()
       shareEnum['Info'] = srvsvc.SRVSVCShareEnumStruct()
       shareEnum['Info']['Level']    = 1
       shareEnum['Info']['Count']    = len(self.__shares)
       shareEnum['Info']['MaxCount'] = len(self.__shares)
       answer = str(shareEnum) 
       for i in self.__shares:
          shareInfo = srvsvc.SRVSVCShareInfo1()
          shareInfo['pNetName'] = id(i)
          shareInfo['Type']     = int(self.__shares[i]['share type'])
          shareInfo['pRemark']  = id(i)+1
          answer += str(shareInfo)

       for i in self.__shares:
          netName = srvsvc.NDRString()
          remark = srvsvc.NDRString()
          netName['sName'] = (i+'\x00').encode('utf-16le')
          remark['sName']  = (self.__shares[i]['comment']+'\x00').encode('utf-16le')
          answer += str(netName) + str(remark)

       # and the answer
       answer += struct.pack('<LLL',len(self.__shares),0,0)
       return answer
