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
#   WKSSVC interface implementation.
#

from impacket.structure import Structure
from impacket import dcerpc
from impacket.dcerpc import ndrutils
from impacket.uuid import uuidtup_to_bin

MSRPC_UUID_WKSSVC = uuidtup_to_bin(('6BFFD098-A112-3610-9833-46C3F87E345A','1.0'))

class WKSTA_TRANSPORT_INFO_0(Structure):
    structure = (
       ('UnUsed','<L'),
       ('NumberOfRemoteConnections','<L'),
       ('RefId1','<L'),
       ('RefId2','<L'),
       ('IsRoutableTransport','<L'),
#       ('TransportName',':',ndrutils.NDRStringW),
#       ('TransportAddress',':',ndrutils.NDRStringW),
    )

class WKSSVCNetrWkstaTransportEnum(Structure):
    opnum = 5
    alignment = 4
    structure = (
       ('ServerName',':',ndrutils.NDRUniqueStringW),
       ('TransportInfo','20s'),
       ('MaxBuffer','<L=0xffffffff'),
       ('refId','<L=1'),
       ('ResumeHandle','<L=0'),
    )

class WKSSVCNetrWkstaTransportEnumResponse(Structure):
    structure = (
       ('Level','<L'),
       ('Case','<L'),
       ('refId','<L'),
       ('Count','<L'),
       ('refId2','<L'),
       ('MaxCount','<L'),
       ('ArrayLen','_-Array','len(self.rawData)-40'),
       ('Array',':'),
       ('TotalEntries','<L'),
       ('refId3','<L'),
       ('ResumeHandle','<L'),
       ('ErrorCode','<L')
    )

class DCERPCWksSvc:
    def __init__(self, dcerpc):
        self._dcerpc = dcerpc

    def doRequest(self, request, noAnswer = 0, checkReturn = 1):
        self._dcerpc.call(request.opnum, request)
        if noAnswer:
            return
        else:
            answer = self._dcerpc.recv()
            if checkReturn and answer[-4:] != '\x00\x00\x00\x00':
                raise Exception, 'DCE-RPC call returned an error.'
            return answer

    def NetrWkstaTransportEnum( self, serverName ):
      transportEnum = WKSSVCNetrWkstaTransportEnum()
      transportEnum['ServerName'] = ndrutils.NDRUniqueStringW()
      transportEnum['ServerName']['Data'] = (serverName+'\x00').encode('utf-16le')
      transportEnum['TransportInfo'] = '\x00'*8 + '\x04\x00\x04\x00' + '\x00'*8
      data = self.doRequest(transportEnum, checkReturn = 1)
      ans = WKSSVCNetrWkstaTransportEnumResponse(data)
      data = ans['Array']
      transportList = []
      for i in range(ans['Count']):
         ll = WKSTA_TRANSPORT_INFO_0(data)
         transportList.append(ll)
         data = data[len(ll):]
      for i in range(ans['Count']):
         transName = ndrutils.NDRStringW(data)
         transportList[i]['TransportName'] = transName
         data = data[len(transName):]
         transAddress = ndrutils.NDRStringW(data)
         transportList[i]['TransportAddress'] = transAddress
         data = data[len(transAddress):]
      ans['Array'] = transportList
      return ans


