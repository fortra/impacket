#!/usr/bin/python
# Copyright (c) 2003-2016 CORE Security Technologies
#
# This software is provided under under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Parses a pcap file or sniffes traffic from the net and checks the SMB structs for errors. 
# Log the error packets in outFile
#
# Author: 
#   Alberto Solino <bethus@gmail.com>
#
# ToDo:
# [ ] Add more SMB Commands
# [ ] Do the same for DCERPC

import struct
from select import select
import socket
import argparse
from impacket import pcapfile, smb, nmb, ntlm, version
from impacket import ImpactPacket, ImpactDecoder, structure

# Command handler

def smbTransaction2( packet, packetNum, SMBCommand, questions, replies):
    # Test return code is always 0, otherwise leave before doing anything
    if packet['ErrorCode'] != 0:
        return False

    print "SMB_COM_TRANSACTION2 ",
    try:
      if (packet['Flags1'] & smb.SMB.FLAGS1_REPLY) == 0:
        # Query

        trans2Parameters= smb.SMBTransaction2_Parameters(SMBCommand['Parameters'])

        # Do the stuff
        if trans2Parameters['ParameterCount'] != trans2Parameters['TotalParameterCount']:
            # TODO: Handle partial parameters 
            #print "Unsupported partial parameters in TRANSACT2!"
            raise Exception("Unsupported partial parameters in TRANSACT2!")
        else:
            trans2Data = smb.SMBTransaction2_Data()
            # Standard says servers shouldn't trust Parameters and Data comes 
            # in order, so we have to parse the offsets, ugly   

            paramCount = trans2Parameters['ParameterCount']
            trans2Data['Trans_ParametersLength'] = paramCount
            dataCount = trans2Parameters['DataCount']
            trans2Data['Trans_DataLength'] = dataCount

            if trans2Parameters['ParameterOffset'] > 0:
                paramOffset = trans2Parameters['ParameterOffset'] - 63 - trans2Parameters['SetupLength']
                trans2Data['Trans_Parameters'] = SMBCommand['Data'][paramOffset:paramOffset+paramCount]
            else:
                trans2Data['Trans_Parameters'] = ''

            if trans2Parameters['DataOffset'] > 0:
                dataOffset = trans2Parameters['DataOffset'] - 63 - trans2Parameters['SetupLength']
                trans2Data['Trans_Data'] = SMBCommand['Data'][dataOffset:dataOffset + dataCount]
      else:
        # Response
        # ToDo not implemented yet
        a = 1

    except Exception, e:
        print "ERROR: %s" % e
        print "Command: 0x%x" % packet['Command']
        print "Packet: %d %r" % (packetNum, packet.getData())
        return True
    else:
        print 'OK!' 

    return False

def smbComOpenAndX( packet, packetNum, SMBCommand, questions, replies):

    # Test return code is always 0, otherwise leave before doing anything
    if packet['ErrorCode'] != 0:
        return True

    print "SMB_COM_OPEN_ANDX ",
    try:
      if (packet['Flags1'] & smb.SMB.FLAGS1_REPLY) == 0:
        # Query

        openAndXParameters = smb.SMBOpenAndX_Parameters(SMBCommand['Parameters'])
        openAndXData       = smb.SMBOpenAndX_Data(SMBCommand['Data'])

      else:
        # Response
        openFileResponse   = SMBCommand
        openFileParameters = smb.SMBOpenAndXResponse_Parameters(openFileResponse['Parameters'])


    except Exception, e:
        print "ERROR: %s" % e
        print "Command: 0x%x" % packet['Command']
        print "Packet: %d %r" % (packetNum, packet.getData())
        return True
    else:
        print 'OK!' 

    return False

def smbComWriteAndX( packet, packetNum, SMBCommand, questions, replies):

    # Test return code is always 0, otherwise leave before doing anything
    if packet['ErrorCode'] != 0:
        return False

    print "SMB_COM_WRITE_ANDX ",
    try:
      if (packet['Flags1'] & smb.SMB.FLAGS1_REPLY) == 0:
        # Query

        if SMBCommand['WordCount'] == 0x0C:
            writeAndX =  smb.SMBWriteAndX_Parameters2(SMBCommand['Parameters'])
        else:
            writeAndX =  smb.SMBWriteAndX_Parameters(SMBCommand['Parameters'])
        writeAndXData = smb.SMBWriteAndX_Data()
        writeAndXData['DataLength'] = writeAndX['DataLength']
        if  writeAndX['DataLength'] > 0:
            writeAndXData.fromString(SMBCommand['Data'])
      else:
        # Response
        writeResponse   = SMBCommand
        writeResponseParameters = smb.SMBWriteAndXResponse_Parameters(writeResponse['Parameters'])

    except Exception, e:
        print "ERROR: %s" % e
        print "Command: 0x%x" % packet['Command']
        print "Packet: %d %r" % (packetNum, packet.getData())
        return True
    else:
        print 'OK!' 

    return False

def smbComNtCreateAndX( packet, packetNum, SMBCommand, questions, replies):

    # Test return code is always 0, otherwise leave before doing anything
    if packet['ErrorCode'] != 0:
        return False

    print "SMB_COM_NT_CREATE_ANDX ",
    try:
      if (packet['Flags1'] & smb.SMB.FLAGS1_REPLY) == 0:
        # Query
        ntCreateAndXParameters = smb.SMBNtCreateAndX_Parameters(SMBCommand['Parameters'])
        ntCreateAndXData       = smb.SMBNtCreateAndX_Data(SMBCommand['Data'])
      else:
        # Response
        ntCreateResponse   = SMBCommand
        ntCreateParameters = smb.SMBNtCreateAndXResponse_Parameters(ntCreateResponse['Parameters'])

    except Exception, e:
        print "ERROR: %s" % e
        print "Command: 0x%x" % packet['Command']
        print "Packet: %d %r" % (packetNum, packet.getData())
        return True
    else:
        print 'OK!' 

    return False

def smbComTreeConnectAndX( packet, packetNum, SMBCommand, questions, replies):

    # Test return code is always 0, otherwise leave before doing anything
    if packet['ErrorCode'] != 0:
        return False

    print "SMB_COM_TREE_CONNECT_ANDX ",
    try:
      if (packet['Flags1'] & smb.SMB.FLAGS1_REPLY) == 0:
        # Query
        treeConnectAndXParameters = smb.SMBTreeConnectAndX_Parameters(SMBCommand['Parameters'])
        treeConnectAndXData       = smb.SMBTreeConnectAndX_Data()
        treeConnectAndXData['_PasswordLength'] = treeConnectAndXParameters['PasswordLength']
        treeConnectAndXData.fromString(SMBCommand['Data'])
      else:
        # Response
        treeConnectAndXParameters = smb.SMBTreeConnectAndXResponse_Parameters(SMBCommand['Parameters'])
        #treeConnectAndXData       = smb.SMBTreeConnectAndXResponse_Data(SMBCommand['Data'])
    except Exception, e:
        print "ERROR: %s" % e
        print "Command: 0x%x" % packet['Command']
        print "Packet: %d %r" % (packetNum, packet.getData())
        return True
    else:
        print 'OK!' 


    return False


def smbComSessionSetupAndX( packet, packetNum, SMBCommand, questions, replies):

    # Test return code is always 0, otherwise leave before doing anything
    if packet['ErrorCode'] != 0:
        if packet['ErrorClass'] != 0x16:
          return False

    print "SMB_COM_SESSION_SETUP_ANDX ",
    try:
      if (packet['Flags1'] & smb.SMB.FLAGS1_REPLY) == 0:
        # Query 
        if SMBCommand['WordCount'] == 12:
            # Extended Security
            sessionSetupParameters = smb.SMBSessionSetupAndX_Extended_Parameters(SMBCommand['Parameters'])
            sessionSetupData = smb.SMBSessionSetupAndX_Extended_Data()
            sessionSetupData['SecurityBlobLength'] = sessionSetupParameters['SecurityBlobLength']
            sessionSetupData.fromString(SMBCommand['Data'])

            if struct.unpack('B',sessionSetupData['SecurityBlob'][0])[0] != smb.ASN1_AID:
               # If there no GSSAPI ID, it must be an AUTH packet
               blob = smb.SPNEGO_NegTokenResp(sessionSetupData['SecurityBlob'])
               token = blob['ResponseToken']
            else:
               # NEGOTIATE packet
               blob =  smb.SPNEGO_NegTokenInit(sessionSetupData['SecurityBlob'])
               token = blob['MechToken']
            messageType = struct.unpack('<L',token[len('NTLMSSP\x00'):len('NTLMSSP\x00')+4])[0]
            if messageType == 0x01:
                # NEGOTIATE_MESSAGE
                negotiateMessage = ntlm.NTLMAuthNegotiate()
                negotiateMessage.fromString(token)
            elif messageType == 0x03:
                # AUTHENTICATE_MESSAGE, here we deal with authentication
                authenticateMessage = ntlm.NTLMAuthChallengeResponse()
                authenticateMessage.fromString(token)

        else:
            # Standard Security  
            sessionSetupParameters = smb.SMBSessionSetupAndX_Parameters(SMBCommand['Parameters'])
            sessionSetupData = smb.SMBSessionSetupAndX_Data()
            sessionSetupData['AnsiPwdLength'] = sessionSetupParameters['AnsiPwdLength']
            sessionSetupData['UnicodePwdLength'] = sessionSetupParameters['UnicodePwdLength']
            sessionSetupData.fromString(SMBCommand['Data'])

      else:
        # Response
        if SMBCommand['WordCount'] == 4:
            # Extended Security
            sessionResponse   = SMBCommand
            sessionParameters = smb.SMBSessionSetupAndX_Extended_Response_Parameters(sessionResponse['Parameters'])
            sessionData       = smb.SMBSessionSetupAndX_Extended_Response_Data(flags = packet['Flags2'])
            sessionData['SecurityBlobLength'] = sessionParameters['SecurityBlobLength']
            sessionData.fromString(sessionResponse['Data'])
            respToken = smb.SPNEGO_NegTokenResp(sessionData['SecurityBlob'])
            if respToken.fields.has_key('ResponseToken'):
                # Let's parse some data and keep it to ourselves in case it is asked
                ntlmChallenge = ntlm.NTLMAuthChallenge(respToken['ResponseToken'])
                if ntlmChallenge['TargetInfoFields_len'] > 0:
                    infoFields = ntlmChallenge['TargetInfoFields']
                    av_pairs = ntlm.AV_PAIRS(ntlmChallenge['TargetInfoFields'][:ntlmChallenge['TargetInfoFields_len']]) 
                    if av_pairs[ntlm.NTLMSSP_AV_HOSTNAME] is not None:
                       __server_name = av_pairs[ntlm.NTLMSSP_AV_HOSTNAME][1].decode('utf-16le')
                    if av_pairs[ntlm.NTLMSSP_AV_DOMAINNAME] is not None:
                       __server_domain = av_pairs[ntlm.NTLMSSP_AV_DOMAINNAME][1].decode('utf-16le')


        else:
            # Standard Security
            sessionResponse   = SMBCommand

            sessionParameters = smb.SMBSessionSetupAndXResponse_Parameters(sessionResponse['Parameters'])
            sessionData       = smb.SMBSessionSetupAndXResponse_Data(flags = packet['Flags2'], data = sessionResponse['Data'])
    except Exception, e:
        print "ERROR: %s" % e
        print "Command: 0x%x" % packet['Command']
        print "Packet: %d %r" % (packetNum, packet.getData())
        return True
    else:
        print 'OK!' 
    

    return False

def smbComNegotiate( packet, packetNum, command, questions, replies):
    sessionResponse = command
    
    if packet['Flags1'] & smb.SMB.FLAGS1_REPLY:
        print "SMB_COM_NEGOTIATE ",
        try:
            _dialects_parameters = smb.SMBNTLMDialect_Parameters(sessionResponse['Parameters'])
            _dialects_data = smb.SMBNTLMDialect_Data()
            _dialects_data['ChallengeLength'] = _dialects_parameters['ChallengeLength']
            _dialects_data.fromString(sessionResponse['Data'])
            if _dialects_parameters['Capabilities'] & smb.SMB.CAP_EXTENDED_SECURITY:
                _dialects_parameters = smb.SMBExtended_Security_Parameters(sessionResponse['Parameters'])
                _dialects_data       = smb.SMBExtended_Security_Data(sessionResponse['Data'])

        except Exception, e:
            print "ERROR: %s" % e
            print "Command: 0x%x" % packet['Command']
            print "Packet: %d %r" % (packetNum, packet.getData())
            return True
        else:
            print 'OK!' 


    return False

# Format
# { SMBCOMMAND: ((questionStruts),(replyStructus), handler) }
HANDLER   = 2
REPLIES   = 1
QUESTIONS = 0

smbCommands = {
# smb.SMB.SMB_COM_CREATE_DIRECTORY:   (, 
# smb.SMB.SMB_COM_DELETE_DIRECTORY:   self.smbComDeleteDirectory, 
# smb.SMB.SMB_COM_RENAME:             self.smbComRename, 
# smb.SMB.SMB_COM_DELETE:             self.smbComDelete, 
 smb.SMB.SMB_COM_NEGOTIATE:          ( None,None,smbComNegotiate), 
 smb.SMB.SMB_COM_SESSION_SETUP_ANDX: ( None,None,smbComSessionSetupAndX),
# smb.SMB.SMB_COM_LOGOFF_ANDX:        self.smbComLogOffAndX,
 smb.SMB.SMB_COM_TREE_CONNECT_ANDX:  ( None,None,smbComTreeConnectAndX),
# smb.SMB.SMB_COM_TREE_DISCONNECT:    self.smbComTreeDisconnect,
# smb.SMB.SMB_COM_ECHO:               self.get_th_sportsmbComEcho,
# smb.SMB.SMB_COM_QUERY_INFORMATION:  self.smbQueryInformation,
 smb.SMB.SMB_COM_TRANSACTION2:       ( None, None, smbTransaction2),
# smb.SMB.SMB_COM_TRANSACTION:        self.smbTransaction,
# smb.SMB.SMB_COM_NT_TRANSACT:        self.smbNTTransact,
# smb.SMB.SMB_COM_QUERY_INFORMATION_DISK: sler.smbQueryInformationDisk,
 smb.SMB.SMB_COM_OPEN_ANDX:          (None, None, smbComOpenAndX),
# smb.SMB.SMB_COM_QUERY_INFORMATION2: self.smbComQueryInformation2,
# smb.SMB.SMB_COM_READ_ANDX:          self.smbComReadAndX,
# smb.SMB.SMB_COM_READ:               self.smbComRead,
 smb.SMB.SMB_COM_WRITE_ANDX:         (None, None, smbComWriteAndX),
# smb.SMB.SMB_COM_WRITE:              self.smbComWrite,
# smb.SMB.SMB_COM_CLOSE:              self.smbComClose,
# smb.SMB.SMB_COM_LOCKING_ANDX:       self.smbComLockingAndX,
 smb.SMB.SMB_COM_NT_CREATE_ANDX:     (None, None, smbComNtCreateAndX),
# 0xFF:                               self.default
}

# Returns True is the packet needs to be logged
def process(data, packetNum):
    packet = smb.NewSMBPacket()
    if data.get_packet()[0] == '\x00':
       if data.get_packet()[4:8] == '\xffSMB':
           try:
               packet.fromString(data.get_packet()[4:])
           except Exception, e:
               print "ERROR: %s" % e
               print "Command: SMBPacket" 
               print "Packet: %d %r" % (packetNum, data.get_packet())
               return True
       else:
           return False
    else:
       return False

    try:
       SMBCommand = smb.SMBCommand(packet['Data'][0])
    except Exception, e:
       print "ERROR: %s" % e
       print "Command: SMBCommand" 
       print "Packet: %d %r" % (packetNum, data.get_packet())
       return True

    if smbCommands.has_key(packet['Command']):
         return smbCommands[packet['Command']][HANDLER](packet, packetNum, SMBCommand, smbCommands[packet['Command']][QUESTIONS], smbCommands[packet['Command']][REPLIES])
    #else:
    #     print "Command 0x%x not handled" % packet['Command']


    
def main():
    import sys
    DEFAULT_PROTOCOLS = ('tcp',)
    sockets = []

    print version.BANNER

    parser = argparse.ArgumentParser()
    parser.add_argument("-i", metavar = 'FILE', help = 'pcap file to read packets. If not specified the program sniffes traffic (only as root)')
    parser.add_argument("-o", metavar = 'FILE', help = 'pcap output file where the packets with errors will be written')

    options = parser.parse_args()

    outFile = options.o

    if options.i is None:
        sniffTraffic = True
        toListen = DEFAULT_PROTOCOLS
    else:
        sniffTraffic = False
        inFile = options.i

    packetNum = 0
    
    if outFile:
        f_out = open(outFile,'wb')
        f_out.write(str(pcapfile.PCapFileHeader()))

    if sniffTraffic is False:
        f_in = open(inFile,'rb')

        hdr = pcapfile.PCapFileHeader()
        hdr.fromString(f_in.read(len(hdr)))
        decoder = ImpactDecoder.EthDecoder()
    else:
        for protocol in toListen:
           try:
                protocol_num = socket.getprotobyname(protocol)
           except socket.error:
               print "Ignoring unknown protocol:", protocol
               toListen.remove(protocol)
	       continue
           s = socket.socket(socket.AF_INET, socket.SOCK_RAW, protocol_num)
           s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
           sockets.append(s)
           print "Listening on protocols:", toListen
        decoder = ImpactDecoder.IPDecoder()

    while 1:
       if sniffTraffic is False:
           pkt = pcapfile.PCapFilePacket()
           try:
              pkt.fromString(f_in.read(len(pkt)))
           except:
              break
           pkt['data'] = f_in.read(pkt['savedLength'])
           p = pkt['data']
       else:
	   ready = select(sockets, [], [])[0]
	   for s in ready:
		p = s.recvfrom(4096)[0]
		if 0 == len(p):
			# Socket remotely closed. Discard it.
			sockets.remove(s)
			s.close()

       packet = decoder.decode(p)
       packetNum += 1
       if sniffTraffic is True: 
           instance = packet.child()
       else:
           instance = packet.child().child()

       if isinstance(instance, ImpactPacket.TCP): 
          tcppacket = instance
          if tcppacket.get_th_sport() == 445 or tcppacket.get_th_dport() == 445 or tcppacket.get_th_sport() == 139 or tcppacket.get_th_dport() == 139:
              data = tcppacket.child()
              if data.get_size() > 0:
                  logPacket = process(data, packetNum)
                  if logPacket is True:
                      pkt_out = pcapfile.PCapFilePacket()
                      if sniffTraffic is True:
                          eth = ImpactPacket.Ethernet()
                          eth.contains(packet)
                          eth.set_ether_type(0x800)
                          pkt_out['data'] = eth.get_packet()
                      else:
                          pkt_out['data'] = str(p)
                      if outFile:
                          f_out.write(str(pkt_out))

if __name__ == '__main__':
   main()
    
