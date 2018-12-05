# SECUREAUTH LABS. Copyright 2018 SecureAuth Corporation. All rights reserved.
#
# This software is provided under under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Description:
#  EAP packets
#
# Author:
# Aureliano Calvo


from impacket.helper import ProtocolPacket, Byte, Word, Long, ThreeBytesBigEndian

DOT1X_AUTHENTICATION = 0x888E

class EAPExpanded(ProtocolPacket):
    """EAP expanded data according to RFC 3748, section 5.7"""
    
    WFA_SMI = 0x00372a
    SIMPLE_CONFIG = 0x00000001

    header_size = 7
    tail_size = 0
    
    vendor_id = ThreeBytesBigEndian(0)
    vendor_type = Long(3, ">")

class EAPR(ProtocolPacket):
    """It represents a request or a response in EAP (codes 1 and 2)"""
    
    IDENTITY = 0x01
    EXPANDED = 0xfe

    header_size = 1
    tail_size = 0
    
    type = Byte(0)            

class EAP(ProtocolPacket):
    REQUEST = 0x01
    RESPONSE = 0x02
    SUCCESS = 0x03
    FAILURE = 0x04 

    header_size = 4
    tail_size = 0

    code = Byte(0)
    identifier = Byte(1)
    length = Word(2, ">")        

class EAPOL(ProtocolPacket):
    EAP_PACKET = 0x00
    EAPOL_START = 0x01
    EAPOL_LOGOFF = 0x02
    EAPOL_KEY = 0x03
    EAPOL_ENCAPSULATED_ASF_ALERT = 0x04
    
    DOT1X_VERSION = 0x01

    header_size = 4
    tail_size = 0
    
    version = Byte(0)
    packet_type = Byte(1)
    body_length = Word(2, ">")
    

