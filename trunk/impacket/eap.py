
# Copyright (c) 2003-2013 CORE Security Technologies
#
# This software is provided under under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# $Id$
#
# Description:
#  EAP packets
#
# Author:
# Aureliano Calvo


from helper import ProtocolPacket, Byte, Word, Long, ThreeBytesBigEndian, BaseDecoder
from dot11 import SNAP
import wps

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
    
class EAPExpandedDecoder(BaseDecoder):
    child_decoders = {
        (EAPExpanded.WFA_SMI, EAPExpanded.SIMPLE_CONFIG): wps.SimpleConfigDecoder(),
    }
    klass = EAPExpanded
    child_key = lambda s,p: (p.get_vendor_id(), p.get_vendor_type())
        
class EAPRDecoder(BaseDecoder):
    child_decoders = {
        EAPR.EXPANDED:EAPExpandedDecoder()
    }
    klass = EAPR
    child_key = lambda s, p: p.get_type()
        
class EAPDecoder(BaseDecoder):
    child_decoders = {
        EAP.REQUEST: EAPRDecoder(),
        EAP.RESPONSE: EAPRDecoder(),
    }
    klass = EAP
    child_key = lambda s, p: p.get_code()
        
class EAPOLDecoder(BaseDecoder):
    child_decoders = {
        EAPOL.EAP_PACKET: EAPDecoder()
    }
    klass = EAPOL
    child_key = lambda s, p: p.get_packet_type()
    
class EnhancedDecoder(object):
    """Enhances a decoder so it handles an EAPOL packet inside a SNAP packet"""
    
    def __init__(self, base_decoder):
        self.base_decoder = base_decoder
    
    def decode(self, buff):
        packet = self.base_decoder.decode(buff)
        snap = self.get_protocol(SNAP)
        
        if snap and snap.get_protoID() == DOT1X_AUTHENTICATION:
            snap.contains(EAPOLDecoder().decode(snap.get_body_as_string()))
            
        return packet
    
    def get_protocol(self, p):
        return self.base_decoder.get_protocol(p)