# Copyright (c) 2003-2006 CORE Security Technologies
#
# This software is provided under under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# $Id$
#
# Description:
#  IEEE 802.11 Network packet codecs.
#
# Author:
#  Gustavo Moreira

import array
import struct
import socket
import string
import sys
from ImpactPacket import ProtocolLayer, PacketBuffer, Header
from binascii import hexlify,crc32
from struct import unpack

class Dot11Types():
    # Management Types/SubTypes
    DOT11_TYPE_MANAGEMENT                           = int("00",2)
    DOT11_SUBTYPE_MANAGEMENT_ASSOCIATION_REQUEST    = int("0000",2)
    DOT11_SUBTYPE_MANAGEMENT_ASSOCIATION_RESPONSE   = int("0001",2)
    DOT11_SUBTYPE_MANAGEMENT_REASSOCIATION_REQUEST  = int("0010",2)
    DOT11_SUBTYPE_MANAGEMENT_REASSOCIATION_RESPONSE = int("0011",2)
    DOT11_SUBTYPE_MANAGEMENT_PROBE_REQUEST          = int("0100",2)
    DOT11_SUBTYPE_MANAGEMENT_PROBE_RESPONSE         = int("0101",2)
    DOT11_SUBTYPE_MANAGEMENT_RESERVED1              = int("0110",2)
    DOT11_SUBTYPE_MANAGEMENT_RESERVED2              = int("0111",2)
    DOT11_SUBTYPE_MANAGEMENT_BEACON                 = int("1000",2)
    DOT11_SUBTYPE_MANAGEMENT_ATIM                   = int("1001",2)
    DOT11_SUBTYPE_MANAGEMENT_DISASSOCIATION         = int("1010",2)
    DOT11_SUBTYPE_MANAGEMENT_AUTHENTICATION         = int("1011",2)
    DOT11_SUBTYPE_MANAGEMENT_DEAUTHENTICATION       = int("1100",2)
    DOT11_SUBTYPE_MANAGEMENT_ACTION                 = int("1101",2)
    DOT11_SUBTYPE_MANAGEMENT_RESERVED3              = int("1110",2)
    DOT11_SUBTYPE_MANAGEMENT_RESERVED4              = int("1111",2)

    DOT11_TYPE_MANAGEMENT_SUBTYPE_ASSOCIATION_REQUEST = \
        DOT11_TYPE_MANAGEMENT|DOT11_SUBTYPE_MANAGEMENT_ASSOCIATION_REQUEST<<2
    DOT11_TYPE_MANAGEMENT_SUBTYPE_ASSOCIATION_RESPONSE = \
        DOT11_TYPE_MANAGEMENT|DOT11_SUBTYPE_MANAGEMENT_ASSOCIATION_RESPONSE<<2
    DOT11_TYPE_MANAGEMENT_SUBTYPE_REASSOCIATION_REQUEST = \
        DOT11_TYPE_MANAGEMENT|DOT11_SUBTYPE_MANAGEMENT_REASSOCIATION_REQUEST<<2
    DOT11_TYPE_MANAGEMENT_SUBTYPE_REASSOCIATION_RESPONSE = \
        DOT11_TYPE_MANAGEMENT|DOT11_SUBTYPE_MANAGEMENT_REASSOCIATION_REQUEST<<2
    DOT11_TYPE_MANAGEMENT_SUBTYPE_PROBE_REQUEST = \
        DOT11_TYPE_MANAGEMENT|DOT11_SUBTYPE_MANAGEMENT_PROBE_REQUEST<<2
    DOT11_TYPE_MANAGEMENT_SUBTYPE_PROBE_RESPONSE = \
        DOT11_TYPE_MANAGEMENT|DOT11_SUBTYPE_MANAGEMENT_PROBE_RESPONSE<<2
    DOT11_TYPE_MANAGEMENT_SUBTYPE_RESERVED1 = \
        DOT11_TYPE_MANAGEMENT|DOT11_SUBTYPE_MANAGEMENT_RESERVED1<<2
    DOT11_TYPE_MANAGEMENT_SUBTYPE_RESERVED2 = \
        DOT11_TYPE_MANAGEMENT|DOT11_SUBTYPE_MANAGEMENT_RESERVED2<<2
    DOT11_TYPE_MANAGEMENT_SUBTYPE_BEACON = \
        DOT11_TYPE_MANAGEMENT|DOT11_SUBTYPE_MANAGEMENT_BEACON<<2
    DOT11_TYPE_MANAGEMENT_SUBTYPE_ATIM = \
        DOT11_TYPE_MANAGEMENT|DOT11_SUBTYPE_MANAGEMENT_ATIM<<2
    DOT11_TYPE_MANAGEMENT_SUBTYPE_DISASSOCIATION = \
        DOT11_TYPE_MANAGEMENT|DOT11_SUBTYPE_MANAGEMENT_DISASSOCIATION<<2
    DOT11_TYPE_MANAGEMENT_SUBTYPE_AUTHENTICATION = \
        DOT11_TYPE_MANAGEMENT|DOT11_SUBTYPE_MANAGEMENT_AUTHENTICATION<<2
    DOT11_TYPE_MANAGEMENT_SUBTYPE_DEAUTHENTICATION = \
        DOT11_TYPE_MANAGEMENT|DOT11_SUBTYPE_MANAGEMENT_DEAUTHENTICATION<<2
    DOT11_TYPE_MANAGEMENT_SUBTYPE_ACTION = \
        DOT11_TYPE_MANAGEMENT|DOT11_SUBTYPE_MANAGEMENT_ACTION<<2
    DOT11_TYPE_MANAGEMENT_SUBTYPE_RESERVED3 = \
        DOT11_TYPE_MANAGEMENT|DOT11_SUBTYPE_MANAGEMENT_RESERVED3<<2
    DOT11_TYPE_MANAGEMENT_SUBTYPE_RESERVED4 = \
        DOT11_TYPE_MANAGEMENT|DOT11_SUBTYPE_MANAGEMENT_RESERVED4<<2
    
    # Control Types/SubTypes
    DOT11_TYPE_CONTROL                              = int("01",2)
    DOT11_SUBTYPE_CONTROL_RESERVED1                 = int("0000",2)
    DOT11_SUBTYPE_CONTROL_RESERVED2                 = int("0001",2)
    DOT11_SUBTYPE_CONTROL_RESERVED3                 = int("0010",2)
    DOT11_SUBTYPE_CONTROL_RESERVED4                 = int("0011",2)
    DOT11_SUBTYPE_CONTROL_RESERVED5                 = int("0100",2)
    DOT11_SUBTYPE_CONTROL_RESERVED6                 = int("0101",2)
    DOT11_SUBTYPE_CONTROL_RESERVED7                 = int("0110",2)
    DOT11_SUBTYPE_CONTROL_RESERVED8                 = int("0111",2)
    DOT11_SUBTYPE_CONTROL_BLOCK_ACK_REQUEST         = int("1000",2)
    DOT11_SUBTYPE_CONTROL_BLOCK_ACK                 = int("1001",2)
    DOT11_SUBTYPE_CONTROL_POWERSAVE_POLL            = int("1010",2)
    DOT11_SUBTYPE_CONTROL_REQUEST_TO_SEND           = int("1011",2)
    DOT11_SUBTYPE_CONTROL_CLEAR_TO_SEND             = int("1100",2)
    DOT11_SUBTYPE_CONTROL_ACKNOWLEDGMENT            = int("1101",2)
    DOT11_SUBTYPE_CONTROL_CF_END                    = int("1110",2)
    DOT11_SUBTYPE_CONTROL_CF_END_CF_ACK             = int("1111",2)

    DOT11_TYPE_CONTROL_SUBTYPE_RESERVED1 = \
        DOT11_TYPE_CONTROL|DOT11_SUBTYPE_CONTROL_RESERVED1<<2
    DOT11_TYPE_CONTROL_SUBTYPE_RESERVED2 = \
        DOT11_TYPE_CONTROL|DOT11_SUBTYPE_CONTROL_RESERVED2<<2
    DOT11_TYPE_CONTROL_SUBTYPE_RESERVED3 = \
        DOT11_TYPE_CONTROL|DOT11_SUBTYPE_CONTROL_RESERVED3<<2
    DOT11_TYPE_CONTROL_SUBTYPE_RESERVED4 = \
        DOT11_TYPE_CONTROL|DOT11_SUBTYPE_CONTROL_RESERVED4<<2
    DOT11_TYPE_CONTROL_SUBTYPE_RESERVED5 = \
        DOT11_TYPE_CONTROL|DOT11_SUBTYPE_CONTROL_RESERVED5<<2
    DOT11_TYPE_CONTROL_SUBTYPE_RESERVED6 = \
        DOT11_TYPE_CONTROL|DOT11_SUBTYPE_CONTROL_RESERVED6<<2
    DOT11_TYPE_CONTROL_SUBTYPE_RESERVED7 = \
        DOT11_TYPE_CONTROL|DOT11_SUBTYPE_CONTROL_RESERVED7<<2
    DOT11_TYPE_CONTROL_SUBTYPE_BLOCK_ACK_REQUEST = \
        DOT11_TYPE_CONTROL|DOT11_SUBTYPE_CONTROL_BLOCK_ACK_REQUEST<<2
    DOT11_TYPE_CONTROL_SUBTYPE_BLOCK_ACK = \
        DOT11_TYPE_CONTROL|DOT11_SUBTYPE_CONTROL_BLOCK_ACK<<2
    DOT11_TYPE_CONTROL_SUBTYPE_POWERSAVE_POLL = \
        DOT11_TYPE_CONTROL|DOT11_SUBTYPE_CONTROL_POWERSAVE_POLL<<2
    DOT11_TYPE_CONTROL_SUBTYPE_REQUEST_TO_SEND = \
        DOT11_TYPE_CONTROL|DOT11_SUBTYPE_CONTROL_REQUEST_TO_SEND<<2
    DOT11_TYPE_CONTROL_SUBTYPE_CLEAR_TO_SEND = \
        DOT11_TYPE_CONTROL|DOT11_SUBTYPE_CONTROL_CLEAR_TO_SEND<<2
    DOT11_TYPE_CONTROL_SUBTYPE_ACKNOWLEDGMENT = \
        DOT11_TYPE_CONTROL|DOT11_SUBTYPE_CONTROL_ACKNOWLEDGMENT<<2
    DOT11_TYPE_CONTROL_SUBTYPE_CF_END = \
        DOT11_TYPE_CONTROL|DOT11_SUBTYPE_CONTROL_CF_END<<2
    DOT11_TYPE_CONTROL_SUBTYPE_CF_END_CF_ACK = \
        DOT11_TYPE_CONTROL|DOT11_SUBTYPE_CONTROL_CF_END_CF_ACK<<2

    # Data Types/SubTypes
    DOT11_TYPE_DATA                                = int("10",2)
    DOT11_SUBTYPE_DATA                             = int("0000",2)
    DOT11_SUBTYPE_DATA_CF_ACK                      = int("0001",2)
    DOT11_SUBTYPE_DATA_CF_POLL                     = int("0010",2)
    DOT11_SUBTYPE_DATA_CF_ACK_CF_POLL              = int("0011",2)
    DOT11_SUBTYPE_DATA_NULL_NO_DATA                = int("0100",2)
    DOT11_SUBTYPE_DATA_CF_ACK_NO_DATA              = int("0101",2)
    DOT11_SUBTYPE_DATA_CF_POLL_NO_DATA             = int("0110",2)
    DOT11_SUBTYPE_DATA_CF_ACK_CF_POLL_NO_DATA      = int("0111",2)
    DOT11_SUBTYPE_DATA_QOS_DATA                    = int("1000",2)
    DOT11_SUBTYPE_DATA_QOS_DATA_CF_ACK             = int("1001",2)
    DOT11_SUBTYPE_DATA_QOS_DATA_CF_POLL            = int("1010",2)
    DOT11_SUBTYPE_DATA_QOS_DATA_CF_ACK_CF_POLL     = int("1011",2)
    DOT11_SUBTYPE_DATA_QOS_NULL_NO_DATA            = int("1100",2)
    DOT11_SUBTYPE_DATA_RESERVED1                   = int("1101",2)
    DOT11_SUBTYPE_DATA_QOS_CF_POLL_NO_DATA         = int("1110",2)
    DOT11_SUBTYPE_DATA_QOS_CF_ACK_CF_POLL_NO_DATA  = int("1111",2)

    DOT11_TYPE_DATA_SUBTYPE_DATA = \
        DOT11_TYPE_DATA|DOT11_SUBTYPE_DATA<<2
    DOT11_TYPE_DATA_SUBTYPE_CF_ACK = \
        DOT11_TYPE_DATA|DOT11_SUBTYPE_DATA_CF_ACK<<2
    DOT11_TYPE_DATA_SUBTYPE_CF_POLL = \
        DOT11_TYPE_DATA|DOT11_SUBTYPE_DATA_CF_POLL<<2
    DOT11_TYPE_DATA_SUBTYPE_CF_ACK_CF_POLL = \
        DOT11_TYPE_DATA|DOT11_SUBTYPE_DATA_CF_ACK_CF_POLL<<2
    DOT11_TYPE_DATA_SUBTYPE_NULL_NO_DATA = \
        DOT11_TYPE_DATA|DOT11_SUBTYPE_DATA_NULL_NO_DATA<<2
    DOT11_TYPE_DATA_SUBTYPE_CF_ACK_NO_DATA = \
        DOT11_TYPE_DATA|DOT11_SUBTYPE_DATA_CF_POLL_NO_DATA<<2
    DOT11_TYPE_DATA_SUBTYPE_CF_ACK_CF_POLL_NO_DATA = \
        DOT11_TYPE_DATA|DOT11_SUBTYPE_DATA_CF_ACK_CF_POLL_NO_DATA<<2
    DOT11_TYPE_DATA_SUBTYPE_QOS_DATA = \
        DOT11_TYPE_DATA|DOT11_SUBTYPE_DATA_QOS_DATA<<2
    DOT11_TYPE_DATA_SUBTYPE_QOS_DATA_CF_ACK = \
        DOT11_TYPE_DATA|DOT11_SUBTYPE_DATA_QOS_DATA_CF_ACK<<2
    DOT11_TYPE_DATA_SUBTYPE_QOS_DATA_CF_POLL = \
        DOT11_TYPE_DATA|DOT11_SUBTYPE_DATA_QOS_DATA_CF_POLL<<2
    DOT11_TYPE_DATA_SUBTYPE_QOS_DATA_CF_ACK_CF_POLL = \
        DOT11_TYPE_DATA|DOT11_SUBTYPE_DATA_QOS_DATA_CF_ACK_CF_POLL<<2
    DOT11_TYPE_DATA_SUBTYPE_QOS_NULL_NO_DATA = \
        DOT11_TYPE_DATA|DOT11_SUBTYPE_DATA_QOS_NULL_NO_DATA<<2
    DOT11_TYPE_DATA_SUBTYPE_RESERVED1 = \
        DOT11_TYPE_DATA|DOT11_SUBTYPE_DATA_RESERVED1<<2
    DOT11_TYPE_DATA_SUBTYPE_QOS_CF_POLL_NO_DATA = \
        DOT11_TYPE_DATA|DOT11_SUBTYPE_DATA_QOS_CF_POLL_NO_DATA<<2
    DOT11_TYPE_DATA_SUBTYPE_QOS_CF_ACK_CF_POLL_NO_DATA = \
        DOT11_TYPE_DATA|DOT11_SUBTYPE_DATA_QOS_CF_ACK_CF_POLL_NO_DATA<<2

    # Reserved Types/SubTypes
    DOT11_TYPE_RESERVED = int("11",2)
    DOT11_SUBTYPE_RESERVED_RESERVED1               = int("0000",2)
    DOT11_SUBTYPE_RESERVED_RESERVED2               = int("0001",2)
    DOT11_SUBTYPE_RESERVED_RESERVED3               = int("0010",2)
    DOT11_SUBTYPE_RESERVED_RESERVED4               = int("0011",2)
    DOT11_SUBTYPE_RESERVED_RESERVED5               = int("0100",2)
    DOT11_SUBTYPE_RESERVED_RESERVED6               = int("0101",2)
    DOT11_SUBTYPE_RESERVED_RESERVED7               = int("0110",2)
    DOT11_SUBTYPE_RESERVED_RESERVED8               = int("0111",2)
    DOT11_SUBTYPE_RESERVED_RESERVED9               = int("1000",2)
    DOT11_SUBTYPE_RESERVED_RESERVED10              = int("1001",2)
    DOT11_SUBTYPE_RESERVED_RESERVED11              = int("1010",2)
    DOT11_SUBTYPE_RESERVED_RESERVED12              = int("1011",2)
    DOT11_SUBTYPE_RESERVED_RESERVED13              = int("1100",2)
    DOT11_SUBTYPE_RESERVED_RESERVED14              = int("1101",2)
    DOT11_SUBTYPE_RESERVED_RESERVED15              = int("1110",2)
    DOT11_SUBTYPE_RESERVED_RESERVED16              = int("1111",2)

    DOT11_TYPE_RESERVED_SUBTYPE_RESERVED1 = \
        DOT11_TYPE_RESERVED|DOT11_SUBTYPE_RESERVED_RESERVED1<<2
    DOT11_TYPE_RESERVED_SUBTYPE_RESERVED2 = \
        DOT11_TYPE_RESERVED|DOT11_SUBTYPE_RESERVED_RESERVED2<<2
    DOT11_TYPE_RESERVED_SUBTYPE_RESERVED3 = \
        DOT11_TYPE_RESERVED|DOT11_SUBTYPE_RESERVED_RESERVED3<<2
    DOT11_TYPE_RESERVED_SUBTYPE_RESERVED4 = \
        DOT11_TYPE_RESERVED|DOT11_SUBTYPE_RESERVED_RESERVED4<<2
    DOT11_TYPE_RESERVED_SUBTYPE_RESERVED5 = \
        DOT11_TYPE_RESERVED|DOT11_SUBTYPE_RESERVED_RESERVED5<<2
    DOT11_TYPE_RESERVED_SUBTYPE_RESERVED6 = \
        DOT11_TYPE_RESERVED|DOT11_SUBTYPE_RESERVED_RESERVED6<<2
    DOT11_TYPE_RESERVED_SUBTYPE_RESERVED7 = \
        DOT11_TYPE_RESERVED|DOT11_SUBTYPE_RESERVED_RESERVED7<<2
    DOT11_TYPE_RESERVED_SUBTYPE_RESERVED8 = \
        DOT11_TYPE_RESERVED|DOT11_SUBTYPE_RESERVED_RESERVED8<<2
    DOT11_TYPE_RESERVED_SUBTYPE_RESERVED9 = \
        DOT11_TYPE_RESERVED|DOT11_SUBTYPE_RESERVED_RESERVED9<<2
    DOT11_TYPE_RESERVED_SUBTYPE_RESERVED10 = \
        DOT11_TYPE_RESERVED|DOT11_SUBTYPE_RESERVED_RESERVED10<<2
    DOT11_TYPE_RESERVED_SUBTYPE_RESERVED11 = \
        DOT11_TYPE_RESERVED|DOT11_SUBTYPE_RESERVED_RESERVED11<<2
    DOT11_TYPE_RESERVED_SUBTYPE_RESERVED12 = \
        DOT11_TYPE_RESERVED|DOT11_SUBTYPE_RESERVED_RESERVED12<<2
    DOT11_TYPE_RESERVED_SUBTYPE_RESERVED13 = \
        DOT11_TYPE_RESERVED|DOT11_SUBTYPE_RESERVED_RESERVED13<<2
    DOT11_TYPE_RESERVED_SUBTYPE_RESERVED14 = \
        DOT11_TYPE_RESERVED|DOT11_SUBTYPE_RESERVED_RESERVED14<<2
    DOT11_TYPE_RESERVED_SUBTYPE_RESERVED15 = \
        DOT11_TYPE_RESERVED|DOT11_SUBTYPE_RESERVED_RESERVED15<<2
    DOT11_TYPE_RESERVED_SUBTYPE_RESERVED16 = \
        DOT11_TYPE_RESERVED|DOT11_SUBTYPE_RESERVED_RESERVED16<<2

class AbstractDot11(ProtocolLayer):
    __HEADER_SIZE = 0
    __BODY_SIZE = 0
    __TAIL_SIZE = 0
    
    __header = None
    __body = None
    __tail = None

    def __init__(self, header_size, tail_size):
        self.__HEADER_SIZE = header_size
        self.__TAIL_SIZE = tail_size
        self.__header=PacketBuffer(self.__HEADER_SIZE)
        self.__body=PacketBuffer()
        self.__tail=PacketBuffer(self.__TAIL_SIZE)
    
    def __get_header(self):
        return self.__header
    
    header = property(__get_header)

    def __get_body(self):
        return self.__body
    
    body = property(__get_body)
    
    def __get_tail(self):
        return self.__tail
    
    tail = property(__get_tail)

    def get_header_size(self):
        "Return frame header size"
        return self.__HEADER_SIZE
    
    def get_tail_size(self):
        "Return frame tail size"
        return self.__TAIL_SIZE
    
    def get_body_size(self):
        "Return frame body size"
        return self.__BODY_SIZE

    def get_size(self):
        "Return frame total size"
        return self.__HEADER_SIZE+self.__BODY_SIZE+self.__TAIL_SIZE
        
    def extract_header(self, aBuffer):
        self.__header.set_bytes_from_string(aBuffer[:self.__HEADER_SIZE])
        
    def extract_body(self, aBuffer):
        if self.__TAIL_SIZE<=0:
            end=None
        else:
            end=-self.__TAIL_SIZE
        self.__BODY_SIZE=len(aBuffer[self.__HEADER_SIZE:end])
        self.__body.set_bytes_from_string(aBuffer[self.__HEADER_SIZE:end])
        
    def extract_tail(self, aBuffer):
        if self.__TAIL_SIZE<=0:
            # leave the array empty
            return
        else:
            start=-self.__TAIL_SIZE
        self.__tail.set_bytes_from_string(aBuffer[start:])

    def load_packet(self, aBuffer):
        self.extract_header(aBuffer)
        self.extract_body(aBuffer)
        self.extract_tail(aBuffer)
        
    def get_header_as_string(self):
        return self.__header.get_buffer_as_string()
        
    def get_body_as_string(self):
        return self.__body.get_buffer_as_string()

    body_string = property(get_body_as_string)
        
    def load_body(self, aBuffer):
        self.__body.set_bytes_from_string(aBuffer[self.__HEADER_SIZE:end])
        
    def get_tail_as_string(self):
        return self.__tail.get_buffer_as_string()
        
    def get_packet(self):
        
        self.calculate_checksum()
        
        ret = ''
        
        header = self.get_header_as_string()
        if header:
            ret += header

        body = self.get_body_as_string()
        if body:
            ret += body
        
        tail = self.get_tail_as_string()    
        if tail:
            ret += tail
            
        return ret
    
    def calculate_checksum(self):
        "Calculate and set the checksum for this header"
        pass

class Dot11(AbstractDot11):
    __HEADER_SIZE = 2
    __TAIL_SIZE = 4
    
    def __init__(self, aBuffer = None):
        AbstractDot11.__init__(self, self.__HEADER_SIZE, self.__TAIL_SIZE)
        if(aBuffer):
            self.load_packet(aBuffer)

    def get_order(self):
        "Return 802.11 frame 'Order' field"
        b = self.header.get_byte(1)
        return ((b >> 7) & 0x01)

    def set_order(self, value):
        "Set 802.11 frame 'Order' field"
        # clear the bits
        mask = (~0x80) & 0xFF
        masked = self.header.get_byte(1) & mask
        # set the bits
        nb = masked | ((value & 0x01) << 7)
        self.header.set_byte(1, nb)

    def get_protectedFrame(self):
        "Return 802.11 frame 'Protected' field"
        b = self.header.get_byte(1)
        return ((b >> 6) & 0x01)

    def set_protectedFrame(self, value):
        "Set 802.11 frame 'Protected Frame' field"
        # clear the bits
        mask = (~0x40) & 0xFF
        masked = self.header.get_byte(1) & mask
        # set the bits
        nb = masked | ((value & 0x01) << 6)
        self.header.set_byte(1, nb)

    def get_moreData(self):
        "Return 802.11 frame 'More Data' field"
        b = self.header.get_byte(1)
        return ((b >> 5) & 0x01)

    def set_moreData(self, value):
        "Set 802.11 frame 'More Data' field"
        # clear the bits
        mask = (~0x20) & 0xFF
        masked = self.header.get_byte(1) & mask
        # set the bits
        nb = masked | ((value & 0x01) << 5)
        self.header.set_byte(1, nb)
        
    def get_powerManagement(self):
        "Return 802.11 frame 'Power Management' field"
        b = self.header.get_byte(1)
        return ((b >> 4) & 0x01)

    def set_powerManagement(self, value):
        "Set 802.11 frame 'Power Management' field"
        # clear the bits
        mask = (~0x10) & 0xFF
        masked = self.header.get_byte(1) & mask
        # set the bits
        nb = masked | ((value & 0x01) << 4)
        self.header.set_byte(1, nb)
  
    def get_retry(self):
        "Return 802.11 frame 'Retry' field"
        b = self.header.get_byte(1)
        return ((b >> 3) & 0x01)

    def set_retry(self, value):
        "Set 802.11 frame 'Retry' field"
        # clear the bits
        mask = (~0x08) & 0xFF
        masked = self.header.get_byte(1) & mask
        # set the bits
        nb = masked | ((value & 0x01) << 3)
        self.header.set_byte(1, nb)   
        
    def get_moreFrag(self):
        "Return 802.11 frame 'More Fragments' field"
        b = self.header.get_byte(1)
        return ((b >> 2) & 0x01)

    def set_moreFrag(self, value):
        "Set 802.11 frame 'More Fragments' field"
        # clear the bits
        mask = (~0x04) & 0xFF
        masked = self.header.get_byte(1) & mask
        # set the bits
        nb = masked | ((value & 0x01) << 2)
        self.header.set_byte(1, nb)  
               
    def get_fromDS(self):
        "Return 802.11 frame 'from DS' field"
        b = self.header.get_byte(1)
        return ((b >> 1) & 0x01)

    def set_fromDS(self, value):
        "Set 802.11 frame 'from DS' field"
        # clear the bits
        mask = (~0x02) & 0xFF
        masked = self.header.get_byte(1) & mask
        # set the bits
        nb = masked | ((value & 0x01) << 1)
        self.header.set_byte(1, nb)
         
    def get_toDS(self):
        "Return 802.11 frame 'to DS' field"
        b = self.header.get_byte(1)
        return (b & 0x01)

    def set_toDS(self, value):
        "Set 802.11 frame 'to DS' field"
        # clear the bits
        mask = (~0x01) & 0xFF
        masked = self.header.get_byte(1) & mask
        # set the bits
        nb = masked | (value & 0x01) 
        self.header.set_byte(1, nb)    
        
    def get_subtype(self):
        "Return 802.11 frame 'subtype' field"
        b = self.header.get_byte(0)
        return ((b >> 4) & 0x0F)

    def set_subtype(self, value):
        "Set 802.11 frame 'subtype' field"
        # clear the bits
        mask = (~0xF0)&0xFF 
        masked = self.header.get_byte(0) & mask 
        # set the bits
        nb = masked | ((value << 4) & 0xF0)
        self.header.set_byte(0, nb)
        
    def get_type(self):
        "Return 802.11 frame 'type' field"
        b = self.header.get_byte(0)
        return ((b >> 2) & 0x03)

    def set_type(self, value):
        "Set 802.11 frame 'type' field"
        # clear the bits
        mask = (~0x0C)&0xFF 
        masked = self.header.get_byte(0) & mask 
        # set the bits
        nb = masked | ((value << 2) & 0x0C)
        self.header.set_byte(0, nb)

    def get_type_n_subtype(self):
        "Return 802.11 frame 'Type and Subtype' field"
        b = self.header.get_byte(0)
        return ((b >> 2) & 0x3F)

    def set_type_n_subtype(self, value):
        "Set 802.11 frame 'Type and Subtype' field"
        # clear the bits
        mask = (~0xFC)&0xFF 
        masked = self.header.get_byte(0) & mask 
        # set the bits
        nb = masked | ((value << 2) & 0xFC)
        self.header.set_byte(0, nb)

    def get_version(self):
        "Return 802.11 frame control 'Protocol version' field"
        b = self.header.get_byte(0)
        return (b & 0x03)

    def set_version(self, value):
        "Set the 802.11 frame control 'Protocol version' field"
        # clear the bits
        mask = (~0x03)&0xFF 
        masked = self.header.get_byte(0) & mask 
        # set the bits
        nb = masked | (value & 0x03)
        self.header.set_byte(0, nb)
        
    def compute_checksum(self,bytes):
        crcle=crc32(bytes)&0xffffffffL
        # ggrr this crc32 is in little endian, convert it to big endian 
        crc=struct.pack('<L', crcle)
         # Convert to long
        (crc_long,) = struct.unpack('!L', crc)
        return crc_long

    def is_QoS_frame(self):
        "Return 'True' if is an QoS data frame type"
        
        b = self.header.get_byte(0)
        return (b & 0x80) and True        

    def is_no_framebody_frame(self):
        "Return 'True' if it frame contain no Frame Body"
        
        b = self.header.get_byte(0)
        return (b & 0x40) and True

    def is_cf_poll_frame(self):
        "Return 'True' if it frame is a CF_POLL frame"
        
        b = self.header.get_byte(0)
        return (b & 0x20) and True

    def is_cf_ack_frame(self):
        "Return 'True' if it frame is a CF_ACK frame"
        
        b = self.header.get_byte(0)
        return (b & 0x10) and True
    
    def get_fcs(self):
        "Return 802.11 'FCS' field"
            
        b = self.tail.get_long(-4, ">")
        return b 

    def set_fcs(self, value = None):
        "Set the 802.11 CTS control frame 'FCS' field. If value is None, is auto_checksum"

        # calculate the FCS
        if value is None:
            payload = self.get_body_as_string()
            crc32=self.compute_checksum(payload)            
            value=crc32

        # set the bits
        nb = value & 0xFFFFFFFF
        self.tail.set_long(-4, nb)

class Dot11ControlFrameCTS(AbstractDot11):
    "802.11 Clear-To-Send Control Frame"
    __HEADER_SIZE = 8
    __TAIL_SIZE = 0
    
    def __init__(self, aBuffer = None):
        AbstractDot11.__init__(self, self.__HEADER_SIZE, self.__TAIL_SIZE)
        if(aBuffer):
            self.load_packet(aBuffer)
            
    def get_duration(self):
        "Return 802.11 CTS control frame 'Duration' field"
        b = self.header.get_word(0, "<")
        return b 

    def set_duration(self, value):
        "Set the 802.11 CTS control frame 'Duration' field" 
        # set the bits
        nb = value & 0xFFFF
        self.header.set_word(0, nb, "<")
        
    def get_ra(self):
        "Return 802.11 CTS control frame 48 bit 'Receiver Address' field as a 6 bytes array"
        return self.header.get_bytes()[2:8]

    def set_ra(self, value):
        "Set 802.11 CTS control frame 48 bit 'Receiver Address' field as a 6 bytes array"
        for i in range(0, 6):
            self.header.set_byte(2+i, value[i])

class Dot11ControlFrameACK(AbstractDot11):
    "802.11 Acknowledgement Control Frame"
    __HEADER_SIZE = 8
    __TAIL_SIZE = 0
    
    def __init__(self, aBuffer = None):
        AbstractDot11.__init__(self, self.__HEADER_SIZE, self.__TAIL_SIZE)
        if(aBuffer):
            self.load_packet(aBuffer)
            
    def get_duration(self):
        "Return 802.11 ACK control frame 'Duration' field"
        b = self.header.get_word(0, "<")
        return b 

    def set_duration(self, value):
        "Set the 802.11 ACK control frame 'Duration' field" 
        # set the bits
        nb = value & 0xFFFF
        self.header.set_word(0, nb, "<")
        
    def get_ra(self):
        "Return 802.11 ACK control frame 48 bit 'Receiver Address' field as a 6 bytes array"
        return self.header.get_bytes()[2:8]

    def set_ra(self, value):
        "Set 802.11 ACK control frame 48 bit 'Receiver Address' field as a 6 bytes array"
        for i in range(0, 6):
            self.header.set_byte(2+i, value[i])

class Dot11ControlFrameRTS(AbstractDot11):
    "802.11 Request-To-Send Control Frame"
    
    __HEADER_SIZE = 14
    __TAIL_SIZE = 0
    
    def __init__(self, aBuffer = None):
        AbstractDot11.__init__(self, self.__HEADER_SIZE, self.__TAIL_SIZE)
        if(aBuffer):
            self.load_packet(aBuffer)
    
    def get_duration(self):
        "Return 802.11 RTS control frame 'Duration' field"
        b = self.header.get_word(0, "<")
        return b 

    def set_duration(self, value):
        "Set the 802.11 RTS control frame 'Duration' field" 
        # set the bits
        nb = value & 0xFFFF
        self.header.set_word(0, nb, "<")
        
    def get_ra(self):
        "Return 802.11 RTS control frame 48 bit 'Receiver Address' field as a 6 bytes array"
        return self.header.get_bytes()[2:8]

    def set_ra(self, value):
        "Set 802.11 RTS control frame 48 bit 'Receiver Address' field as a 6 bytes array"
        for i in range(0, 6):
            self.header.set_byte(2+i, value[i])

    def get_ta(self):
        "Return 802.11 RTS control frame 48 bit 'Transmitter Address' field as a 6 bytes array"
        return self.header.get_bytes()[8:14]

    def set_ta(self, value):
        "Set 802.11 RTS control frame 48 bit 'Transmitter Address' field as a 6 bytes array"
        for i in range(0, 6):
            self.header.set_byte(8+i, value[i])            

class Dot11ControlFramePSPoll(AbstractDot11):
    "802.11 Power-Save Poll Control Frame"
    
    __HEADER_SIZE = 14
    __TAIL_SIZE = 0
    
    def __init__(self, aBuffer = None):
        AbstractDot11.__init__(self, self.__HEADER_SIZE, self.__TAIL_SIZE)
        if(aBuffer):
            self.load_packet(aBuffer)

    def get_aid(self):
        "Return 802.11 PSPoll control frame 'AID' field"
        # the spec says "The AID value always has its two MSBs each set to 1."
        # TODO: Should we do check/modify it? Wireshark shows the only MSB to 0
        b = self.header.get_word(0, "<")
        return b 

    def set_aid(self, value):
        "Set the 802.11 PSPoll control frame 'AID' field" 
        # set the bits
        nb = value & 0xFFFF
        # the spec says "The AID value always has its two MSBs each set to 1."
        # TODO: Should we do check/modify it? Wireshark shows the only MSB to 0
        self.header.set_word(0, nb, "<")
        
    def get_bssid(self):
        "Return 802.11 PSPoll control frame 48 bit 'BSS ID' field as a 6 bytes array"
        return self.header.get_bytes()[2:8]

    def set_bssid(self, value):
        "Set 802.11 PSPoll control frame 48 bit 'BSS ID' field as a 6 bytes array"
        for i in range(0, 6):
            self.header.set_byte(2+i, value[i])

    def get_ta(self):
        "Return 802.11 PSPoll control frame 48 bit 'Transmitter Address' field as a 6 bytes array"
        return self.header.get_bytes()[8:14]

    def set_ta(self, value):
        "Set 802.11 PSPoll control frame 48 bit 'Transmitter Address' field as a 6 bytes array"
        for i in range(0, 6):
            self.header.set_byte(8+i, value[i])            

class Dot11ControlFrameCFEnd(AbstractDot11):
    "802.11 'Contention Free End' Control Frame"
    
    __HEADER_SIZE = 14
    __TAIL_SIZE = 0
    
    def __init__(self, aBuffer = None):
        AbstractDot11.__init__(self, self.__HEADER_SIZE, self.__TAIL_SIZE)
        if(aBuffer):
            self.load_packet(aBuffer)

    def get_duration(self):
        "Return 802.11 CF-End control frame 'Duration' field"
        b = self.header.get_word(0, "<")
        return b 

    def set_duration(self, value):
        "Set the 802.11 CF-End control frame 'Duration' field" 
        # set the bits
        nb = value & 0xFFFF
        self.header.set_word(0, nb, "<")
        
    def get_ra(self):
        "Return 802.11 CF-End control frame 48 bit 'Receiver Address' field as a 6 bytes array"
        return self.header.get_bytes()[2:8]

    def set_ra(self, value):
        "Set 802.11 CF-End control frame 48 bit 'Receiver Address' field as a 6 bytes array"
        for i in range(0, 6):
            self.header.set_byte(2+i, value[i])

    def get_bssid(self):
        "Return 802.11 CF-End control frame 48 bit 'BSS ID' field as a 6 bytes array"
        return self.header.get_bytes()[8:14]

    def set_bssid(self, value):
        "Set 802.11 CF-End control frame 48 bit 'BSS ID' field as a 6 bytes array"
        for i in range(0, 6):
            self.header.set_byte(8+i, value[i])            

class Dot11ControlFrameCFEndCFACK(AbstractDot11):
    '802.11 \'CF-End + CF-ACK\' Control Frame'
    
    __HEADER_SIZE = 14
    __TAIL_SIZE = 0
    
    def __init__(self, aBuffer = None):
        AbstractDot11.__init__(self, self.__HEADER_SIZE, self.__TAIL_SIZE)
        if(aBuffer):
            self.load_packet(aBuffer)

    def get_duration(self):
        'Return 802.11 \'CF-End+CF-ACK\' control frame \'Duration\' field'
        b = self.header.get_word(0, "<")
        return b 

    def set_duration(self, value):
        'Set the 802.11 \'CF-End+CF-ACK\' control frame \'Duration\' field' 
        # set the bits
        nb = value & 0xFFFF
        self.header.set_word(0, nb, "<")
        
    def get_ra(self):
        'Return 802.11 \'CF-End+CF-ACK\' control frame 48 bit \'Receiver Address\' field as a 6 bytes array'
        return self.header.get_bytes()[2:8]

    def set_ra(self, value):
        'Set 802.11 \'CF-End+CF-ACK\' control frame 48 bit \'Receiver Address\' field as a 6 bytes array'
        for i in range(0, 6):
            self.header.set_byte(2+i, value[i])

    def get_bssid(self):
        'Return 802.11 \'CF-End+CF-ACK\' control frame 48 bit \'BSS ID\' field as a 6 bytes array'
        return self.header.get_bytes()[8:16]

    def set_bssid(self, value):
        'Set 802.11 \'CF-End+CF-ACK\' control frame 48 bit \'BSS ID\' field as a 6 bytes array'
        for i in range(0, 6):
            self.header.set_byte(8+i, value[i])            

class Dot11DataFrame(AbstractDot11):
    '802.11 Data Frame'
    
    __HEADER_SIZE = 22
    __TAIL_SIZE = 0

    def __init__(self, aBuffer = None):
        AbstractDot11.__init__(self, self.__HEADER_SIZE, self.__TAIL_SIZE)
        if(aBuffer):
            self.load_packet(aBuffer)
        
    def get_duration(self):
        'Return 802.11 \'Data\' data frame \'Duration\' field'
        b = self.header.get_word(0, "<")
        return b 

    def set_duration(self, value):
        'Set the 802.11 \'Data\' data frame \'Duration\' field' 
        # set the bits
        nb = value & 0xFFFF
        self.header.set_word(0, nb, "<")
        
    def get_address1(self):
        'Return 802.11 \'Data\' data frame 48 bit \'Address1\' field as a 6 bytes array'
        return self.header.get_bytes()[2:8]

    def set_address1(self, value):
        'Set 802.11 \'Data\' data frame 48 bit \'Address1\' field as a 6 bytes array'
        for i in range(0, 6):
            self.header.set_byte(2+i, value[i])

    def get_address2(self):
        'Return 802.11 \'Data\' data frame 48 bit \'Address2\' field as a 6 bytes array'
        return self.header.get_bytes()[8:14]

    def set_address2(self, value):
        'Set 802.11 \'Data\' data frame 48 bit \'Address2\' field as a 6 bytes array'
        for i in range(0, 6):
            self.header.set_byte(8+i, value[i])
            
    def get_address3(self):
        'Return 802.11 \'Data\' data frame 48 bit \'Address3\' field as a 6 bytes array'
        return self.header.get_bytes()[14: 20]

    def set_address3(self, value):
        'Set 802.11 \'Data\' data frame 48 bit \'Address3\' field as a 6 bytes array'
        for i in range(0, 6):
            self.header.set_byte(14+i, value[i])

    def get_sequence_control(self):
        'Return 802.11 \'Data\' data frame \'Sequence Control\' field'
        b = self.header.get_word(20, "<")
        return b 

    def set_sequence_control(self, value):
        'Set the 802.11 \'Data\' data frame \'Sequence Control\' field' 
        # set the bits
        nb = value & 0xFFFF
        self.header.set_word(20, nb, "<")

    def get_fragment_number(self):
        'Return 802.11 \'Data\' data frame \'Fragment Number\' subfield'

        b = self.header.get_word(20, "<")
        return (b&0x000F) 

    def set_fragment_number(self, value):
        'Set the 802.11 \'Data\' data frame \'Fragment Number\' subfield' 
        # clear the bits
        mask = (~0x000F) & 0xFFFF
        masked = self.header.get_word(20, "<") & mask
        # set the bits 
        nb = masked | (value & 0x000F)
        self.header.set_word(20, nb, "<")
        
    def get_secuence_number(self):
        'Return 802.11 \'Data\' data frame \'Secuence Number\' subfield'
        
        b = self.header.get_word(20, "<")
        return ((b>>4) & 0xFFF) 
    
    def set_secuence_number(self, value):
        'Set the 802.11 \'Data\' data frame \'Secuence Number\' subfield' 
        # clear the bits
        mask = (~0xFFF0) & 0xFFFF
        masked = self.header.get_word(20, "<") & mask
        # set the bits 
        nb = masked | ((value & 0x0FFF ) << 4 ) 
        self.header.set_word(20, nb, "<")

    def get_frame_body(self):
        'Return 802.11 \'Data\' data frame \'Frame Body\' field'
        
        return self.get_body_as_string()

    def set_frame_body(self, data):
        'Set 802.11 \'Data\' data frame \'Frame Body\' field'
        
        self.load_body(data)

class Dot11DataQoSFrame(Dot11DataFrame):
    '802.11 Data QoS Frame'
    __HEADER_SIZE = 24
    __TAIL_SIZE = 0
    
    def __init__(self, aBuffer = None):
        AbstractDot11.__init__(self, self.__HEADER_SIZE, self.__TAIL_SIZE)
        if(aBuffer):
            self.load_packet(aBuffer)

    def get_QoS(self):
        'Return 802.11 \'Data\' data frame \'QoS\' field'
        b = self.header.get_word(22, "<")
        return b 

    def set_QoS(self, value):
        'Set the 802.11 \'Data\' data frame \'QoS\' field' 
        # set the bits
        nb = value & 0xFFFF
        self.header.set_word(22, nb, "<")

class Dot11DataAddr4Frame(Dot11DataFrame):
    '802.11 Data With ToDS From DS Flags (With Addr 4) Frame'
    __HEADER_SIZE = 28
    __TAIL_SIZE = 0

    def __init__(self, aBuffer = None):
        AbstractDot11.__init__(self, self.__HEADER_SIZE, self.__TAIL_SIZE)
        if(aBuffer):
            self.load_packet(aBuffer)
    
    def get_address4(self):
        'Return 802.11 \'Data\' data frame 48 bit \'Address4\' field as a 6 bytes array'
        return self.header.get_bytes()[22:28]
        
    def set_address4(self, value):
        'Set 802.11 \'Data\' data frame 48 bit \'Address4\' field as a 6 bytes array'
        for i in range(0, 6):
            self.header.set_byte(22+i, value[i])

class Dot11DataAddr4QoSFrame(Dot11DataAddr4Frame):
    '802.11 Data With ToDS From DS Flags (With Addr 4) and QoS Frame'
    __HEADER_SIZE = 30
    __TAIL_SIZE = 0

    def __init__(self, aBuffer = None):
        AbstractDot11.__init__(self, self.__HEADER_SIZE, self.__TAIL_SIZE)
        if(aBuffer):
            self.load_packet(aBuffer)
    
    def get_QoS(self):
        'Return 802.11 \'Data\' data frame \'QoS\' field'
        b = self.header.get_word(28, "<")
        return b 

    def set_QoS(self, value):
        'Set the 802.11 \'Data\' data frame \'QoS\' field' 
        # set the bits
        nb = value & 0xFFFF
        self.header.set_word(28, nb, "<")

class SAPTypes():
    NULL            = 0x00
    LLC_SLMGMT      = 0x02
    SNA_PATHCTRL    = 0x04
    IP              = 0x06
    SNA1            = 0x08
    SNA2            = 0x0C
    PROWAY_NM_INIT  = 0x0E
    NETWARE1        = 0x10
    OSINL1          = 0x14
    TI              = 0x18
    OSINL2          = 0x20
    OSINL3          = 0x34
    SNA3            = 0x40
    BPDU            = 0x42
    RS511           = 0x4E
    OSINL4          = 0x54
    X25             = 0x7E
    XNS             = 0x80
    BACNET          = 0x82
    NESTAR          = 0x86
    PROWAY_ASLM     = 0x8E
    ARP             = 0x98
    SNAP            = 0xAA
    HPJD            = 0xB4
    VINES1          = 0xBA
    VINES2          = 0xBC
    NETWARE2        = 0xE0
    NETBIOS         = 0xF0
    IBMNM           = 0xF4
    HPEXT           = 0xF8
    UB              = 0xFA
    RPL             = 0xFC
    OSINL5          = 0xFE
    GLOBAL          = 0xFF

class LLC(AbstractDot11):
    '802.2 Logical Link Control (LLC) Frame'
    __HEADER_SIZE = 3
    __TAIL_SIZE = 0
    
    DLC_UNNUMBERED_FRAMES = 0x03

    def __init__(self, aBuffer = None):
        AbstractDot11.__init__(self, self.__HEADER_SIZE, self.__TAIL_SIZE)
        if(aBuffer):
            self.load_packet(aBuffer)

    def get_DSAP(self):
        "Get the Destination Service Access Point (SAP) from LLC frame"
        return self.header.get_byte(0)

    def set_DSAP(self, value):
        "Set the Destination Service Access Point (SAP) of LLC frame"
        self.header.set_byte(0, value)

    def get_SSAP(self):
        "Get the Source Service Access Point (SAP) from LLC frame"
        return self.header.get_byte(1)

    def set_SSAP(self, value):
        "Set the Source Service Access Point (SAP) of LLC frame"
        self.header.set_byte(1, value)
    
    def get_control(self):
        "Get the Control field from LLC frame"
        return self.header.get_byte(2)

    def set_control(self, value):
        "Set the Control field of LLC frame"
        self.header.set_byte(2, value)

class SNAP(AbstractDot11):
    '802.2 SubNetwork Access Protocol (SNAP) Frame'
    __HEADER_SIZE = 5
    __TAIL_SIZE = 0

    def __init__(self, aBuffer = None):
        AbstractDot11.__init__(self, self.__HEADER_SIZE, self.__TAIL_SIZE)
        if(aBuffer):
            self.load_packet(aBuffer)

    def get_OUI(self):
        "Get the three-octet Organizationally Unique Identifier (OUI) SNAP frame"
        return self.header.get_bytes()[0:3]

    def set_OUI(self, value):
        "Set the three-octet Organizationally Unique Identifier (OUI) SNAP frame"
        
        for i in range(0, 3):
            self.header.set_byte(0+i, value[i])

    def get_protoID(self):
        "Get the two-octet Protocol Identifier (PID) SNAP field"
        return self.header.get_word(3, "<")
    
    def set_protoID(self, value):
        "Set the two-octet Protocol Identifier (PID) SNAP field"
        self.header.set_word(3, value, "<")

class Dot11WEP(AbstractDot11):
    '802.11 WEP'

    __HEADER_SIZE = 4
    __TAIL_SIZE = 0

    def __init__(self, aBuffer = None):
        AbstractDot11.__init__(self, self.__HEADER_SIZE, self.__TAIL_SIZE)
        if(aBuffer):
            self.load_packet(aBuffer)
        
    def is_WEP(self):
        'Return True if it\'s a WEP'
        # We already know that it's private.
        # Now we must differentiate between WEP and WPA/WPA2
        # WPA/WPA2 have the ExtIV (Bit 5) enaled and WEP disabled
        b = self.header.get_byte(3)
        return not (b & 0x20)
            
    def get_iv(self):
        'Return the \'WEP IV\' field'
        b=self.header.get_bytes()[0:3].tostring()
        #unpack requires a string argument of length 4 and b is 3 bytes long
        (iv,)=struct.unpack('!L', '\x00'+b)
        return iv

    def set_iv(self, value):
        'Set the \'WEP IV\' field. If value is None, is auto_checksum"'
        # clear the bits
        mask = ((~0xFFFFFF00) & 0xFF)
        masked = self.header.get_long(0, ">") & mask
        # set the bits 
        nb = masked | ((value & 0x00FFFFFF) << 8)
        self.header.set_long(0, nb)

    def get_keyid(self):
        'Return the \'WEP KEY ID\' field'
        b = self.header.get_byte(3)
        return ((b>>6) & 0x03)

    def set_keyid(self, value):
        'Set the \'WEP KEY ID\' field'
        # clear the bits
        mask = (~0xC0) & 0xFF
        masked = self.header.get_byte(3) & mask
        # set the bits
        nb = masked | ((value & 0x03) << 6)
        self.header.set_byte(3, nb)

    def get_decrypted_data(self):
        'Return \'WEP Data\' field decrypted'
        # TODO: Replace it with the decoded string
        # Ver 8.2.1.4.5 WEP MPDU decapsulation
        return self.body_string

class Dot11WEPData(AbstractDot11):
    '802.11 WEP Data Part'

    __HEADER_SIZE = 0
    __TAIL_SIZE = 4

    def __init__(self, aBuffer = None):
        AbstractDot11.__init__(self, self.__HEADER_SIZE, self.__TAIL_SIZE)
        if(aBuffer):
            self.load_packet(aBuffer)
        
    def get_icv(self):
        "Return 'WEP ICV' field"
            
        b = self.tail.get_long(-4, ">")
        return b 

    def set_icv(self, value = None):
        "Set 'WEP ICV' field"

        # calculate the FCS
        if value is None:
            value=self.compute_checksum(self.body_string)

        # set the bits
        nb = value & 0xFFFFFFFF
        self.tail.set_long(-4, nb)

class Dot11WPA(AbstractDot11):
    '802.11 WPA'

    __HEADER_SIZE = 8
    __TAIL_SIZE = 0

    def __init__(self, aBuffer = None):
        AbstractDot11.__init__(self, self.__HEADER_SIZE, self.__TAIL_SIZE)
        if(aBuffer):
            self.load_packet(aBuffer)
        
    def is_WPA(self):
        'Return True if it\'s a WPA'
        # Now we must differentiate between WPA and WPA2
        # In WPA WEPSeed is set to (TSC1 | 0x20) & 0x7f.
        b = self.get_WEPSeed() == ((self.get_TSC1() | 0x20 ) & 0x7f)
        return (b and self.get_extIV())
        
    def get_keyid(self):
        'Return the \'WPA KEY ID\' field'
        b = self.header.get_byte(3)
        return ((b>>6) & 0x03)

    def set_keyid(self, value):
        'Set the \'WPA KEY ID\' field'
        # clear the bits
        mask = (~0xC0) & 0xFF
        masked = self.header.get_byte(3) & mask
        # set the bits
        nb = masked | ((value & 0x03) << 6)
        self.header.set_byte(3, nb)

    def get_decrypted_data(self):
        'Return \'WPA Data\' field decrypted'
        # TODO: Replace it with the decoded string
        return self.body_string
    
    def get_TSC1(self):
        'Return the \'WPA TSC1\' field'
        b = self.header.get_byte(0)
        return (b & 0xFF)
    
    def set_TSC1(self, value):
        'Set the \'WPA TSC1\' field'
        # set the bits
        nb = (value & 0xFF)
        self.header.set_byte(0, nb)
        
    def get_WEPSeed(self):
        'Return the \'WPA WEPSeed\' field'
        b = self.header.get_byte(1)
        return (b & 0xFF)
    
    def set_WEPSeed(self, value):
        'Set the \'WPA WEPSeed\' field'
        # set the bits
        nb = (value & 0xFF)
        self.header.set_byte(1, nb)

    def get_TSC0(self):
        'Return the \'WPA TSC0\' field'
        b = self.header.get_byte(2)
        return (b & 0xFF)
    
    def set_TSC0(self, value):
        'Set the \'WPA TSC0\' field'
        # set the bits
        nb = (value & 0xFF)
        self.header.set_byte(2, nb)

    def get_extIV(self):
        'Return the \'WPA extID\' field'
        b = self.header.get_byte(3)
        return ((b>>5) & 0x1)

    def set_extIV(self, value):
        'Set the \'WPA extID\' field'
        # clear the bits
        mask = (~0x20) & 0xFF
        masked = self.header.get_byte(3) & mask
        # set the bits
        nb = masked | ((value & 0x01) << 5)
        self.header.set_byte(3, nb)
        
    def get_TSC2(self):
        'Return the \'WPA TSC2\' field'
        b = self.header.get_byte(4)
        return (b & 0xFF)
    
    def set_TSC2(self, value):
        'Set the \'WPA TSC2\' field'
        # set the bits
        nb = (value & 0xFF)
        self.header.set_byte(4, nb)

    def get_TSC3(self):
        'Return the \'WPA TSC3\' field'
        b = self.header.get_byte(5)
        return (b & 0xFF)
    
    def set_TSC3(self, value):
        'Set the \'WPA TSC3\' field'
        # set the bits
        nb = (value & 0xFF)
        self.header.set_byte(5, nb)

    def get_TSC4(self):
        'Return the \'WPA TSC4\' field'
        b = self.header.get_byte(6)
        return (b & 0xFF)
    
    def set_TSC4(self, value):
        'Set the \'WPA TSC4\' field'
        # set the bits
        nb = (value & 0xFF)
        self.header.set_byte(6, nb)

    def get_TSC5(self):
        'Return the \'WPA TSC5\' field'
        b = self.header.get_byte(7)
        return (b & 0xFF)
    
    def set_TSC5(self, value):
        'Set the \'WPA TSC5\' field'
        # set the bits
        nb = (value & 0xFF)
        self.header.set_byte(7, nb)

class Dot11WPAData(AbstractDot11):
    '802.11 WPA Data Part'

    __HEADER_SIZE = 0
    __TAIL_SIZE = 12

    def __init__(self, aBuffer = None):
        AbstractDot11.__init__(self, self.__HEADER_SIZE, self.__TAIL_SIZE)
        if(aBuffer):
            self.load_packet(aBuffer)
        
    def get_icv(self):
        "Return 'WPA ICV' field"
            
        b = self.tail.get_long(-4, ">")
        return b 

    def set_icv(self, value = None):
        "Set 'WPA ICV' field"

        # calculate the FCS
        if value is None:
            value=self.compute_checksum(self.body_string)

        # set the bits
        nb = value & 0xFFFFFFFF
        self.tail.set_long(-4, nb)
    
    def get_MIC(self):
        'Return the \'WPA2Data MIC\' field'
        return self.get_tail_as_string()[:8]

    def set_MIC(self, value):
        'Set the \'WPA2Data MIC\' field'
        #Padding to 8 bytes with 0x00's 
        value.ljust(8,'\x00')
        #Stripping to 8 bytes
        value=value[:8]
        icv=self.tail.get_buffer_as_string()[-4:] 
        self.tail.set_bytes_from_string(value+icv)
        
class Dot11WPA2(AbstractDot11):
    '802.11 WPA2'

    __HEADER_SIZE = 8
    __TAIL_SIZE = 0

    def __init__(self, aBuffer = None):
        AbstractDot11.__init__(self, self.__HEADER_SIZE, self.__TAIL_SIZE)
        if(aBuffer):
            self.load_packet(aBuffer)
        
    def is_WPA2(self):
        'Return True if it\'s a WPA2'
        # Now we must differentiate between WPA and WPA2
        # In WPA WEPSeed is set to (TSC1 | 0x20) & 0x7f.
        # In WPA2 WEPSeed=PN1 and TSC1=PN0
        b = self.get_PN1() == ((self.get_PN0() | 0x20 ) & 0x7f)
        return (not b and self.get_extIV())

    def get_extIV(self):
        'Return the \'WPA2 extID\' field'
        b = self.header.get_byte(3)
        return ((b>>5) & 0x1)
    
    def set_extIV(self, value):
        'Set the \'WPA2 extID\' field'
        # clear the bits
        mask = (~0x20) & 0xFF
        masked = self.header.get_byte(3) & mask
        # set the bits
        nb = masked | ((value & 0x01) << 5)
        self.header.set_byte(3, nb)
        
    def get_keyid(self):
        'Return the \'WPA2 KEY ID\' field'
        b = self.header.get_byte(3)
        return ((b>>6) & 0x03)

    def set_keyid(self, value):
        'Set the \'WPA2 KEY ID\' field'
        # clear the bits
        mask = (~0xC0) & 0xFF
        masked = self.header.get_byte(3) & mask
        # set the bits
        nb = masked | ((value & 0x03) << 6)
        self.header.set_byte(3, nb)

    def get_decrypted_data(self):
        'Return \'WPA2 Data\' field decrypted'
        # TODO: Replace it with the decoded string
        return self.body_string
    
    def get_PN0(self):
        'Return the \'WPA2 PN0\' field'
        b = self.header.get_byte(0)
        return (b & 0xFF)
    
    def set_PN0(self, value):
        'Set the \'WPA2 PN0\' field'
        # set the bits
        nb = (value & 0xFF)
        self.header.set_byte(0, nb)
        
    def get_PN1(self):
        'Return the \'WPA2 PN1\' field'
        b = self.header.get_byte(1)
        return (b & 0xFF)
    
    def set_PN1(self, value):
        'Set the \'WPA2 PN1\' field'
        # set the bits
        nb = (value & 0xFF)
        self.header.set_byte(1, nb)

    def get_PN2(self):
        'Return the \'WPA2 PN2\' field'
        b = self.header.get_byte(4)
        return (b & 0xFF)
    
    def set_PN2(self, value):
        'Set the \'WPA2 PN2\' field'
        # set the bits
        nb = (value & 0xFF)
        self.header.set_byte(4, nb)

    def get_PN3(self):
        'Return the \'WPA2 PN3\' field'
        b = self.header.get_byte(5)
        return (b & 0xFF)
    
    def set_PN3(self, value):
        'Set the \'WPA2 PN3\' field'
        # set the bits
        nb = (value & 0xFF)
        self.header.set_byte(5, nb)

    def get_PN4(self):
        'Return the \'WPA2 PN4\' field'
        b = self.header.get_byte(6)
        return (b & 0xFF)
    
    def set_PN4(self, value):
        'Set the \'WPA2 PN4\' field'
        # set the bits
        nb = (value & 0xFF)
        self.header.set_byte(6, nb)

    def get_PN5(self):
        'Return the \'WPA2 PN5\' field'
        b = self.header.get_byte(7)
        return (b & 0xFF)
    
    def set_PN5(self, value):
        'Set the \'WPA2 PN5\' field'
        # set the bits
        nb = (value & 0xFF)
        self.header.set_byte(7, nb)

class Dot11WPA2Data(AbstractDot11):
    '802.11 WPA2 Data Part'

    __HEADER_SIZE = 0
    __TAIL_SIZE = 8

    def __init__(self, aBuffer = None):
        AbstractDot11.__init__(self, self.__HEADER_SIZE, self.__TAIL_SIZE)
        if(aBuffer):
            self.load_packet(aBuffer)
            
    def get_MIC(self):
        'Return the \'WPA2Data MIC\' field'
        return self.get_tail_as_string()

    def set_MIC(self, value):
        'Set the \'WPA2Data MIC\' field'
        #Padding to 8 bytes with 0x00's 
        value.ljust(8,'\x00')
        #Stripping to 8 bytes
        value=value[:8]
        self.tail.set_bytes_from_string(value)

class RadioTap(AbstractDot11):
    __HEADER_BASE_SIZE = 8 # minimal header size
    __HEADER_SIZE = __HEADER_BASE_SIZE 
    __TAIL_SIZE = 0

    RADIOTAP_TSFT = 0
    RADIOTAP_FLAGS = 1
    RADIOTAP_RATE = 2
    RADIOTAP_CHANNEL = 3
    RADIOTAP_FHSS = 4
    RADIOTAP_DBM_ANTSIGNAL = 5
    RADIOTAP_DBM_ANTNOISE = 6
    RADIOTAP_LOCK_QUALITY = 7
    RADIOTAP_TX_ATTENUATION = 8
    RADIOTAP_DB_TX_ATTENUATION = 9
    RADIOTAP_DBM_TX_POWER = 10
    RADIOTAP_ANTENNA = 11
    RADIOTAP_DB_ANTSIGNAL = 12
    RADIOTAP_DB_ANTNOISE = 13
    #RADIOTAP_RX_FLAGS = 14 # official assignment
    RADIOTAP_FCS_IN_HEADER = 14 # clashes with RX_FLAGS
    RADIOTAP_TX_FLAGS = 15 # clashes with HARDWARE_QUEUE
    #RADIOTAP_HARDWARE_QUEUE = 15 # clashes with TX_FLAGS
    RADIOTAP_RTS_RETRIES = 16 # clashes with RSSI
    #RADIOTAP_RSSI = 16 # clashes with RTS_RETRIES 
    RADIOTAP_DATA_RETRIES = 17
    RADIOTAP_XCHANNEL = 18
    RADIOTAP_EXT = 31

    __fields_bytes_len={
        RADIOTAP_TSFT: 8,
        RADIOTAP_FLAGS: 1,
        RADIOTAP_RATE: 1,
        RADIOTAP_CHANNEL: 2+2,
        RADIOTAP_FHSS: 1+1,
        RADIOTAP_DBM_ANTSIGNAL: 1,
        RADIOTAP_DBM_ANTNOISE: 1,
        RADIOTAP_LOCK_QUALITY: 2,
        RADIOTAP_TX_ATTENUATION: 2,
        RADIOTAP_DB_TX_ATTENUATION: 2,
        RADIOTAP_DBM_TX_POWER: 1,
        RADIOTAP_ANTENNA: 1,
        RADIOTAP_DB_ANTSIGNAL: 1,
        RADIOTAP_DB_ANTNOISE: 1,
        #RADIOTAP_RX_FLAGS: 2,
        RADIOTAP_FCS_IN_HEADER: 4,
        RADIOTAP_TX_FLAGS: 2,
        #RADIOTAP_HARDWARE_QUEUE: 1,        
        RADIOTAP_RTS_RETRIES: 1,
        #RADIOTAP_RSSI: 2,
        RADIOTAP_DATA_RETRIES: 1,
        RADIOTAP_XCHANNEL: 4+2+1+1,
    }
        
    def __init__(self, aBuffer = None):
        if aBuffer:
            length = unpack('<H', aBuffer[2:4])[0]
            self.__HEADER_SIZE=length
                    
            AbstractDot11.__init__(self, self.__HEADER_SIZE, self.__TAIL_SIZE)
            self.load_packet(aBuffer)
        else:
            AbstractDot11.__init__(self, self.__HEADER_SIZE, self.__TAIL_SIZE)
            self.set_version(0)
            self.set_present(0x00000000)
            
    def get_version(self):
        'Return the \'version\' field'
        b = self.header.get_byte(0)
        return b
    
    def set_version(self, value):
        'Set the \'version\' field'
        nb = (value & 0xFF)
        self.header.set_byte(0, nb)
        
        nb = (value & 0xFF)
        "Return RadioTap len field"
        
        return self.__HEADER_SIZE
        
    def get_present(self):
        "Return RadioTap present bitmap field"
        present = self.header.get_long(4, "<")
        # TODO: Implement extended 'present' bit logic here
        return present

    def __set_present(self, value):
        "Set RadioTap present field bit"
        # TODO: Implement extended 'present' bit logic here
        self.header.set_long(4, value)

    def get_present_bit(self, bit):
        'Get a \'present\' field bit'
        present=self.get_present()
        # TODO: Implement extended 'present' bit logic here
        return not not (2**bit & present)

    def __set_present_bit(self, bit):
        'Set a \'present\' field bit'
        npresent=2**bit | self.get_present()
        self.header.set_long(4, npresent,'<')
        
    def __get_field_position(self, field):
        
        if not self.__fields_bytes_len.has_key(field):
            return None
        
        field_position=self.__HEADER_BASE_SIZE
        for (f,length) in self.__fields_bytes_len.items():
            if f==field:
                return field_position
            
            if self.get_present_bit(f):
                field_position+=length
        
        return None
    
    def __set_field_from_string( self, field, field_bytes_length, value):
        is_present=self.get_present_bit(field)
        if is_present is False:
            self.__set_present_bit(field)
        
        byte_pos=self.__get_field_position(field)
        header=self.get_header_as_string()
        
        if is_present is True:
            header=header[:byte_pos]+value+header[byte_pos+field_bytes_length:]
        else:
            header=header[:byte_pos]+value+header[byte_pos:]
        self.header.set_bytes_from_string(header)

    def __get_field_as_string( self, field, field_bytes_length ):
        #Structure: u64 mactime 
        #Required Alignment: 8
        #Unit: microseconds
        is_present=self.get_present_bit(field)
        if is_present is False:
            return None
        
        byte_pos=self.__get_field_position(field)
        header=self.get_header_as_string()
        v=header[ byte_pos:byte_pos+field_bytes_length ]
        return v
         
        ov = self.header.get_long(4, "<") 
        # set the bits 
        nv |= (1<<bit) 
        self.header.set_long(4, nv, "<")
   
    def set_tsft( self, nvalue ):
        #Structure: u64 mactime 
        #Required Alignment: 8
        #Unit: microseconds
        field_bytes_len=8
        field_bits_len=field_bytes_len*8
        mask=2**field_bits_len-1
        nvalue=nvalue&mask

        nvalue = struct.pack('<Q', nvalue)
        self.__set_field_from_string(field=self.RADIOTAP_TSFT, field_bytes_length=field_bytes_len, value=nvalue)
        
    def get_tsft( self ):
        #Structure: u64 mactime 
        #Required Alignment: 8
        #Unit: microseconds
        s=self.__get_field_as_string(field=self.RADIOTAP_TSFT,field_bytes_length=8)
        if s is None:
            return s
        print "[%s]" % hexlify(s)
        n = struct.unpack('<Q', s)[0]
        return n
   
    def get_flags( self ):
        pass
   
    def get_rate( self ):
        pass
