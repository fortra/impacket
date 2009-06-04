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
from ImpactPacket import Header
from binascii import hexlify,crc32

class RadioTap(Header):
    def __init__(self, aBuffer = None):
        bytes = aBuffer[2:4]
        #self.__bytes = array.array('B', data)
        print "Bytes [%s] Len [%d]\n" % (bytes,len(bytes))
        # Little-Endian
        order = '<'
        print "Order: %s" % order
        (length,) = struct.unpack('<H', bytes)
        print "Len: %s" % str(length)

        Header.__init__(self, length)
        if(aBuffer):
            self.load_header(aBuffer)

    def get_header_size(self):
        "Return size of RadioTap header"
        return self.get_word(2, "<")

    def get_packet(self):
        return Header.get_packet(self)

    def __str__(self):
        tmp_str = 'RadioTap: Len: ' + str(self.get_header_size()) 
        #tmp_str = 'RadioTap: ' + self.as_eth_addr(self.get_ether_shost()) + ' -> '
        #tmp_str += self.as_eth_addr(self.get_ether_dhost())
        if self.child():
            tmp_str += '\n' + self.child().__str__()
        return tmp_str

class Dot11(Header):
    __SIZE = 2

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
        
    def __init__(self, aBuffer = None):
        Header.__init__(self, self.__SIZE)
        if(aBuffer):
            self.load_header(aBuffer)
            
    def get_header_size(self):
        "Return size of 802.11 frame control header"
        return self.__SIZE
        
    def get_packet(self):       
        return self.get_bytes().tostring()
     
    def get_order_field(self):
        "Return 802.11 frame 'Order' field"
        b = self.get_byte(1)
        return ((b >> 7) & 0x01)

    def set_order_field(self, value):
        "Set 802.11 frame 'Order' field"
        # clear the bits
        mask = (~0x80) & 0xFF
        masked = self.get_byte(1) & mask
        # set the bits
        nb = masked | ((value & 0x01) << 7)
        self.set_byte(1, nb)

    def get_protectedFrame_field(self):
        "Return 802.11 frame 'Protected' field"
        b = self.get_byte(1)
        return ((b >> 6) & 0x01)

    def set_protectedFrame_field(self, value):
        "Set 802.11 frame 'Protected Frame' field"
        # clear the bits
        mask = (~0x40) & 0xFF
        masked = self.get_byte(1) & mask
        # set the bits
        nb = masked | ((value & 0x01) << 6)
        self.set_byte(1, nb)

    def get_moreData_field(self):
        "Return 802.11 frame 'More Data' field"
        b = self.get_byte(1)
        return ((b >> 5) & 0x01)

    def set_moreData_field(self, value):
        "Set 802.11 frame 'More Data' field"
        # clear the bits
        mask = (~0x20) & 0xFF
        masked = self.get_byte(1) & mask
        # set the bits
        nb = masked | ((value & 0x01) << 5)
        self.set_byte(1, nb)
        
    def get_powerManagement_field(self):
        "Return 802.11 frame 'Power Management' field"
        b = self.get_byte(1)
        return ((b >> 4) & 0x01)

    def set_powerManagement_field(self, value):
        "Set 802.11 frame 'Power Management' field"
        # clear the bits
        mask = (~0x10) & 0xFF
        masked = self.get_byte(1) & mask
        # set the bits
        nb = masked | ((value & 0x01) << 4)
        self.set_byte(1, nb)
  
    def get_retry_field(self):
        "Return 802.11 frame 'Retry' field"
        b = self.get_byte(1)
        return ((b >> 3) & 0x01)

    def set_retry_field(self, value):
        "Set 802.11 frame 'Retry' field"
        # clear the bits
        mask = (~0x08) & 0xFF
        masked = self.get_byte(1) & mask
        # set the bits
        nb = masked | ((value & 0x01) << 3)
        self.set_byte(1, nb)   
        
    def get_moreFrag_field(self):
        "Return 802.11 frame 'More Fragments' field"
        b = self.get_byte(1)
        return ((b >> 2) & 0x01)

    def set_moreFrag_field(self, value):
        "Set 802.11 frame 'More Fragments' field"
        # clear the bits
        mask = (~0x04) & 0xFF
        masked = self.get_byte(1) & mask
        # set the bits
        nb = masked | ((value & 0x01) << 2)
        self.set_byte(1, nb)  
               
    def get_fromDS_field(self):
        "Return 802.11 frame 'from DS' field"
        b = self.get_byte(1)
        return ((b >> 1) & 0x01)

    def set_fromDS_field(self, value):
        "Set 802.11 frame 'from DS' field"
        # clear the bits
        mask = (~0x02) & 0xFF
        masked = self.get_byte(1) & mask
        # set the bits
        nb = masked | ((value & 0x01) << 1)
        self.set_byte(1, nb)
         
    def get_toDS_field(self):
        "Return 802.11 frame 'to DS' field"
        b = self.get_byte(1)
        return (b & 0x01)

    def set_toDS_field(self, value):
        "Set 802.11 frame 'to DS' field"
        # clear the bits
        mask = (~0x01) & 0xFF
        masked = self.get_byte(1) & mask
        # set the bits
        nb = masked | (value & 0x01) 
        self.set_byte(1, nb)    
        
    def get_subtype_field(self):
        "Return 802.11 frame 'subtype' field"
        b = self.get_byte(0)
        return ((b >> 4) & 0x0F)

    def set_subtype_field(self, value):
        "Set 802.11 frame 'subtype' field"
        # clear the bits
        mask = (~0xF0)&0xFF 
        masked = self.get_byte(0) & mask 
        # set the bits
        nb = masked | ((value << 4) & 0xF0)
        self.set_byte(0, nb)
        
    def get_type_field(self):
        "Return 802.11 frame 'type' field"
        b = self.get_byte(0)
        return ((b >> 2) & 0x03)

    def set_type_field(self, value):
        "Set 802.11 frame 'type' field"
        # clear the bits
        mask = (~0x0C)&0xFF 
        masked = self.get_byte(0) & mask 
        # set the bits
        nb = masked | ((value << 2) & 0x0C)
        self.set_byte(0, nb)

    def get_type_n_subtype_field(self):
        "Return 802.11 frame 'Type and Subtype' field"
        b = self.get_byte(0)
        return ((b >> 2) & 0x3F)

    def set_type_n_subtype_field(self, value):
        "Set 802.11 frame 'Type and Subtype' field"
        # clear the bits
        mask = (~0xFC)&0xFF 
        masked = self.get_byte(0) & mask 
        # set the bits
        nb = masked | ((value << 2) & 0xFC)
        self.set_byte(0, nb)

    def get_version_field(self):
        "Return 802.11 frame control 'Protocol version' field"
        b = self.get_byte(0)
        return (b & 0x03)

    def set_version_field(self, value):
        "Set the 802.11 frame control 'Protocol version' field"
        # clear the bits
        mask = (~0x03)&0xFF 
        masked = self.get_byte(0) & mask 
        # set the bits
        nb = masked | (value & 0x03)
        self.set_byte(0, nb)
        
    def compute_checksum(self,bytes):
        crcle=crc32(bytes)&0xffffffffL
        # ggrr this crc32 is in little endian, convert it to big endian 
        crc=struct.pack('<L', crcle)
         # Convert to long
        (crc_long,) = struct.unpack('!L', crc)
        return crc_long

class Dot11ControlFrameCTS(Dot11):
    "802.11 Clear-To-Send Control Frame"
    __SIZE = 14
    
    def __init__(self, aBuffer = None):
        Header.__init__(self, self.__SIZE)
        if aBuffer:
            self.load_header(aBuffer)
        else:
            self.set_type_n_subtype_field(self.DOT11_TYPE_CONTROL_SUBTYPE_CLEAR_TO_SEND)
            
    def get_header_size(self):
        "Return size of 802.11 CTS control frame"
        return self.__SIZE
    
    def get_packet(self):
        'Return the 802.11 CTS control frame'
        # set the checksum if the user hasn't modified it
        if self.auto_checksum:
            payload = self.get_bytes()[:self.__SIZE-4]
            crc32=self.compute_checksum(payload)            
            self.set_fcs_field(crc32)
        
        return self.get_bytes().tostring() 

    def get_duration_field(self):
        "Return 802.11 CTS control frame 'Duration' field"
        b = self.get_word(2, "<")
        return b 

    def set_duration_field(self, value):
        "Set the 802.11 CTS control frame 'Duration' field" 
        # set the bits
        nb = value & 0xFFFF
        self.set_word(2, nb, "<")
        
    def get_ra_field(self):
        "Return 802.11 CTS control frame 48 bit 'Receiver Address' field as a 6 bytes array"
        return self.get_bytes()[4:10]

    def set_ra_field(self, value):
        "Set 802.11 CTS control frame 48 bit 'Receiver Address' field as a 6 bytes array"
        for i in range(0, 6):
            self.set_byte(4+i, value[i])

    def get_fcs_field(self):
        "Return 802.11 CTS control frame 'FCS' field"
        b = self.get_long(10, ">")
        return b 

    def set_fcs_field(self, value):
        "Set the 802.11 CTS control frame 'FCS' field" 
        # set the bits
        nb = value & 0xFFFFFFFF
        self.set_long(10, nb)

class Dot11ControlFrameACK(Dot11):
    "802.11 Acknowledgement Control Frame"
    __SIZE = 14
    
    def __init__(self, aBuffer = None):
        Header.__init__(self, self.__SIZE)
        if aBuffer:
            self.load_header(aBuffer)
        else:
            self.set_type_n_subtype_field(self.DOT11_TYPE_CONTROL_SUBTYPE_ACKNOWLEDGMENT)
            
    def get_header_size(self):
        "Return size of 802.11 ACK control frame"
        return self.__SIZE
    
    def get_packet(self):
        'Return the 802.11 ACK control frame'
        # set the checksum if the user hasn't modified it
        if self.auto_checksum:
            payload = self.get_bytes()[:self.__SIZE-4]
            crc32=self.compute_checksum(payload)            
            self.set_fcs_field(crc32)
        
        return self.get_bytes().tostring() 

    def get_duration_field(self):
        "Return 802.11 ACK control frame 'Duration' field"
        b = self.get_word(2, "<")
        return b 

    def set_duration_field(self, value):
        "Set the 802.11 ACK control frame 'Duration' field" 
        # set the bits
        nb = value & 0xFFFF
        self.set_word(2, nb, "<")
        
    def get_ra_field(self):
        "Return 802.11 ACK control frame 48 bit 'Receiver Address' field as a 6 bytes array"
        return self.get_bytes()[4:10]

    def set_ra_field(self, value):
        "Set 802.11 ACK control frame 48 bit 'Receiver Address' field as a 6 bytes array"
        for i in range(0, 6):
            self.set_byte(4+i, value[i])

    def get_fcs_field(self):
        "Return 802.11 ACK control frame 'FCS' field"
        b = self.get_long(10, ">")
        return b 

    def set_fcs_field(self, value):
        "Set the 802.11 ACK control frame 'FCS' field" 
        # set the bits
        nb = value & 0xFFFFFFFF
        self.set_long(10, nb)

class Dot11ControlFrameRTS(Dot11):
    "802.11 Request-To-Send Control Frame"
    
    __SIZE = 20
    def __init__(self, aBuffer = None):
        Header.__init__(self, self.__SIZE)
        if aBuffer:
            self.load_header(aBuffer)
        else:
            self.set_type_n_subtype_field(self.DOT11_TYPE_CONTROL_SUBTYPE_REQUEST_TO_SEND)
    
    def get_header_size(self):
        "Return size of 802.11 RTS control frame header"
        return self.__SIZE        
    
    def get_packet(self):
        'Return the 802.11 RTS control frame'
        # set the checksum if the user hasn't modified it
        if self.auto_checksum:
            payload = self.get_bytes()[:self.__SIZE-4]
            crc32=self.compute_checksum(payload)            
            self.set_fcs_field(crc32)
        
        return self.get_bytes().tostring()
     
    def get_duration_field(self):
        "Return 802.11 RTS control frame 'Duration' field"
        b = self.get_word(2, "<")
        return b 

    def set_duration_field(self, value):
        "Set the 802.11 RTS control frame 'Duration' field" 
        # set the bits
        nb = value & 0xFFFF
        self.set_word(2, nb, "<")
        
    def get_ra_field(self):
        "Return 802.11 RTS control frame 48 bit 'Receiver Address' field as a 6 bytes array"
        return self.get_bytes()[4:10]

    def set_ra_field(self, value):
        "Set 802.11 RTS control frame 48 bit 'Receiver Address' field as a 6 bytes array"
        for i in range(0, 6):
            self.set_byte(4+i, value[i])

    def get_ta_field(self):
        "Return 802.11 RTS control frame 48 bit 'Transmitter Address' field as a 6 bytes array"
        return self.get_bytes()[10:16]

    def set_ta_field(self, value):
        "Set 802.11 RTS control frame 48 bit 'Transmitter Address' field as a 6 bytes array"
        for i in range(0, 6):
            self.set_byte(10+i, value[i])            

    def get_fcs_field(self):
        "Return 802.11 RTS control frame 'FCS' field"
        b = self.get_long(16, ">")
        return b 

    def set_fcs_field(self, value):
        "Set the 802.11 RTS control frame 'FCS' field" 
        # set the bits
        nb = value & 0xFFFFFFFF
        self.set_long(16, nb)

class Dot11ControlFramePSPoll(Dot11):
    "802.11 Power-Save Poll Control Frame"
    
    __SIZE = 20
    def __init__(self, aBuffer = None):
        Header.__init__(self, self.__SIZE)
        if aBuffer:
            self.load_header(aBuffer)
        else:
            self.set_type_n_subtype_field(self.DOT11_TYPE_CONTROL_SUBTYPE_POWERSAVE_POLL)

    def get_header_size(self):
        "Return size of 802.11 PSPoll control frame header"
        return self.__SIZE        
    
    def get_packet(self):
        'Return the 802.11 PSPoll control frame'
        # set the checksum if the user hasn't modified it
        if self.auto_checksum:
            payload = self.get_bytes()[:self.__SIZE-4]
            crc32=self.compute_checksum(payload)            
            self.set_fcs_field(crc32)
        
        return self.get_bytes().tostring()
     
    def get_aid_field(self):
        "Return 802.11 PSPoll control frame 'AID' field"
        b = self.get_word(2, "<")
        return b 

    def set_aid_field(self, value):
        "Set the 802.11 PSPoll control frame 'AID' field" 
        # set the bits
        nb = value & 0xFFFF
        self.set_word(2, nb, "<")
        
    def get_bssid_field(self):
        "Return 802.11 PSPoll control frame 48 bit 'BSS ID' field as a 6 bytes array"
        return self.get_bytes()[4:10]

    def set_bssid_field(self, value):
        "Set 802.11 PSPoll control frame 48 bit 'BSS ID' field as a 6 bytes array"
        for i in range(0, 6):
            self.set_byte(4+i, value[i])

    def get_ta_field(self):
        "Return 802.11 PSPoll control frame 48 bit 'Transmitter Address' field as a 6 bytes array"
        return self.get_bytes()[10:16]

    def set_ta_field(self, value):
        "Set 802.11 PSPoll control frame 48 bit 'Transmitter Address' field as a 6 bytes array"
        for i in range(0, 6):
            self.set_byte(10+i, value[i])            

    def get_fcs_field(self):
        "Return 802.11 PSPoll control frame 'FCS' field"
        b = self.get_long(16, ">")
        return b 

    def set_fcs_field(self, value):
        "Set the 802.11 PSPoll control frame 'FCS' field" 
        # set the bits
        nb = value & 0xFFFFFFFF
        self.set_long(16, nb)


class Dot11ControlFrameCFEnd(Dot11):
    "802.11 'Contention Free End' Control Frame"
    
    __SIZE = 20
    def __init__(self, aBuffer = None):
        Header.__init__(self, self.__SIZE)
        if aBuffer:
            self.load_header(aBuffer)
        else:
            self.set_type_n_subtype_field(self.DOT11_TYPE_CONTROL_SUBTYPE_CF_END)

    def get_header_size(self):
        "Return size of 802.11 CF-End control frame header"
        return self.__SIZE        
    
    def get_packet(self):
        'Return the 802.11 CF-End control frame'
        # set the checksum if the user hasn't modified it
        if self.auto_checksum:
            payload = self.get_bytes()[:self.__SIZE-4]
            crc32=self.compute_checksum(payload)            
            self.set_fcs_field(crc32)
        
        return self.get_bytes().tostring()
     
    def get_duration_field(self):
        "Return 802.11 CF-End control frame 'Duration' field"
        b = self.get_word(2, "<")
        return b 

    def set_duration_field(self, value):
        "Set the 802.11 CF-End control frame 'Duration' field" 
        # set the bits
        nb = value & 0xFFFF
        self.set_word(2, nb, "<")
        
    def get_ra_field(self):
        "Return 802.11 CF-End control frame 48 bit 'Receiver Address' field as a 6 bytes array"
        return self.get_bytes()[4:10]

    def set_ra_field(self, value):
        "Set 802.11 CF-End control frame 48 bit 'Receiver Address' field as a 6 bytes array"
        for i in range(0, 6):
            self.set_byte(4+i, value[i])

    def get_bssid_field(self):
        "Return 802.11 CF-End control frame 48 bit 'BSS ID' field as a 6 bytes array"
        return self.get_bytes()[10:16]

    def set_bssid_field(self, value):
        "Set 802.11 CF-End control frame 48 bit 'BSS ID' field as a 6 bytes array"
        for i in range(0, 6):
            self.set_byte(10+i, value[i])            

    def get_fcs_field(self):
        "Return 802.11 CF-End control frame 'FCS' field"
        b = self.get_long(16, ">")
        return b 

    def set_fcs_field(self, value):
        "Set the 802.11 CF-End control frame 'FCS' field" 
        # set the bits
        nb = value & 0xFFFFFFFF
        self.set_long(16, nb)

class Dot11ControlFrameCFEndCFACK(Dot11):
    '802.11 \'CF-End + CF-ACK\' Control Frame'
    
    __SIZE = 20
    def __init__(self, aBuffer = None):
        Header.__init__(self, self.__SIZE)
        if aBuffer:
            self.load_header(aBuffer)
        else:
            self.set_type_n_subtype_field(self.DOT11_TYPE_CONTROL_SUBTYPE_CF_END_CF_ACK)

    def get_header_size(self):
        'Return size of 802.11 \'CF-End+CF-ACK\' control frame header' 
        return self.__SIZE        
    
    def get_packet(self):
        'Return the 802.11 \'CF-End+CF-ACK\' control frame'
        # set the checksum if the user hasn't modified it
        if self.auto_checksum:
            payload = self.get_bytes()[:self.__SIZE-4]
            crc32=self.compute_checksum(payload)            
            self.set_fcs_field(crc32)
        
        return self.get_bytes().tostring()
     
    def get_duration_field(self):
        'Return 802.11 \'CF-End+CF-ACK\' control frame \'Duration\' field'
        b = self.get_word(2, "<")
        return b 

    def set_duration_field(self, value):
        'Set the 802.11 \'CF-End+CF-ACK\' control frame \'Duration\' field' 
        # set the bits
        nb = value & 0xFFFF
        self.set_word(2, nb, "<")
        
    def get_ra_field(self):
        'Return 802.11 \'CF-End+CF-ACK\' control frame 48 bit \'Receiver Address\' field as a 6 bytes array'
        return self.get_bytes()[4:10]

    def set_ra_field(self, value):
        'Set 802.11 \'CF-End+CF-ACK\' control frame 48 bit \'Receiver Address\' field as a 6 bytes array'
        for i in range(0, 6):
            self.set_byte(4+i, value[i])

    def get_bssid_field(self):
        'Return 802.11 \'CF-End+CF-ACK\' control frame 48 bit \'BSS ID\' field as a 6 bytes array'
        return self.get_bytes()[10:16]

    def set_bssid_field(self, value):
        'Set 802.11 \'CF-End+CF-ACK\' control frame 48 bit \'BSS ID\' field as a 6 bytes array'
        for i in range(0, 6):
            self.set_byte(10+i, value[i])            

    def get_fcs_field(self):
        "Return 802.11 CF-End control frame 'FCS' field"
        b = self.get_long(16, ">")
        return b 

    def set_fcs_field(self, value):
        "Set the 802.11 CF-End control frame 'FCS' field" 
        # set the bits
        nb = value & 0xFFFFFFFF
        self.set_long(16, nb)


class Dot11WEPData(Header):
    '802.11 WEP Data Part'
  
    def __init__(self, aBuffer = None):
        Header.__init__(self)

        self.auto_checksum = 0
        
        if aBuffer:
            self.__SIZE = len(aBuffer)
            self.load_header(aBuffer)
            
    def get_header_size(self):
        'Return size of \'WEP\' data part' 

        return len(self.get_bytes().tostring())
    
    def set_auto_wep_icv(self):
        self.auto_checksum = 1

    def unset_auto_wep_icv(self):
        self.auto_checksum = 0

    def get_auto_wep_icv(self):
        return self.auto_checksum

    def get_iv_field(self):
        'Return the \'WEP IV\' field'
        b=self.get_bytes()[0:3].tostring()
        #unpack requires a string argument of length 4 and b is 3 bytes long
        (iv,)=struct.unpack('!L', '\x00'+b)
        return iv

    def set_iv_field(self, value):
        'Set the \'WEP IV\' field'
        # clear the bits
        mask = ((~0xFFFFFF00) & 0xFF)
        masked = self.get_long(0, ">") & mask
        # set the bits 
        nb = masked | ((value & 0x00FFFFFF) << 8)
        self.set_long(0, nb)

    def get_keyid_field(self):
        'Return the \'WEP KEY ID\' field'
        pass

    def set_keyid_field(self):
        'Set the \'WEP KEY ID\' field'
        pass

    def get_packet(self):
        'Return the \'WEP\' field'
        # set the WEP ICV if the user hasn't modified it
        if self.auto_checksum:
            payload = self.get_bytes()[:self.get_header_size()-4]
            crc32=self.compute_checksum(payload)            
            self.set_icv_field(crc32)
        
        return self.get_bytes().tostring()
    
    def get_wep_data_not_decrypted(self):
        'Return \'WEP Data\' field not decrypted'

        return  self.get_bytes()[:self.get_header_size()-4]

    def get_wep_data_decrypted(self):
        'Return \'WEP Data\' field decrypted'
        # TODO: Ver 8.2.1.4.5 WEP MPDU decapsulation
        pass

    def get_icv_field(self):
        "Return the 'WEP ICV' field"

        # set the WEP ICV if the user hasn't modified it
        if self.auto_checksum:
            payload = self.get_bytes()[:self.get_header_size()-4]
            crc32=self.compute_checksum(payload)            
            self.set_icv_field(crc32)
            
        b = self.get_long(-4, ">")
        return b 

    def set_icv_field(self, value):
        "Set the 'WEP ICV' field" 
        # set the bits
        nb = value & 0xFFFFFFFF
        self.set_long(-4, nb)     

class Dot11DataFrame(Dot11):
    '802.11 Data Frame'
    
    def __init__(self, aBuffer = None):
        Dot11.__init__(self, aBuffer)
        
        if aBuffer:
            self.__SIZE = len(aBuffer)
            self.load_header(aBuffer)
        else:
            self.set_type_n_subtype_field(self.DOT11_TYPE_DATA_SUBTYPE_DATA)

    def get_header_size(self):
        'Return size of 802.11 \'Data\' data frame header' 
        #TODO: Check if is correct
        return len(self.get_bytes().tostring())
    
    def get_packet(self):
        'Return the 802.11 \'Data\' data frame'
        # set the checksum if the user hasn't modified it
        if self.auto_checksum:
            payload = self.get_bytes()[:self.get_header_size()-4]
            crc32=self.compute_checksum(payload)            
            self.set_fcs_field(crc32)
        
        return self.get_bytes().tostring()
    
    def is_QoS_frame(self):
        "Return 'True' if is an QoS data frame type"
        
        b = self.get_byte(0)
        return (b & 0x80) and True        

    def is_no_framebody_frame(self):
        "Return 'True' if it frame contain no Frame Body"
        
        b = self.get_byte(0)
        return (b & 0x40) and True

    def is_cf_poll_frame(self):
        "Return 'True' if it frame is a CF_POLL frame"
        
        b = self.get_byte(0)
        return (b & 0x20) and True

    def is_cf_ack_frame(self):
        "Return 'True' if it frame is a CF_ACK frame"
        
        b = self.get_byte(0)
        return (b & 0x10) and True

    def get_duration_field(self):
        'Return 802.11 \'Data\' data frame \'Duration\' field'
        b = self.get_word(2, "<")
        return b 

    def set_duration_field(self, value):
        'Set the 802.11 \'Data\' data frame \'Duration\' field' 
        # set the bits
        nb = value & 0xFFFF
        self.set_word(2, nb, "<")
        
    def get_address1_field(self):
        'Return 802.11 \'Data\' data frame 48 bit \'Address1\' field as a 6 bytes array'
        return self.get_bytes()[4:10]

    def set_address1_field(self, value):
        'Set 802.11 \'Data\' data frame 48 bit \'Address1\' field as a 6 bytes array'
        for i in range(0, 6):
            self.set_byte(4+i, value[i])

    def get_address2_field(self):
        'Return 802.11 \'Data\' data frame 48 bit \'Address2\' field as a 6 bytes array'
        return self.get_bytes()[10:16]

    def set_address2_field(self, value):
        'Set 802.11 \'Data\' data frame 48 bit \'Address2\' field as a 6 bytes array'
        for i in range(0, 6):
            self.set_byte(10+i, value[i])
            
    def get_address3_field(self):
        'Return 802.11 \'Data\' data frame 48 bit \'Address3\' field as a 6 bytes array'
        return self.get_bytes()[16: 22]

    def set_address3_field(self, value):
        'Set 802.11 \'Data\' data frame 48 bit \'Address3\' field as a 6 bytes array'
        for i in range(0, 6):
            self.set_byte(16+i, value[i])

    def get_sequence_control_field(self):
        'Return 802.11 \'Data\' data frame \'Sequence Control\' field'
        b = self.get_word(22, "<")
        return b 

    def set_sequence_control_field(self, value):
        'Set the 802.11 \'Data\' data frame \'Sequence Control\' field' 
        # set the bits
        nb = value & 0xFFFF
        self.set_word(22, nb, "<")

    def get_fragment_number_field(self):
        'Return 802.11 \'Data\' data frame \'Fragment Number\' subfield'

        b = self.get_word(22, "<")
        return (b&0x000F) 

    def set_fragment_number_field(self, value):
        'Set the 802.11 \'Data\' data frame \'Fragment Number\' subfield' 
        # clear the bits
        mask = (~0x000F) & 0xFFFF
        masked = self.get_word(22, "<") & mask
        # set the bits 
        nb = masked | (value & 0x000F)
        self.set_word(22, nb, "<")
        
    def get_secuence_number_field(self):
        'Return 802.11 \'Data\' data frame \'Secuence Number\' subfield'
        
        b = self.get_word(22, "<")
        return ((b>>4) & 0xFFF) 
    
    def set_secuence_number_field(self, value):
        'Set the 802.11 \'Data\' data frame \'Secuence Number\' subfield' 
        # clear the bits
        mask = (~0xFFF0) & 0xFFFF
        masked = self.get_word(22, "<") & mask
        # set the bits 
        nb = masked | ((value & 0x0FFF ) << 4 ) 
        self.set_word(22, nb, "<")

    def get_address4_field(self):
        'Return 802.11 \'Data\' data frame 48 bit \'Address4\' field as a 6 bytes array'
        if self.get_fromDS_field() and self.get_toDS_field():
            return self.get_bytes()[24: 30]
        else:
            return None

    def set_address4_field(self, value):
        'Set 802.11 \'Data\' data frame 48 bit \'Address4\' field as a 6 bytes array'
        if self.get_fromDS_field() and self.get_toDS_field():
            for i in range(0, 6):
                self.set_byte(24+i, value[i])
        else:
            # this does not have address4
            pass

    def get_frame_body_field(self):
        'Return 802.11 \'Data\' data frame \'Frame Body\' field'
        index=24
        if self.get_fromDS_field() and self.get_toDS_field():
            # this does have address4
            index+=6
        if self.is_QoS_frame(): 
            index+=2
        return self.get_bytes()[index:-4].tostring()

    def get_frame_body_field2(self):
        #TODO: Este metodo reemplazara al anterior, aca necesitamos
        # devolver dependiendo si es Open/WEP/WPA/WPA2, el objeto 
        # correspondiente
        'Return 802.11 \'Data\' data frame \'Frame Body\' field'
        index=24
        if self.get_fromDS_field() and self.get_toDS_field():
            # this does have address4
            index+=6
        if self.is_QoS_frame(): 
            index+=2
        return self.get_bytes()[index:-4].tostring()

    def set_frame_body_field(self, data):
        'Set 802.11 \'Data\' data frame \'Frame Body\' field'
        index=24
        if self.get_fromDS_field() and self.get_toDS_field():
            # this does have address4
            index+=6
        if False and QoS: 
            #TODO: Completar QoS
            index+=2
        frame=self.get_bytes()
        del frame[index:]      # Strip from framebody (incl) to end 
        frame.append(data)  # Append the new frameboy

        crc32=self.compute_checksum(frame)
        frame.append(crc32) # Append the new calculated FCS-CRC32
        
    def get_fcs_field(self):
        "Return 802.11 \'Data\' data frame 'FCS' field"
        b = self.get_long(-4, ">")
        return b 

    def set_fcs_field(self, value):
        "Set the 802.11 \'Data\' data frame 'FCS' field" 
        # set the bits
        nb = value & 0xFFFFFFFF
        self.set_long(-4, nb) 
