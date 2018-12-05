# SECUREAUTH LABS. Copyright 2018 SecureAuth Corporation. All rights reserved.
#
# This software is provided under under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Description:
#  IEEE 802.11 Network packet codecs.
#
# Author:
#  Gustavo Moreira

import struct
import string
from binascii import crc32

from ImpactPacket import ProtocolPacket
from Dot11Crypto import RC4

frequency = {
    2412: 1,    2417: 2,    2422: 3,    2427: 4,    2432: 5,    2437: 6,    2442: 7,    2447: 8,    2452: 9,
    2457: 10,   2462: 11,   2467: 12,   2472: 13,   2484: 14,   5170: 34,   5180: 36,   5190: 38,   5200: 40,
    5210: 42,   5220: 44,   5230: 46,   5240: 48,   5260: 52,   5280: 56,   5300: 60,   5320: 64,   5500: 100,
    5510: 102,  5520: 104,  5530: 106,  5540: 108,  5550: 110,  5560: 112,  5570: 114,  5580: 116,  5590: 118,
    5600: 120,  5610: 122,  5620: 124,  5630: 126,  5640: 128,  5650: 130,  5660: 132,  5670: 134,  5680: 136,
    5690: 138,  5700: 140,  5745: 149,  5765: 153,  5785: 157,  5805: 161,  5825: 165,  5855: 170,  5860: 172,
    5865: 173,  5870: 174,  5875: 175,  5880: 176,  5885: 177,  5890: 178,  5895: 179,  5900: 180,  5905: 181,
    5910: 182,  5915: 183,  5920: 184,
}


class Dot11ManagementCapabilities():
    #
    # Capability Information
    #   0   1   2   3   4   5   6   7   8   9   A   B   C   D   E   F
    # +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
    # | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
    # +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
    #   |   |   |   |   |   |   |   |   |   |   |   |   |   |   |   |
    #   |   |   |   |   |   |   |   |   |   |   |   |   |   |   |---+-- Reserved
    #   |   |   |   |   |   |   |   |   |   |   |   |   |   |
    #   |   |   |   |   |   |   |   |   |   |   |   |   |   |---------- DSSS-OFDM
    #   |   |   |   |   |   |   |   |   |   |   |   |   |
    #   |   |   |   |   |   |   |   |   |   |   |   |---+-------------- Reserved
    #   |   |   |   |   |   |   |   |   |   |   |
    #   |   |   |   |   |   |   |   |   |   |   |---------------------- Short slot time
    #   |   |   |   |   |   |   |   |   |   |
    #   |   |   |   |   |   |   |   |   |---+-------------------------- Reserved
    #   |   |   |   |   |   |   |   |
    #   |   |   |   |   |   |   |   |---------------------------------- Channel agility (802.11b)
    #   |   |   |   |   |   |   |
    #   |   |   |   |   |   |   |-------------------------------------- PBCC (802.11b)
    #   |   |   |   |   |   |
    #   |   |   |   |   |   |------------------------------------------ Short preamble (802.11b)
    #   |   |   |   |   |
    #   |   |   |   |   |---------------------------------------------- Privacy
    #   |   |   |   |
    #   |   |   |   |-------------------------------------------------- CF-Poll request
    #   |   |   |
    #   |   |   |------------------------------------------------------ CF-Pollable
    #   |   |
    #   |   |---------------------------------------------------------- IBSS
    #   |
    #   |-------------------------------------------------------------- ESS
    #
    CAPABILITY_RESERVED_1      = int("1000000000000000", 2)
    CAPABILITY_RESERVED_2      = int("0100000000000000", 2)
    CAPABILITY_DSSS_OFDM       = int("0010000000000000", 2)
    CAPABILITY_RESERVED_3      = int("0001000000000000", 2)
    CAPABILITY_RESERVED_4      = int("0000100000000000", 2)
    CAPABILITY_SHORT_SLOT_TIME = int("0000010000000000", 2)
    CAPABILITY_RESERVED_5      = int("0000001000000000", 2)
    CAPABILITY_RESERVED_6      = int("0000000100000000", 2)
    CAPABILITY_CH_AGILITY      = int("0000000010000000", 2)
    CAPABILITY_PBCC            = int("0000000001000000", 2)
    CAPABILITY_SHORT_PREAMBLE  = int("0000000000100000", 2)
    CAPABILITY_PRIVACY         = int("0000000000010000", 2)
    CAPABILITY_CF_POLL_REQ     = int("0000000000001000", 2)
    CAPABILITY_CF_POLLABLE     = int("0000000000000100", 2)
    CAPABILITY_IBSS            = int("0000000000000010", 2)
    CAPABILITY_ESS             = int("0000000000000001", 2)

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
        DOT11_TYPE_MANAGEMENT|DOT11_SUBTYPE_MANAGEMENT_REASSOCIATION_RESPONSE<<2
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

class Dot11(ProtocolPacket):    
    def __init__(self, aBuffer = None, FCS_at_end = True):
        header_size = 2
        self.__FCS_at_end=not not FCS_at_end # Is Boolean
        if self.__FCS_at_end:
            tail_size = 4
        else:
            tail_size = 0
            
        ProtocolPacket.__init__(self, header_size,tail_size)
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
        
        if not self.__FCS_at_end:
            return None   

        b = self.tail.get_long(-4, ">")
        return b 

    def set_fcs(self, value = None):
        "Set the 802.11 CTS control frame 'FCS' field. If value is None, is auto_checksum"

        if not self.__FCS_at_end:   
            return
        
        # calculate the FCS
        if value is None:
            payload = self.get_body_as_string()
            crc32=self.compute_checksum(payload)            
            value=crc32

        # set the bits
        nb = value & 0xFFFFFFFF
        self.tail.set_long(-4, nb)

class Dot11ControlFrameCTS(ProtocolPacket):
    "802.11 Clear-To-Send Control Frame"
    
    def __init__(self, aBuffer = None):
        header_size = 8
        tail_size = 0

        ProtocolPacket.__init__(self, header_size, tail_size)
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

class Dot11ControlFrameACK(ProtocolPacket):
    "802.11 Acknowledgement Control Frame"
        
    def __init__(self, aBuffer = None):
        header_size = 8
        tail_size = 0

        ProtocolPacket.__init__(self, header_size, tail_size)
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

class Dot11ControlFrameRTS(ProtocolPacket):
    "802.11 Request-To-Send Control Frame"
        
    def __init__(self, aBuffer = None):
        header_size = 14
        tail_size = 0

        ProtocolPacket.__init__(self, header_size, tail_size)
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

class Dot11ControlFramePSPoll(ProtocolPacket):
    "802.11 Power-Save Poll Control Frame"
    
    def __init__(self, aBuffer = None):
        header_size = 14
        tail_size = 0
        
        ProtocolPacket.__init__(self, header_size, tail_size)
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

class Dot11ControlFrameCFEnd(ProtocolPacket):
    "802.11 'Contention Free End' Control Frame"
    
    def __init__(self, aBuffer = None):
        header_size = 14
        tail_size = 0
    
        ProtocolPacket.__init__(self, header_size, tail_size)
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

class Dot11ControlFrameCFEndCFACK(ProtocolPacket):
    '802.11 \'CF-End + CF-ACK\' Control Frame'
        
    def __init__(self, aBuffer = None):
        header_size = 14
        tail_size = 0

        ProtocolPacket.__init__(self, header_size, tail_size)
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

class Dot11DataFrame(ProtocolPacket):
    '802.11 Data Frame'
    
    def __init__(self, aBuffer = None):
        header_size = 22
        tail_size = 0

        ProtocolPacket.__init__(self, header_size, tail_size)
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
        
    def get_sequence_number(self):
        'Return 802.11 \'Data\' data frame \'Sequence Number\' subfield'
        
        b = self.header.get_word(20, "<")
        return ((b>>4) & 0xFFF) 
    
    def set_sequence_number(self, value):
        'Set the 802.11 \'Data\' data frame \'Sequence Number\' subfield' 
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
    
    def __init__(self, aBuffer = None):
        header_size = 24
        tail_size = 0

        ProtocolPacket.__init__(self, header_size, tail_size)
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

    def __init__(self, aBuffer = None):
        header_size = 28
        tail_size = 0

        ProtocolPacket.__init__(self, header_size, tail_size)
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

    def __init__(self, aBuffer = None):
        header_size = 30
        tail_size = 0

        ProtocolPacket.__init__(self, header_size, tail_size)
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

class LLC(ProtocolPacket):
    '802.2 Logical Link Control (LLC) Frame'
    
    DLC_UNNUMBERED_FRAMES = 0x03

    def __init__(self, aBuffer = None):
        header_size = 3
        tail_size = 0

        ProtocolPacket.__init__(self, header_size, tail_size)
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

class SNAP(ProtocolPacket):
    '802.2 SubNetwork Access Protocol (SNAP) Frame'

    def __init__(self, aBuffer = None):
        header_size = 5
        tail_size = 0

        ProtocolPacket.__init__(self, header_size, tail_size)
        if(aBuffer):
            self.load_packet(aBuffer)

    def get_OUI(self):
        "Get the three-octet Organizationally Unique Identifier (OUI) SNAP frame"
        b=self.header.get_bytes()[0:3].tostring()
        #unpack requires a string argument of length 4 and b is 3 bytes long
        (oui,)=struct.unpack('!L', '\x00'+b)
        return oui

    def set_OUI(self, value):
        "Set the three-octet Organizationally Unique Identifier (OUI) SNAP frame"
        # clear the bits
        mask = ((~0xFFFFFF00) & 0xFF)
        masked = self.header.get_long(0, ">") & mask
        # set the bits 
        nb = masked | ((value & 0x00FFFFFF) << 8)
        self.header.set_long(0, nb)

    def get_protoID(self):
        "Get the two-octet Protocol Identifier (PID) SNAP field"
        return self.header.get_word(3, ">")

    def set_protoID(self, value):
        "Set the two-octet Protocol Identifier (PID) SNAP field"
        self.header.set_word(3, value, ">")

class Dot11WEP(ProtocolPacket):
    '802.11 WEP'

    def __init__(self, aBuffer = None):
        header_size = 4
        tail_size = 0

        ProtocolPacket.__init__(self, header_size, tail_size)
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
        'Set the \'WEP IV\' field.'
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
    
    def get_decrypted_data(self, key_string):
        'Return \'WEP Data\' field decrypted'

        # Needs to be at least 8 bytes of payload 
        if len(self.body_string)<8:
            return self.body_string
        
        # initialize the first bytes of the key from the IV 
        # and copy rest of the WEP key (the secret part) 
        
        # Convert IV to 3 bytes long string
        iv=struct.pack('>L',self.get_iv())[-3:]
        key=iv+key_string
        rc4=RC4(key)
        decrypted_data=rc4.decrypt(self.body_string)
        
        return decrypted_data
    
    def get_encrypted_data(self, key_string):
        # RC4 is symmetric
        return self.get_decrypted_data(key_string)
    
    def encrypt_frame(self, key_string):
        enc = self.get_encrypted_data(key_string)
        self.load_body(enc)
    
class Dot11WEPData(ProtocolPacket):
    '802.11 WEP Data Part'

    def __init__(self, aBuffer = None):
        header_size = 0
        tail_size = 4

        ProtocolPacket.__init__(self, header_size, tail_size)
        if(aBuffer):
            self.load_packet(aBuffer)
        
    def get_icv(self):
        "Return 'WEP ICV' field"
            
        b = self.tail.get_long(-4, ">")
        return b 

    def set_icv(self, value = None):
        "Set 'WEP ICV' field"

        # Compute the WEP ICV
        if value is None:
            value=self.get_computed_icv()

        # set the bits
        nb = value & 0xFFFFFFFF
        self.tail.set_long(-4, nb)
    
    def get_computed_icv(self):
        crcle=crc32(self.body_string)&0xffffffffL
        # This crc32 is in little endian, convert it to big endian 
        crc=struct.pack('<L', crcle)
         # Convert to long
        (crc_long,) = struct.unpack('!L', crc)
        return crc_long
    
    def check_icv(self):
        computed_icv=self.get_computed_icv()
        current_icv=self.get_icv()
        if computed_icv==current_icv:
            return True
        else:
            return False

class Dot11WPA(ProtocolPacket):
    '802.11 WPA'

    def __init__(self, aBuffer = None):
        header_size = 8
        tail_size = 0

        ProtocolPacket.__init__(self, header_size, tail_size)
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

class Dot11WPAData(ProtocolPacket):
    '802.11 WPA Data Part'

    def __init__(self, aBuffer = None):
        header_size = 0
        tail_size = 12

        ProtocolPacket.__init__(self, header_size, tail_size)
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
        
class Dot11WPA2(ProtocolPacket):
    '802.11 WPA2'

    def __init__(self, aBuffer = None):
        header_size = 8
        tail_size = 0

        ProtocolPacket.__init__(self, header_size, tail_size)
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

class Dot11WPA2Data(ProtocolPacket):
    '802.11 WPA2 Data Part'

    def __init__(self, aBuffer = None):
        header_size = 0
        tail_size = 8

        ProtocolPacket.__init__(self, header_size, tail_size)
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

class RadioTap(ProtocolPacket):
    __HEADER_BASE_SIZE = 8  # minimal header size
    _PRESENT_FLAGS_SIZE = 4
    _BASE_PRESENT_FLAGS_OFFSET = 4

    class __RadioTapField(object):
        ALIGNMENT = 1

        def __str__( self ):
            return str( self.__class__.__name__ )

    class RTF_TSFT(__RadioTapField):
        BIT_NUMBER = 0
        STRUCTURE = "<Q"
        ALIGNMENT = 8

    class RTF_FLAGS(__RadioTapField):
        BIT_NUMBER = 1
        STRUCTURE = "<B"

        # https://web.archive.org/web/20160423125307/www.radiotap.org/defined-fields/Flags
        PROPERTY_CFP            = 0x01 #sent/received during CFP
        PROPERTY_SHORTPREAMBLE  = 0x02 #sent/received with short preamble
        PROPERTY_WEP            = 0x04 #sent/received with WEP encryption
        PROPERTY_FRAGMENTATION  = 0x08 #sent/received with fragmentation
        PROPERTY_FCS_AT_END     = 0x10 #frame includes FCS
        PROPERTY_PAYLOAD_PADDING= 0x20 #frame has padding between 802.11 header and payload (to 32-bit boundary)
        PROPERTY_BAD_FCS        = 0x40 #does not pass FCS check
        PROPERTY_SHORT_GI       = 0x80 #frame used short guard interval (HT). Unspecified but used:

    class RTF_RATE(__RadioTapField):
        BIT_NUMBER = 2
        STRUCTURE = "<B"

    class RTF_CHANNEL(__RadioTapField):
        BIT_NUMBER = 3
        STRUCTURE = "<HH"
        ALIGNMENT = 2

    class RTF_FHSS(__RadioTapField):
        BIT_NUMBER = 4
        STRUCTURE = "<BB"

    class RTF_DBM_ANTSIGNAL(__RadioTapField):
        BIT_NUMBER = 5
        STRUCTURE = "<B"

    class RTF_DBM_ANTNOISE(__RadioTapField):
        BIT_NUMBER = 6
        STRUCTURE = "<B"

    class RTF_LOCK_QUALITY(__RadioTapField):
        BIT_NUMBER = 7
        STRUCTURE = "<H"
        ALIGNMENT = 2

    class RTF_TX_ATTENUATION(__RadioTapField):
        BIT_NUMBER = 8
        STRUCTURE = "<H"
        ALIGNMENT = 2

    class RTF_DB_TX_ATTENUATION(__RadioTapField):
        BIT_NUMBER = 9
        STRUCTURE = "<H"
        ALIGNMENT = 2

    class RTF_DBM_TX_POWER(__RadioTapField):
        BIT_NUMBER = 10
        STRUCTURE = "<b"
        ALIGNMENT = 2

    class RTF_ANTENNA(__RadioTapField):
        BIT_NUMBER = 11
        STRUCTURE = "<B"

    class RTF_DB_ANTSIGNAL(__RadioTapField):
        BIT_NUMBER = 12
        STRUCTURE = "<B"

    class RTF_DB_ANTNOISE(__RadioTapField):
        BIT_NUMBER = 13
        STRUCTURE = "<B"

##    # official assignment, clashes with RTF_FCS_IN_HEADER
##    class RTF_RX_FLAGS(__RadioTapField):
##        BIT_NUMBER = 14
##        STRUCTURE = "<H"
##        ALIGNMENT = 2

    # clashes with RTF_RX_FLAGS
    class RTF_FCS_IN_HEADER(__RadioTapField):
        BIT_NUMBER = 14
        STRUCTURE = "<L"
        ALIGNMENT = 4   

    # clashes with HARDWARE_QUEUE
    class RTF_TX_FLAGS(__RadioTapField):
        BIT_NUMBER = 15
        STRUCTURE = "<H"
        ALIGNMENT = 2

##    # clashes with TX_FLAGS
##    class RTF_HARDWARE_QUEUE(__RadioTapField):
##        BIT_NUMBER = 15
##        STRUCTURE = "<B"
##        ALIGNMENT = 1

    # clashes with RSSI
    class RTF_RTS_RETRIES(__RadioTapField):
        BIT_NUMBER = 16
        STRUCTURE = "<B"

##    # clashes with RTS_RETRIES 
##    class RTF_RSSI(__RadioTapField):
##        BIT_NUMBER = 16
##        STRUCTURE = "<H"
##        ALIGNMENT = 1

    class RTF_DATA_RETRIES(__RadioTapField):
        BIT_NUMBER = 17
        STRUCTURE = "<B"

    class RTF_XCHANNEL(__RadioTapField):
        BIT_NUMBER = 18
        STRUCTURE = "<LHBB"
        ALIGNMENT = 4

    class RTF_EXT(__RadioTapField):
        BIT_NUMBER = 31
        STRUCTURE = []
    
    # Sort the list so the 'for' statement walk the list in the right order
    radiotap_fields = __RadioTapField.__subclasses__()
    radiotap_fields.sort(lambda x, y: cmp(x.BIT_NUMBER,y.BIT_NUMBER))
    
    def __init__(self, aBuffer = None):
        header_size = self.__HEADER_BASE_SIZE 
        tail_size = 0
        
        if aBuffer:
            length = struct.unpack('<H', aBuffer[2:4])[0]
            header_size=length
                    
            ProtocolPacket.__init__(self, header_size, tail_size)
            self.load_packet(aBuffer)
        else:
            ProtocolPacket.__init__(self, header_size, tail_size)
            self.set_version(0)
            self.__set_present(0x00000000)
            
    def get_header_length(self):
        'Return the RadioTap header \'length\' field'
        self.__update_header_length()        
        return self.header.get_word(2, "<")
            
    def get_version(self):
        'Return the \'version\' field'
        b = self.header.get_byte(0)
        return b
    
    def set_version(self, value):
        'Set the \'version\' field'
        nb = (value & 0xFF)
        self.header.set_byte(0, nb)
        
        nb = (value & 0xFF)
        
    def get_present(self, offset=_BASE_PRESENT_FLAGS_OFFSET):
        "Return RadioTap present bitmap field"
        present = self.header.get_long(offset, "<")
        return present

    def __set_present(self, value):
        "Set RadioTap present field bit"
        self.header.set_long(4, value)

    def get_present_bit(self, field, offset=4):
        'Get a \'present\' field bit'
        present=self.get_present(offset)
        return not not (2**field.BIT_NUMBER & present)

    def __set_present_bit(self, field):
        'Set a \'present\' field bit'
        npresent=2**field.BIT_NUMBER | self.get_present()
        self.header.set_long(4, npresent,'<')

    def __unset_present_bit(self, field):
        'Unset a \'present\' field bit'
        npresent=~(2**field.BIT_NUMBER) & self.get_present()
        self.header.set_long(4, npresent,'<')
        
    def __align(self, val, align):
        return ( (((val) + ((align) - 1)) & ~((align) - 1)) - val )

    def __get_field_position(self, field):

        offset = RadioTap._BASE_PRESENT_FLAGS_OFFSET
        extra_present_flags_count = 0
        while self.get_present_bit(RadioTap.RTF_EXT, offset):
            offset += RadioTap._PRESENT_FLAGS_SIZE
            extra_present_flags_count += 1

        field_position = self.__HEADER_BASE_SIZE + (RadioTap._BASE_PRESENT_FLAGS_OFFSET * extra_present_flags_count)

        for f in self.radiotap_fields:
            field_position += self.__align(field_position, f.ALIGNMENT)
            if f == field:
                return field_position

            if self.get_present_bit(f):
                total_length = struct.calcsize(f.STRUCTURE)
                field_position += total_length

        return None

    def unset_field( self, field):
        is_present=self.get_present_bit(field)
        if is_present is False:
            return False
                
        byte_pos=self.__get_field_position(field)
        if not byte_pos:
            return False

        self.__unset_present_bit(field)

        header=self.get_header_as_string()
        total_length = struct.calcsize(field.STRUCTURE)
        header=header[:byte_pos]+header[byte_pos+total_length:]
        
        self.load_header(header)

    def __get_field_values( self, field ):
        is_present=self.get_present_bit(field)
        if is_present is False:
            return None
        
        byte_pos=self.__get_field_position(field)
        header=self.get_header_as_string()
        total_length=struct.calcsize(field.STRUCTURE)
        v=header[ byte_pos:byte_pos+total_length ]
        
        field_values = struct.unpack(field.STRUCTURE, v)
        
        return field_values

    def __set_field_values( self, field, values ):
        if not hasattr(values,'__iter__'):
            raise Exception("arg 'values' is not iterable")
        
        # It's for to known the qty of argument of a structure
        num_fields=len(field.STRUCTURE.translate(string.maketrans("",""), '=@!<>'))

        if len(values)!=num_fields:
            raise Exception("Field %s has exactly %d items"%(str(field),struct.calcsize(field.STRUCTURE)))
        
        is_present=self.get_present_bit(field)
        if is_present is False:
            self.__set_present_bit(field)
        
        byte_pos=self.__get_field_position(field)
        header=self.get_header_as_string()
        total_length=struct.calcsize(field.STRUCTURE)
        v=header[ byte_pos:byte_pos+total_length ]
        
        new_str = struct.pack(field.STRUCTURE, *values)

        if is_present is True:
            header=header[:byte_pos]+new_str+header[byte_pos+total_length:]
        else:
            header=header[:byte_pos]+new_str+header[byte_pos:]
        self.load_header(header)

            
    def set_tsft( self, nvalue ):
        "Set the Value in microseconds of the MAC's 64-bit 802.11 "\
        "Time Synchronization Function timer when the first bit of "\
        "the MPDU arrived at the MAC"
        self.__set_field_values(RadioTap.RTF_TSFT, [nvalue])
        
    def get_tsft( self ):
        "Get the Value in microseconds of the MAC's 64-bit 802.11 "\
        "Time Synchronization Function timer when the first bit of "\
        "the MPDU arrived at the MAC"
        
        values=self.__get_field_values(RadioTap.RTF_TSFT)
        if not values:
            return None
        return values[0]

    def set_flags( self, nvalue ):
        "Set the properties of transmitted and received frames."
        self.__set_field_values(self.RTF_FLAGS, [nvalue])
   
    def get_flags( self ):
        "Get the properties of transmitted and received frames."
        values=self.__get_field_values(self.RTF_FLAGS)
        if not values:
            return None
        return values[0]
   
    def set_rate( self, nvalue ):
        "Set the TX/RX data rate in 500 Kbps units" 
        
        self.__set_field_values(self.RTF_RATE, [nvalue])
   
    def get_rate( self ):
        "Get the TX/RX data rate in 500 Kbps units" 

        values=self.__get_field_values(self.RTF_RATE)
        if not values:
            return None
        return values[0]

    def set_channel( self, freq, flags ):
        "Set the channel Tx/Rx frequency in MHz and the channel flags" 

        self.__set_field_values(self.RTF_CHANNEL, [freq, flags])
   
    def get_channel( self ):
        "Get the TX/RX data rate in 500 Kbps units" 

        values=self.__get_field_values(self.RTF_CHANNEL)

        return values

    def set_FHSS( self, hop_set, hop_pattern ):
        "Set the hop set and pattern for frequency-hopping radios" 

        self.__set_field_values(self.RTF_FHSS, [hop_set, hop_pattern])
   
    def get_FHSS( self ):
        "Get the hop set and pattern for frequency-hopping radios" 

        values=self.__get_field_values(self.RTF_FHSS)

        return values

    def set_dBm_ant_signal( self, signal ):
        "Set the RF signal power at the antenna, decibel difference from an "\
        "arbitrary, fixed reference." 

        self.__set_field_values(self.RTF_DBM_ANTSIGNAL, [signal])
   
    def get_dBm_ant_signal( self ):
        "Get the RF signal power at the antenna, decibel difference from an "\
        "arbitrary, fixed reference." 

        values=self.__get_field_values(self.RTF_DBM_ANTSIGNAL)
        if not values:
            return None
        return values[0]

    def set_dBm_ant_noise( self, signal ):
        "Set the RF noise power at the antenna, decibel difference from an "\
        "arbitrary, fixed reference."

        self.__set_field_values(self.RTF_DBM_ANTNOISE, [signal])
   
    def get_dBm_ant_noise( self ):
        "Get the RF noise power at the antenna, decibel difference from an "\
        "arbitrary, fixed reference."

        values=self.__get_field_values(self.RTF_DBM_ANTNOISE)
        if not values:
            return None
        return values[0]

    def set_lock_quality( self, quality ):
        "Set the quality of Barker code lock. "\
        "Called 'Signal Quality' in datasheets. "

        self.__set_field_values(self.RTF_LOCK_QUALITY, [quality])
   
    def get_lock_quality( self ):
        "Get the quality of Barker code lock. "\
        "Called 'Signal Quality' in datasheets. "
        
        values=self.__get_field_values(self.RTF_LOCK_QUALITY)
        if not values:
            return None
        return values[0]

    def set_tx_attenuation( self, power ):
        "Set the transmit power expressed as unitless distance from max power "\
        "set at factory calibration. 0 is max power."

        self.__set_field_values(self.RTF_TX_ATTENUATION, [power])
   
    def get_tx_attenuation( self ):
        "Set the transmit power expressed as unitless distance from max power "\
        "set at factory calibration. 0 is max power."
        
        values=self.__get_field_values(self.RTF_TX_ATTENUATION)
        if not values:
            return None
        return values[0]

    def set_dB_tx_attenuation( self, power ):
        "Set the transmit power expressed as decibel distance from max power "\
        "set at factory calibration. 0 is max power. "

        self.__set_field_values(self.RTF_DB_TX_ATTENUATION, [power])
   
    def get_dB_tx_attenuation( self ):
        "Set the transmit power expressed as decibel distance from max power "\
        "set at factory calibration. 0 is max power. "
        
        values=self.__get_field_values(self.RTF_DB_TX_ATTENUATION)
        if not values:
            return None
        return values[0]

    def set_dBm_tx_power( self, power ):
        "Set the transmit power expressed as dBm (decibels from a 1 milliwatt"\
        " reference). This is the absolute power level measured at the "\
        "antenna port."
        
        self.__set_field_values(self.RTF_DBM_TX_POWER, [power])
   
    def get_dBm_tx_power( self ):
        "Get the transmit power expressed as dBm (decibels from a 1 milliwatt"\
        " reference). This is the absolute power level measured at the "\
        "antenna port."
        
        values=self.__get_field_values(self.RTF_DBM_TX_POWER)
        if not values:
            return None
        return values[0]

    def set_antenna( self, antenna_index ):
        "Set Rx/Tx antenna index for this packet. "\
        "The first antenna is antenna 0. "\
        
        self.__set_field_values(self.RTF_ANTENNA, [antenna_index])
   
    def get_antenna( self ):
        "Set Rx/Tx antenna index for this packet. "\
        "The first antenna is antenna 0. "\
        
        values=self.__get_field_values(self.RTF_ANTENNA)
        if not values:
            return None
        return values[0]

    def set_dB_ant_signal( self, signal ):
        "Set the RF signal power at the antenna, decibel difference from an "\
        "arbitrary, fixed reference." 

        self.__set_field_values(self.RTF_DB_ANTSIGNAL, [signal])
   
    def get_dB_ant_signal( self ):
        "Get the RF signal power at the antenna, decibel difference from an "\
        "arbitrary, fixed reference." 

        values=self.__get_field_values(self.RTF_DB_ANTSIGNAL)
        if not values:
            return None
        return values[0]

    def set_dB_ant_noise( self, signal ):
        "Set the RF noise power at the antenna, decibel difference from an "\
        "arbitrary, fixed reference." 

        self.__set_field_values(self.RTF_DB_ANTNOISE, [signal])
   
    def get_dB_ant_noise( self ):
        "Get the RF noise power at the antenna, decibel difference from an "\
        "arbitrary, fixed reference." 

        values=self.__get_field_values(self.RTF_DB_ANTNOISE)
        if not values:
            return None
        return values[0]

##    def set_rx_flags( self, flags ):
##        "Set the properties of received frames." 
##
##        self.__set_field_values(self.RTF_RX_FLAGS, [flags])
##   
##    def get_rx_flags( self ):
##        "Get the properties of received frames." 
##
##        values=self.__get_field_values(self.RTF_RX_FLAGS)
##        if not values:
##            return None
##        return values[0]

    def set_FCS_in_header( self, fcs ):
        "Set the Field containing the FCS of the frame (instead of it being "\
        "appended to the frame as it would appear on the air.) " 

        self.__set_field_values(self.RTF_FCS_IN_HEADER, [fcs])
   
    def get_FCS_in_header( self ):
        "Get the Field containing the FCS of the frame (instead of it being "\
        "appended to the frame as it would appear on the air.) " 

        values=self.__get_field_values(self.RTF_FCS_IN_HEADER)
        if not values:
            return None
        return values[0]

##    def set_RSSI( self, rssi, max_rssi ):
##        "Set the received signal strength and the maximum for the hardware." 
##        
##        self.__set_field_values(self.RTF_RSSI, [rssi, max_rssi])
##   
##    def get_RSSI( self ):
##        "Get the received signal strength and the maximum for the hardware." 
##        
##        values=self.__get_field_values(self.RTF_RSSI)
##        
##        return values

    def set_RTS_retries( self, retries):
        "Set the number of RTS retries a transmitted frame used." 
        
        self.__set_field_values(self.RTF_RTS_RETRIES, [retries])
   
    def get_RTS_retries( self ):
        "Get the number of RTS retries a transmitted frame used." 
        
        values=self.__get_field_values(self.RTF_RTS_RETRIES)
        if not values:
            return None
        return values[0]

    def set_tx_flags( self, flags ):
        "Set the properties of transmitted frames." 

        self.__set_field_values(self.RTF_TX_FLAGS, [flags])
   
    def get_tx_flags( self ):
        "Get the properties of transmitted frames." 

        values=self.__get_field_values(self.RTF_TX_FLAGS)
        if not values:
            return None
        return values[0]

    def set_xchannel( self, flags, freq, channel, maxpower ):
        "Set extended channel information: flags, freq, channel and maxpower" 
        
        self.__set_field_values(self.RTF_XCHANNEL, [flags, freq, channel, maxpower] )
   
    def get_xchannel( self ):
        "Get extended channel information: flags, freq, channel and maxpower" 
        
        values=self.__get_field_values(field=self.RTF_XCHANNEL)

        return values

    def set_data_retries( self, retries ):
        "Set the number of data retries a transmitted frame used." 

        self.__set_field_values(self.RTF_DATA_RETRIES, [retries])
   
    def get_data_retries( self ):
        "Get the number of data retries a transmitted frame used." 

        values=self.__get_field_values(self.RTF_DATA_RETRIES)
        if not values:
            return None
        return values[0]

    def set_hardware_queue( self, queue ):
        "Set the hardware queue to send the frame on." 

        self.__set_field_values(self.RTF_HARDWARE_QUEUE, [queue])
   
##    def get_hardware_queue( self ):
##        "Get the hardware queue to send the frame on." 
##
##        values=self.__get_field_values(self.RTF_HARDWARE_QUEUE)
##        if not values:
##            return None
##        return values[0]

    def __update_header_length(self):
        'Update the RadioTap header length field with the real size'
        self.header.set_word(2, self.get_header_size(), "<")

    def get_packet(self):
        self.__update_header_length()
        return ProtocolPacket.get_packet(self)

class Dot11ManagementFrame(ProtocolPacket):
    '802.11 Management Frame'
    
    def __init__(self, aBuffer = None):
        header_size = 22
        tail_size = 0

        ProtocolPacket.__init__(self, header_size, tail_size)
        if(aBuffer):
            self.load_packet(aBuffer)

    def __init__(self, aBuffer = None):
        header_size = 22
        tail_size = 0

        ProtocolPacket.__init__(self, header_size, tail_size)
        if(aBuffer):
            self.load_packet(aBuffer)
        
    def get_duration(self):
        'Return 802.11 Management frame \'Duration\' field'
        b = self.header.get_word(0, "<")
        return b 

    def set_duration(self, value):
        'Set the 802.11 Management frame \'Duration\' field' 
        # set the bits
        nb = value & 0xFFFF
        self.header.set_word(0, nb, "<")
        
    def get_destination_address(self):
        'Return 802.11 Management frame \'Destination Address\' field as a 6 bytes array'
        return self.header.get_bytes()[2:8]

    def set_destination_address(self, value):
        'Set 802.11 Management frame \'Destination Address\' field as a 6 bytes array'
        for i in range(0, 6):
            self.header.set_byte(2+i, value[i])

    def get_source_address(self):
        'Return 802.11 Management frame \'Source Address\' field as a 6 bytes array'
        return self.header.get_bytes()[8:14]

    def set_source_address(self, value):
        'Set 802.11 Management frame \'Source Address\' field as a 6 bytes array'
        for i in range(0, 6):
            self.header.set_byte(8+i, value[i])
            
    def get_bssid(self):
        'Return 802.11 Management frame \'BSSID\' field as a 6 bytes array'
        return self.header.get_bytes()[14: 20]

    def set_bssid(self, value):
        'Set 802.11 Management frame \'BSSID\' field as a 6 bytes array'
        for i in range(0, 6):
            self.header.set_byte(14+i, value[i])

    def get_sequence_control(self):
        'Return 802.11 Management frame \'Sequence Control\' field'
        b = self.header.get_word(20, "<")
        return b 

    def set_sequence_control(self, value):
        'Set the 802.11 Management frame \'Sequence Control\' field' 
        # set the bits
        nb = value & 0xFFFF
        self.header.set_word(20, nb, "<")

    def get_fragment_number(self):
        'Return 802.11 Management frame \'Fragment Number\' subfield'

        b = self.get_sequence_control()
        return (b&0x000F) 

    def set_fragment_number(self, value):
        'Set the 802.11 Management frame \'Fragment Number\' subfield' 
        # clear the bits
        mask = (~0x000F) & 0xFFFF
        masked = self.header.get_word(20, "<") & mask
        # set the bits 
        nb = masked | (value & 0x000F)
        self.header.set_word(20, nb, "<")
        
    def get_sequence_number(self):
        'Return 802.11 Management frame \'Sequence Number\' subfield'
        
        b = self.get_sequence_control()
        return ((b>>4) & 0xFFF) 
    
    def set_sequence_number(self, value):
        'Set the 802.11 Management frame \'Sequence Number\' subfield' 
        # clear the bits
        mask = (~0xFFF0) & 0xFFFF
        masked = self.header.get_word(20, "<") & mask
        # set the bits 
        nb = masked | ((value & 0x0FFF ) << 4 ) 
        self.header.set_word(20, nb, "<")

    def get_frame_body(self):
        'Return 802.11 Management frame \'Frame Body\' field'
        
        return self.get_body_as_string()

    def set_frame_body(self, data):
        'Set 802.11 Management frame \'Frame Body\' field'
        
        self.load_body(data)

class DOT11_MANAGEMENT_ELEMENTS():
    SSID                    =  0
    SUPPORTED_RATES         =  1
    FH_PARAMETER_SET        =  2
    DS_PARAMETER_SET        =  3
    CF_PARAMETER_SET        =  4
    TIM                     =  5
    IBSS_PARAMETER_SET      =  6
    COUNTRY                 =  7
    HOPPING_PARAMETER       =  8
    HOPPING_TABLE           =  9
    REQUEST                 = 10
    BSS_LOAD                = 11
    EDCA_PARAMETER_SET      = 12
    TSPEC                   = 13
    TCLAS                   = 14
    SCHEDULE                = 15
    CHALLENGE_TEXT          = 16
    # RESERVED                17-31 
    POWER_CONSTRAINT        = 32
    POWER_CAPABILITY        = 33
    TPC_REQUEST             = 34
    TPC_REPORT              = 35
    SUPPORTED_CHANNELS      = 36
    CHANNEL_SWITCH_ANN      = 37
    MEASURE_REQ             = 38
    MEASURE_REP             = 39
    QUIET                   = 40
    IBSS_DFS                = 41
    ERP_INFO                = 42
    TS_DELAY                = 43
    TCLAS_PROCESSING        = 44
    #RESERVED                 45  # See: IEEE 802.11n
    QOS_CAPABILITY          = 46
    #RESERVED                 47  # See: IEEE 802.11g
    RSN                     = 48
    #RESERVED                 49
    EXT_SUPPORTED_RATES     = 50
    #RESERVED                 51-126
    EXTENDED_CAPABILITIES   = 127
    #RESERVED                 128-220
    VENDOR_SPECIFIC         = 221
    #RESERVED                 222-255
    
class Dot11ManagementHelper(ProtocolPacket):
        
    def __init__(self, header_size, tail_size, aBuffer = None):
        self.__HEADER_BASE_SIZE=header_size
        
        if aBuffer:
            elements_length=self.__calculate_elements_length(aBuffer[self.__HEADER_BASE_SIZE:])
            header_size+=elements_length
            
            ProtocolPacket.__init__(self, header_size, tail_size)
            self.load_packet(aBuffer)
        else:
            ProtocolPacket.__init__(self, header_size, tail_size)

    def _find_element(self, elements, element_id ):
        remaining=len(elements)
        
        offset=0
        while remaining > 0:
            (id,length)=struct.unpack("!BB",elements[offset:offset+2])
            if element_id is None:
                pass # through the whole list returning the length
            elif id==element_id:
                yield (0,offset,length+2)    # ==
            length+=2 #id+length
            offset+=length
            if length>remaining:
                # Error!!
                length = remaining;
            remaining-=length
        # < Not found
        yield (-1, offset, None)

    def __calculate_elements_length(self, elements):
        gen_tp=self._find_element(elements, None )
        (match,offset,length)=gen_tp.next()
        if match != -1:
            # element_id is None, then __find_tagged_parameter must return -1
            raise Exception("Internal Error %s"%match)
        return offset
        
    def _get_elements_generator(self, element_id):
        elements=self.get_header_as_string()[self.__HEADER_BASE_SIZE:]
        gen_tp=self._find_element(elements, element_id )
        while True:
            (match,offset,length)=gen_tp.next()
            if match != 0:
                return
            value_offset=offset+2
            value_end=offset+length
            value=elements[value_offset:value_end]
            yield value
        
    def _get_element(self, element_id):
        gen_get_element=self._get_elements_generator(element_id)
        try:
            s=gen_get_element.next()
            
            if s is None:
                raise Exception("gen_get_element salio con None in _get_element!!!")
            
            return s
        except StopIteration:
            pass
            
        return None

    def delete_element(self, element_id, multiple = False):
        header=self.get_header_as_string()
        elements=header[self.__HEADER_BASE_SIZE:]
        gen_tp=self._find_element(elements, element_id )
        found=False
        while True:
            (match,offset,length)=gen_tp.next()
            if match != 0:
                break
            start=self.__HEADER_BASE_SIZE+offset
            header=header[:start]+header[start+length:]
            found=True
            if multiple is False:
                break
            
        if not found:
            return  False
        
        self.load_header(header)
        return True
    
    def _set_element(self, element_id, value, replace = True):
        parameter=struct.pack('BB%ds'%len(value),element_id,len(value),value)
        
        header=self.get_header_as_string()
        elements=header[self.__HEADER_BASE_SIZE:]
        gen_tp=self._find_element(elements, element_id )
        found=False
        while True:
            (match,offset,length)=gen_tp.next()
            start=self.__HEADER_BASE_SIZE+offset
            if match == 0 and replace:
                # Replace
                header=header[:start]+parameter+header[start+length:]
                found=True
                break
            elif match > 0:
                # Add
                header=header[:start]+parameter+header[start:]
                found=True
                break
            else:
                break
        if not found:
            # Append (found<0 Not found)
            header=header+parameter        
        self.load_header(header)

class Dot11ManagementBeacon(Dot11ManagementHelper):
    '802.11 Management Beacon Frame'
        
    __HEADER_BASE_SIZE = 12 # minimal header size

    def __init__(self, aBuffer = None):
        header_size = self.__HEADER_BASE_SIZE
        tail_size = 0
        Dot11ManagementHelper.__init__(self, header_size, tail_size, aBuffer)

    def get_timestamp(self):
        'Return the 802.11 Management Beacon frame \'Timestamp\' field' 
        b = self.header.get_long_long(0, "<")
        return b 

    def set_timestamp(self, value):
        'Set the 802.11 Management Beacon frame \'Timestamp\' field' 
        # set the bits
        nb = value & 0xFFFFFFFFFFFFFFFF
        self.header.set_long_long(0, nb, "<")

    def get_beacon_interval(self):
        'Return the 802.11 Management Beacon frame \'Beacon Interval\' field' \
        'To convert it to seconds =>  secs = Beacon_Interval*1024/1000000'

        b = self.header.get_word(8, "<")
        return b 

    def set_beacon_interval(self, value):
        'Set the 802.11 Management Beacon frame \'Beacon Interval\' field' 
        # set the bits
        nb = value & 0xFFFF
        self.header.set_word(8, nb, "<")

    def get_capabilities(self):
        'Return the 802.11 Management Beacon frame \'Capability information\' field. '
        
        b = self.header.get_word(10, "<")
        return b 

    def set_capabilities(self, value):
        'Set the 802.11 Management Beacon frame \'Capability Information\' field' 
        # set the bits
        nb = value & 0xFFFF
        self.header.set_word(10, nb, "<")
        
    def get_ssid(self):
        "Get the 802.11 Management SSID element. "\
        "The SSID element indicates the identity of an ESS or IBSS."
        return self._get_element(DOT11_MANAGEMENT_ELEMENTS.SSID)

    def set_ssid(self, ssid):
        self._set_element(DOT11_MANAGEMENT_ELEMENTS.SSID,ssid)

    def get_supported_rates(self, human_readable=False):
        "Get the 802.11 Management Supported Rates element. "\
        "Specifies up to eight rates, then an Extended Supported Rate element "\
        "shall be generated to specify the remaining supported rates."\
        "If human_readable is True, the rates are returned in Mbit/sec"
        s=self._get_element(DOT11_MANAGEMENT_ELEMENTS.SUPPORTED_RATES)
        if s is None:
            return None
        
        rates=struct.unpack('%dB'%len(s),s)
        if not human_readable:
            return rates
            
        rates_Mbs=tuple(map(lambda x: (x&0x7F)*0.5,rates))
        return rates_Mbs

    def set_supported_rates(self, rates):
        "Set the 802.11 Management Supported Rates element. "\
        "Specifies a tuple or list with up to eight rates, then an "\
        "Extended Supported Rate element shall be generated to specify "\
        "the remaining supported rates."
        qty_rates=len(rates)
        if qty_rates>8:
            raise Exception("requires up to eight rates")
        rates_string=struct.pack('B'*qty_rates,*rates)
        self._set_element(DOT11_MANAGEMENT_ELEMENTS.SUPPORTED_RATES,rates_string)

    def get_ds_parameter_set(self):
        "Get the 802.11 Management DS Parameter set element. "\
        "Contains information to allow channel number identification for "\
        "STAs using a DSSS PHY."
        s=self._get_element(DOT11_MANAGEMENT_ELEMENTS.DS_PARAMETER_SET)
        if s is None:
            return None
        
        (ch,)=struct.unpack('B',s)

        return ch

    def set_ds_parameter_set(self, channel):
        "Set the 802.11 Management DS Parameter set element. "\
        "Contains information to allow channel number identification for "\
        "STAs using a DSSS PHY."
        channel_string=struct.pack('B',channel)
        self._set_element(DOT11_MANAGEMENT_ELEMENTS.DS_PARAMETER_SET,channel_string)

    def get_rsn(self):
        "Get the 802.11 Management Robust Security Network element."
        s = self._get_element(DOT11_MANAGEMENT_ELEMENTS.RSN)
        if s is None:
            return None
        return s

    def set_rsn(self, data):
        "Set the 802.11 Management Robust Security Network element."
        self._set_element(DOT11_MANAGEMENT_ELEMENTS.RSN, data)

    def get_erp(self):
        "Get the 802.11 Management ERP (extended rate PHY) Information element."
        s = self._get_element(DOT11_MANAGEMENT_ELEMENTS.ERP_INFO)
        if s is None:
            return None

        (erp,) = struct.unpack('B',s)
        
        return erp

    def set_erp(self, erp):
        "Set the 802.11 Management ERP (extended rate PHY) Inforamation "\
        "element."
        erp_string = struct.pack('B',erp)
        self._set_element(DOT11_MANAGEMENT_ELEMENTS.ERP_INFO, erp_string)

    def get_country(self):
        "Get the 802.11 Management Country element." \
        "Returns a tuple containing Country code, first channel number, "\
        "number of channels and maximum transmit power level"
        s = self._get_element(DOT11_MANAGEMENT_ELEMENTS.COUNTRY)
        if s is None:
            return None

        code, first, num, max = struct.unpack('3sBBB',s)
        code = code.strip(' ')
        return code, first, num, max

    def set_country(self, code, first_channel, number_of_channels, max_power):
        "Set the 802.11 Management Country element."
        if len(code) > 3:
            raise Exception("Country code must be up to 3 bytes long")

        #Padding the country code
        code += ' ' * (3-len(code))

        country_string = struct.pack('3sBBB', code, first_channel,
                number_of_channels, max_power)
        self._set_element(DOT11_MANAGEMENT_ELEMENTS.COUNTRY, country_string)

    def get_vendor_specific(self):
        "Get the 802.11 Management Vendor Specific elements "\
        "as a list of tuples."
        "The Vendor Specific information element is used to carry "\
        "information not defined in the standard within a single "\
        "defined format"
        
        vs=[]
        gen_get_element=self._get_elements_generator(DOT11_MANAGEMENT_ELEMENTS.VENDOR_SPECIFIC)
        try:
            while 1:
                s=gen_get_element.next()
                
                if s is None:
                    raise Exception("gen_get_element salio con None!!!")
                
                # OUI is 3 bytes
                oui=s[:3]
                data=s[3:]
                vs.append((oui,data))
        except StopIteration:
            pass
            
        return vs

    def add_vendor_specific(self, oui, data):
        "Set the 802.11 Management Vendor Specific element. "\
        "The Vendor Specific information element is used to carry "\
        "information not defined in the standard within a single "\
        "defined format"
        
        # 3 is the OUI length
        max_data_len=255-3
        data_len=len(data)

        if data_len>max_data_len:
            raise Exception("data allow up to %d bytes long" % max_data_len)
        if len(oui) > 3:
            raise Exception("oui is three bytes long")
        
        self._set_element(DOT11_MANAGEMENT_ELEMENTS.VENDOR_SPECIFIC,oui+data, replace=False)

class Dot11ManagementProbeRequest(Dot11ManagementHelper):
    '802.11 Management Probe Request Frame'
        
    def __init__(self, aBuffer = None):
        header_size = 0
        tail_size = 0
        Dot11ManagementHelper.__init__(self, header_size, tail_size, aBuffer)

    def get_ssid(self):
        "Get the 802.11 Management SSID element. "\
        "The SSID element indicates the identity of an ESS or IBSS."
        return self._get_element(DOT11_MANAGEMENT_ELEMENTS.SSID)

    def set_ssid(self, ssid):
        self._set_element(DOT11_MANAGEMENT_ELEMENTS.SSID,ssid)

    def get_supported_rates(self, human_readable=False):
        "Get the 802.11 Management Supported Rates element. "\
        "Specifies up to eight rates, then an Extended Supported Rate element "\
        "shall be generated to specify the remaining supported rates."\
        "If human_readable is True, the rates are returned in Mbit/sec"
        s=self._get_element(DOT11_MANAGEMENT_ELEMENTS.SUPPORTED_RATES)
        if s is None:
            return None
        
        rates=struct.unpack('%dB'%len(s),s)
        if not human_readable:
            return rates
            
        rates_Mbs=tuple(map(lambda x: (x&0x7F)*0.5,rates))
        return rates_Mbs

    def set_supported_rates(self, rates):
        "Set the 802.11 Management Supported Rates element. "\
        "Specifies a tuple or list with up to eight rates, then an "\
        "Extended Supported Rate element shall be generated to specify "\
        "the remaining supported rates."
        qty_rates=len(rates)
        if qty_rates>8:
            raise Exception("requires up to eight rates")
        rates_string=struct.pack('B'*qty_rates,*rates)
        self._set_element(DOT11_MANAGEMENT_ELEMENTS.SUPPORTED_RATES,rates_string)

class Dot11ManagementProbeResponse(Dot11ManagementBeacon):
    '802.11 Management Probe Response Frame'

    def __init__(self, aBuffer = None):
        Dot11ManagementBeacon.__init__(self, aBuffer)

class DOT11_REASON_CODES():
    # RESERVED                                         = 0
    UNSPECIFIED_REASON                                 = 1
    PREV_AUTH_NO_LONGER_VALID                          = 2
    DEAUTH_STA_IS_LEAVING                              = 3
    DISASS_DUE_TO_INACTIVITY                           = 4
    DISASS_AP_UNABLE_HANDLE_ALL_STA                    = 5
    C2_FRAME_FROM_NONAUTHENTICATED_STA                 = 6
    C3_FRAME_FROM_NONASSOCIATED_STA                    = 7
    DISSASS_STA_IS_LEAVING                             = 8
    STA_REQ_NOT_AUTH_STA                               = 9
    DISASS_POWER_CAP_IE_UNNACCEPTABLE                  = 10
    DISASS_SUP_CH_IE_UNNACCEPTABLE                     = 11
    # RESERVED                                         = 12
    INVALID_IE                                         = 13
    MIC_FAILURE                                        = 14
    FOUR_WAY_HANDSHAKE_TIMEOUT                         = 15
    GROUP_KEY_HANDSHAKE_TIMEOUT                        = 16
    IE_FOUR_WAY_HANDSHAKE_DIFFERENT                    = 17
    INVALID_GROUP_CIPHER                               = 18
    INVALID_PAIRWISE_CIPHER                            = 19
    INVALID_AKMP                                       = 20
    UNSUPPORTED_RSN_IE_VERSION                         = 21
    INVALID_RSN_IE_CAP                                 = 22
    X_AUTH_FAILED                                      = 23
    CIPHER_SUITE_REJECTED_SECURITY_POLICY              = 24
    # RESERVED                                         = 25 - 31
    DISASS_QOS_RELATED_REASON                          = 32
    DISASS_QOS_UNSUFFICIENT_BANDWIDTH                  = 33
    DISASS_EXCESSIVE_FRAMES_WITHOUT_ACK                = 34
    DISASS_STA_TX_OUTSIDE_TXOPS                        = 35
    REQ_STA_LEAVING                                    = 36
    REQ_STA_NOT_WANT_MECHANISM                         = 37
    REQ_STA_RECV_FRAMES_WHICH_SETUP_REQ                = 38
    REQ_STA_DUE_TIMEOUT                                = 39
    STA_NOT_SUPPORT_CIPHER_SUITE                       = 45
    # RESERVED                                         = 46 - 65 535

class Dot11ManagementDeauthentication(ProtocolPacket):
    '802.11 Management Deauthentication Frame'

    def __init__(self, aBuffer = None):
        header_size = 2
        tail_size = 0
        if aBuffer:
            ProtocolPacket.__init__(self, header_size, tail_size)
            self.load_packet(aBuffer)
        else:
            ProtocolPacket.__init__(self, header_size, tail_size)

    def get_reason_code(self):
        "Get the 802.11 Management Deauthentication or Disassociation Code."
        return self.header.get_word(0, "<")

    def set_reason_code(self, rc):
        self.header.set_word(0, rc, "<")

class DOT11_AUTH_ALGORITHMS():
    OPEN       = 0
    SHARED_KEY = 1

class DOT11_AUTH_STATUS_CODES():
    SUCCESSFUL                                         = 0
    UNSPECIFIED_FAILURE                                = 1
    # RESERVED                                         = 2 - 9
    CAP_REQ_UNSUPPORTED                                = 10
    REASS_DENIED_CANNOT_CONFIRM_ASS_EXISTS             = 11
    ASS_DENIED_REASON_OUTSIDE_SCOPE_STANDARD           = 12
    STA_NOT_SUPPORT_AUTH_ALGORITHM                     = 13
    AUTH_SEQ_OUT_OF_EXPECTED                           = 14
    AUTH_REJECTED_CHALLENGE_FAILURE                    = 15
    AUTH_REJECTED_TIMEOUT                              = 16
    ASS_DENIED_AP_UNABLE_HANDLE_MORE_STA               = 17
    ASS_DENIED_STA_NOT_SUPPORTING_DATA_RATES           = 18
    ASS_DENIED_STA_NOT_SUPPORTING_SHORT_PREAMBLE       = 19
    ASS_DENIED_STA_NOT_SUPPORTING_PBCC_MODULATION      = 20
    ASS_DENIED_STA_NOT_SUPPORTING_CHANNEL_AGILITY      = 21
    ASS_REQUEST_REJECTED_SPACTRUM_MGT_CAP              = 22
    ASS_REQUEST_REJECTED_POWER_CAP_IE_UNNACCEPTABLE    = 23
    ASS_REQUEST_REJECTED_SUP_CH_IE_UNNACCEPTABLE       = 24
    ASS_DENIED_STA_NOT_SUPPORTING_SHORT_SLOT_TIME      = 25
    ASS_DENIED_STA_NOT_SUPPORTING_DSSS_OFDM            = 26
    # RESERVED                                         = 27 - 31
    UNSPECIFIED_QOS                                    = 32
    ASS_DENIED_QOS_UNSUFFICIENT_BANDWIDTH              = 33
    ASS_DENIED_EXCESSIVE_FRAME_LOST                    = 34
    ASS_DENIED_STA_NOT_SUPPORT_QOS                     = 35
    # RESERVED                                         = 36
    REQ_HAS_BEEN_DECLINED                              = 37
    REQ_NOT_SUCCESSFUL_PARAM_INVALID_VALUE             = 38
    TSPEC                                              = 39
    INVALID_IE                                         = 40
    INVALID_GROUP_CIPHER                               = 41
    INVALID_PAIRWISE_CIPHER                            = 42
    INVALID_AKMP                                       = 43
    UNSUPPORTED_RSN_IE_VERSION                         = 44
    INVALID_RSN_IE_CAP                                 = 45
    CIPHER_SUITE_REJECTED_SECURITY_POLICY              = 46
    TS_NOT_CREATED                                     = 47
    DIRECT_LINK_NOT_ALLOWED_BSS_POLICY                 = 48
    DST_STA_NOT_PRESENT_IN_BSS                         = 49
    DST_STA_NOT_QOS_STA                                = 50
    ASS_DENIED_LISTEN_INTERVAL_TOO_LARGE               = 51
    # RESERVED                                         = 52 - 65 535

class Dot11ManagementAuthentication(Dot11ManagementHelper):
    '802.11 Management Authentication Frame'

    __HEADER_BASE_SIZE = 6 # minimal header size

    def __init__(self, aBuffer = None):
        header_size = self.__HEADER_BASE_SIZE
        tail_size = 0
        Dot11ManagementHelper.__init__(self, header_size, tail_size, aBuffer)

    def get_authentication_algorithm(self):
        "Get the 802.11 Management Authentication Algorithm."
        return self.header.get_word(0, "<")

    def set_authentication_algorithm(self, algorithm):
        "Set the 802.11 Management Authentication Algorithm."
        self.header.set_word(0, algorithm, "<")

    def get_authentication_sequence(self):
        "Get the 802.11 Management Authentication Sequence."
        return self.header.get_word(2, "<")

    def set_authentication_sequence(self, seq):
        "Set the 802.11 Management Authentication Sequence."
        self.header.set_word(2, seq, "<")

    def get_authentication_status(self):
        "Get the 802.11 Management Authentication Status."
        return self.header.get_word(4, "<")

    def set_authentication_status(self, status):
        "Set the 802.11 Management Authentication Status."
        self.header.set_word(4, status, "<")

    def get_challenge_text(self):
        return self._get_element(DOT11_MANAGEMENT_ELEMENTS.CHALLENGE_TEXT)

    def set_challenge_text(self, challenge):
        self._set_element(DOT11_MANAGEMENT_ELEMENTS.CHALLENGE_TEXT, challenge)

    def get_vendor_specific(self):
        "Get the 802.11 Management Vendor Specific elements "\
        "as a list of tuples."
        "The Vendor Specific information element is used to carry "\
        "information not defined in the standard within a single "\
        "defined format"
        
        vs=[]
        gen_get_element=self._get_elements_generator(DOT11_MANAGEMENT_ELEMENTS.VENDOR_SPECIFIC)
        try:
            while 1:
                s=gen_get_element.next()
                
                if s is None:
                    raise Exception("gen_get_element salio con None!!!")
                
                # OUI is 3 bytes
                oui=s[:3]
                data=s[3:]
                vs.append((oui,data))
        except StopIteration:
            pass
            
        return vs

    def add_vendor_specific(self, oui, data):
        "Set the 802.11 Management Vendor Specific element. "\
        "The Vendor Specific information element is used to carry "\
        "information not defined in the standard within a single "\
        "defined format"
        
        # 3 is the OUI length
        max_data_len=255-3
        data_len=len(data)

        if data_len>max_data_len:
            raise Exception("data allow up to %d bytes long" % max_data_len)
        if len(oui) > 3:
            raise Exception("oui is three bytes long")
        
        self._set_element(DOT11_MANAGEMENT_ELEMENTS.VENDOR_SPECIFIC,oui+data, replace=False)

class Dot11ManagementDisassociation(Dot11ManagementDeauthentication):
    '802.11 Management Disassociation Frame'

    def __init__(self, aBuffer = None):
        Dot11ManagementDeauthentication.__init__(self, aBuffer)

class Dot11ManagementAssociationRequest(Dot11ManagementHelper):
    '802.11 Management Association Request Frame'
        
    __HEADER_BASE_SIZE = 4 # minimal header size

    def __init__(self, aBuffer = None):
        header_size = self.__HEADER_BASE_SIZE
        tail_size = 0
        Dot11ManagementHelper.__init__(self, header_size, tail_size, aBuffer)

    def get_capabilities(self):
        'Return the 802.11 Management Association Request Frame \'Capability information\' field. '
        b = self.header.get_word(0, "<")
        return b 

    def set_capabilities(self, value):
        'Set the 802.11 Management Association Request Frame \'Capability Information\' field' 
        # set the bits
        nb = value & 0xFFFF
        self.header.set_word(0, nb, "<")
        
    def get_listen_interval(self):
        'Return the 802.11 Management Association Request Frame \'Listen Interval\' field. '
        b = self.header.get_word(2, "<")
        return b 

    def set_listen_interval(self, value):
        'Set the 802.11 Management Association Request Frame \'Listen Interval\' field' 
        self.header.set_word(2, value, "<")
        
    def get_ssid(self):
        "Get the 802.11 Management SSID element. "\
        "The SSID element indicates the identity of an ESS or IBSS."
        return self._get_element(DOT11_MANAGEMENT_ELEMENTS.SSID)

    def set_ssid(self, ssid):
        self._set_element(DOT11_MANAGEMENT_ELEMENTS.SSID,ssid)

    def get_supported_rates(self, human_readable=False):
        "Get the 802.11 Management Supported Rates element. "\
        "Specifies up to eight rates, then an Extended Supported Rate element "\
        "shall be generated to specify the remaining supported rates."\
        "If human_readable is True, the rates are returned in Mbit/sec"
        s=self._get_element(DOT11_MANAGEMENT_ELEMENTS.SUPPORTED_RATES)
        if s is None:
            return None
        
        rates=struct.unpack('%dB'%len(s),s)
        if not human_readable:
            return rates
            
        rates_Mbs=tuple(map(lambda x: (x&0x7F)*0.5,rates))
        return rates_Mbs

    def set_supported_rates(self, rates):
        "Set the 802.11 Management Supported Rates element. "\
        "Specifies a tuple or list with up to eight rates, then an "\
        "Extended Supported Rate element shall be generated to specify "\
        "the remaining supported rates."
        qty_rates=len(rates)
        if qty_rates>8:
            raise Exception("requires up to eight rates")
        rates_string=struct.pack('B'*qty_rates,*rates)
        self._set_element(DOT11_MANAGEMENT_ELEMENTS.SUPPORTED_RATES,rates_string)

    def get_rsn(self):
        "Get the 802.11 Management Robust Security Network element."
        s = self._get_element(DOT11_MANAGEMENT_ELEMENTS.RSN)
        if s is None:
            return None
        return s

    def set_rsn(self, data):
        "Set the 802.11 Management Robust Security Network element."
        self._set_element(DOT11_MANAGEMENT_ELEMENTS.RSN, data)

    def get_vendor_specific(self):
        "Get the 802.11 Management Vendor Specific elements "\
        "as a list of tuples."
        "The Vendor Specific information element is used to carry "\
        "information not defined in the standard within a single "\
        "defined format"
        
        vs=[]
        gen_get_element=self._get_elements_generator(DOT11_MANAGEMENT_ELEMENTS.VENDOR_SPECIFIC)
        try:
            while 1:
                s=gen_get_element.next()
                
                if s is None:
                    raise Exception("gen_get_element salio con None!!!")
                
                # OUI is 3 bytes
                oui=s[:3]
                data=s[3:]
                vs.append((oui,data))
        except StopIteration:
            pass
            
        return vs

    def add_vendor_specific(self, oui, data):
        "Set the 802.11 Management Vendor Specific element. "\
        "The Vendor Specific information element is used to carry "\
        "information not defined in the standard within a single "\
        "defined format"
        
        # 3 is the OUI length
        max_data_len=255-3
        data_len=len(data)

        if data_len>max_data_len:
            raise Exception("data allow up to %d bytes long" % max_data_len)
        if len(oui) > 3:
            raise Exception("oui is three bytes long")
        
        self._set_element(DOT11_MANAGEMENT_ELEMENTS.VENDOR_SPECIFIC,oui+data, replace=False)

class Dot11ManagementAssociationResponse(Dot11ManagementHelper):
    '802.11 Management Association Response Frame'
        
    __HEADER_BASE_SIZE = 6 # minimal header size

    def __init__(self, aBuffer = None):
        header_size = self.__HEADER_BASE_SIZE
        tail_size = 0
        Dot11ManagementHelper.__init__(self, header_size, tail_size, aBuffer)

    def get_capabilities(self):
        'Return the 802.11 Management Association Response Frame \'Capability information\' field. '
        b = self.header.get_word(0, "<")
        return b 

    def set_capabilities(self, value):
        'Set the 802.11 Management Association Response Frame \'Capability Information\' field' 
        # set the bits
        nb = value & 0xFFFF
        self.header.set_word(0, nb, "<")
        
    def get_status_code(self):
        'Return the 802.11 Management Association Response Frame \'Status Code\' field. '
        b = self.header.get_word(2, "<")
        return b 

    def set_status_code(self, value):
        'Set the 802.11 Management Association Response Frame \'Status Code\' field' 
        self.header.set_word(2, value, "<")

    def get_association_id(self):
        'Return the 802.11 Management Association Response Frame \'Association Id\' field. '
        b = self.header.get_word(4, "<")
        return b 

    def set_association_id(self, value):
        'Set the 802.11 Management Association Response Frame \'Association Id\' field' 
        self.header.set_word(4, value, "<")

    def get_supported_rates(self, human_readable=False):
        "Get the 802.11 Management Supported Rates element. "\
        "Specifies up to eight rates, then an Extended Supported Rate element "\
        "shall be generated to specify the remaining supported rates."\
        "If human_readable is True, the rates are returned in Mbit/sec"
        s=self._get_element(DOT11_MANAGEMENT_ELEMENTS.SUPPORTED_RATES)
        if s is None:
            return None
        
        rates=struct.unpack('%dB'%len(s),s)
        if not human_readable:
            return rates
            
        rates_Mbs=tuple(map(lambda x: (x&0x7F)*0.5,rates))
        return rates_Mbs

    def set_supported_rates(self, rates):
        "Set the 802.11 Management Supported Rates element. "\
        "Specifies a tuple or list with up to eight rates, then an "\
        "Extended Supported Rate element shall be generated to specify "\
        "the remaining supported rates."
        qty_rates=len(rates)
        if qty_rates>8:
            raise Exception("requires up to eight rates")
        rates_string=struct.pack('B'*qty_rates,*rates)
        self._set_element(DOT11_MANAGEMENT_ELEMENTS.SUPPORTED_RATES,rates_string)

    def get_vendor_specific(self):
        "Get the 802.11 Management Vendor Specific elements "\
        "as a list of tuples."
        "The Vendor Specific information element is used to carry "\
        "information not defined in the standard within a single "\
        "defined format"
        
        vs=[]
        gen_get_element=self._get_elements_generator(DOT11_MANAGEMENT_ELEMENTS.VENDOR_SPECIFIC)
        try:
            while 1:
                s=gen_get_element.next()
                
                if s is None:
                    raise Exception("gen_get_element salio con None!!!")
                
                # OUI is 3 bytes
                oui=s[:3]
                data=s[3:]
                vs.append((oui,data))
        except StopIteration:
            pass
            
        return vs

    def add_vendor_specific(self, oui, data):
        "Set the 802.11 Management Vendor Specific element. "\
        "The Vendor Specific information element is used to carry "\
        "information not defined in the standard within a single "\
        "defined format"
        
        # 3 is the OUI length
        max_data_len=255-3
        data_len=len(data)
        if data_len>max_data_len:
            raise Exception("data allow up to %d bytes long" % max_data_len)
        if len(oui) > 3:
            raise Exception("oui is three bytes long")
        
        self._set_element(DOT11_MANAGEMENT_ELEMENTS.VENDOR_SPECIFIC,oui+data, replace=False)

class Dot11ManagementReassociationRequest(Dot11ManagementHelper):
    '802.11 Management Reassociation Request Frame'
        
    __HEADER_BASE_SIZE = 10 # minimal header size

    def __init__(self, aBuffer = None):
        header_size = self.__HEADER_BASE_SIZE
        tail_size = 0
        Dot11ManagementHelper.__init__(self, header_size, tail_size, aBuffer)

    def get_capabilities(self):
        'Return the 802.11 Management Reassociation Request Frame \'Capability information\' field. '
        b = self.header.get_word(0, "<")
        return b 

    def set_capabilities(self, value):
        'Set the 802.11 Management Reassociation Request Frame \'Capability Information\' field' 
        # set the bits
        nb = value & 0xFFFF
        self.header.set_word(0, nb, "<")

    def get_listen_interval(self):
        'Return the 802.11 Management Reassociation Request Frame \'Listen Interval\' field. '
        b = self.header.get_word(2, "<")
        return b 

    def set_listen_interval(self, value):
        'Set the 802.11 Management Reassociation Request Frame \'Listen Interval\' field' 
        self.header.set_word(2, value, "<")

    def get_current_ap(self):
        'Return the 802.11 Management Reassociation Request Frame \'Current AP\' field.'
        return self.header.get_bytes()[4:10]

    def set_current_ap(self, value):
        'Set the 802.11 Management Reassociation Request Frame \'Current AP\' field'
        for i in range(0, 6):
            self.header.set_byte(4+i, value[i])

    def get_ssid(self):
        "Get the 802.11 Management SSID element. "\
        "The SSID element indicates the identity of an ESS or IBSS."
        return self._get_element(DOT11_MANAGEMENT_ELEMENTS.SSID)

    def set_ssid(self, ssid):
        self._set_element(DOT11_MANAGEMENT_ELEMENTS.SSID,ssid)

    def get_supported_rates(self, human_readable=False):
        "Get the 802.11 Management Supported Rates element. "\
        "Specifies up to eight rates, then an Extended Supported Rate element "\
        "shall be generated to specify the remaining supported rates."\
        "If human_readable is True, the rates are returned in Mbit/sec"
        s=self._get_element(DOT11_MANAGEMENT_ELEMENTS.SUPPORTED_RATES)
        if s is None:
            return None
        
        rates=struct.unpack('%dB'%len(s),s)
        if not human_readable:
            return rates
            
        rates_Mbs=tuple(map(lambda x: (x&0x7F)*0.5,rates))
        return rates_Mbs

    def set_supported_rates(self, rates):
        "Set the 802.11 Management Supported Rates element. "\
        "Specifies a tuple or list with up to eight rates, then an "\
        "Extended Supported Rate element shall be generated to specify "\
        "the remaining supported rates."
        qty_rates=len(rates)
        if qty_rates>8:
            raise Exception("requires up to eight rates")
        rates_string=struct.pack('B'*qty_rates,*rates)
        self._set_element(DOT11_MANAGEMENT_ELEMENTS.SUPPORTED_RATES,rates_string)

    def get_rsn(self):
        "Get the 802.11 Management Robust Security Network element."
        s = self._get_element(DOT11_MANAGEMENT_ELEMENTS.RSN)
        if s is None:
            return None
        return s

    def set_rsn(self, data):
        "Set the 802.11 Management Robust Security Network element."
        self._set_element(DOT11_MANAGEMENT_ELEMENTS.RSN, data)

    def get_vendor_specific(self):
        "Get the 802.11 Management Vendor Specific elements "\
        "as a list of tuples."
        "The Vendor Specific information element is used to carry "\
        "information not defined in the standard within a single "\
        "defined format"
        
        vs=[]
        gen_get_element=self._get_elements_generator(DOT11_MANAGEMENT_ELEMENTS.VENDOR_SPECIFIC)
        try:
            while 1:
                s=gen_get_element.next()
                
                if s is None:
                    raise Exception("gen_get_element salio con None!!!")
                
                # OUI is 3 bytes
                oui=s[:3]
                data=s[3:]
                vs.append((oui,data))
        except StopIteration:
            pass
            
        return vs

    def add_vendor_specific(self, oui, data):
        "Set the 802.11 Management Vendor Specific element. "\
        "The Vendor Specific information element is used to carry "\
        "information not defined in the standard within a single "\
        "defined format"
        
        # 3 is the OUI length
        max_data_len=255-3
        data_len=len(data)

        if data_len>max_data_len:
            raise Exception("data allow up to %d bytes long" % max_data_len)
        if len(oui) > 3:
            raise Exception("oui is three bytes long")
        
        self._set_element(DOT11_MANAGEMENT_ELEMENTS.VENDOR_SPECIFIC,oui+data, replace=False)

class Dot11ManagementReassociationResponse(Dot11ManagementAssociationResponse):
    '802.11 Management Reassociation Response Frame'

    def __init__(self, aBuffer = None):
        Dot11ManagementAssociationResponse.__init__(self, aBuffer)
