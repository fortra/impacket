# Copyright (c) 2003-2016 CORE Security Technologies
#
# This software is provided under under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Description:
#  WPS packets
#
# Author:
# Aureliano Calvo


import array
import struct

from impacket.helper import ProtocolPacket, Byte, Bit


class ArrayBuilder(object):

    def from_ary(self, ary):
        return ary

    def to_ary(self, value):
        return array.array("B", value)
    
class ByteBuilder(object):

    def from_ary(self, ary):
        return ary[0]
    
    def to_ary(self, value):
        return array.array('B', [value])
    
class StringBuilder(object):
    def from_ary(self, ary):
        return ary.tostring()
        
    def to_ary(self, value):
        return array.array('B', value)
    
class NumBuilder(object):
    """Converts back and forth between arrays and numbers in network byte-order"""
    
    def __init__(self, size):
        """size: number of bytes in the field"""
        self.size = size
    
    def from_ary(self, ary):
        if len(ary) != self.size:
            raise Exception("Expected %s size but got %s" % (self.size, len(ary)))
        return reduce( lambda ac, x: ac * 256 + x, ary, 0)
    
    def to_ary(self, value0):
        value = value0
        rv = array.array('B')
        for _ in xrange(self.size):
            value, mod = divmod(value, 256)
            rv.append(mod)
            
        if value != 0:
            raise Exception("%s is too big. Max size: %s" % (value0, self.size))
            
        rv.reverse()
        return rv
    
class TLVContainer(object):
    
    def builder(self, kind):
        return self.builders.get(kind, self.default_builder)
    
    def from_ary(self, ary):
        i = 0
        while i<len(ary):
            kind = self.ary2n(ary, i)
            length = self.ary2n(ary, i+2)
            i+=4
            value = ary[i:i+length]
            self.elems.append((kind, value))
            i += length
            
        return self
                
    def __init__(self, builders, default_builder = ArrayBuilder(), descs=None):
        self.builders = builders
        self.default_builder = default_builder
        self.elems = []
        self.descs = descs or {}
        
    def append(self, kind, value):
        self.elems.append((kind, self.builder(kind).to_ary(value)))
    
    def __iter__(self):
        return ((k, self.builder(k).from_ary(v)) for k,v in self.elems)
    
    def all(self, kind):
        return [e[1] for e in self if e[0] == kind]
    
    def __contains__(self, kind):
        return len(self.all(kind)) != 0
    
    def first(self, kind):
        return self.all(kind)[0]
    
    def to_ary(self):
        ary = array.array('B')
        for k,v in self.elems:
            ary.extend(self.n2ary(k))
            ary.extend(self.n2ary(len(v)))
            ary.extend(v)
            
        return ary

    
    def get_packet(self):
        return self.to_ary().tostring()
    
    def set_parent(self, my_parent):
        self.__parent = my_parent
        
    def parent(self):
        return self.__parent
    
    def n2ary(self, n):
        return array.array("B", struct.pack(">H",n))
    
    def ary2n(self, ary, i=0):
        return struct.unpack(">H", ary[i:i+2].tostring())[0]
    
    def __repr__(self):
        def desc(kind):
            return self.descs[kind] if kind in self.descs else kind
        
        return "<TLVContainer %s>" % repr([(desc(k), self.builder(k).from_ary(v)) for (k,v) in self.elems])
    
    def child(self):
        return None

class SCElem(object):    
    #Data elements as defined in section 11 of the WPS 1.0h spec.
    
    AP_CHANNEL = 0x1001
    ASSOCIATION_STATE = 0x1002
    AUTHENTICATION_TYPE = 0x1003
    AUTHENTICATION_TYPE_FLAGS = 0x1004
    AUTHENTICATOR = 0x1005
    CONFIG_METHODS = 0x1008
    CONFIGURATION_ERROR = 0x1009
    CONFIRMATION_URL4 = 0x100A
    CONFIRMATION_URL6 = 0x100B
    CONNECTION_TYPE = 0X100C
    CONNECTION_TYPE_FLAGS = 0X100D
    CREDENTIAL = 0X100E 
    DEVICE_NAME = 0x1011
    DEVICE_PASSWORD_ID = 0x1012
    E_HASH1 = 0x1014
    E_HASH2 = 0x1015
    E_SNONCE1 = 0x1016
    E_SNONCE2 = 0x1017
    ENCRYPTED_SETTINGS = 0x1018 
    ENCRYPTION_TYPE = 0X100F
    ENCRYPTION_TYPE_FLAGS = 0x1010
    ENROLLEE_NONCE = 0x101A
    FEATURE_ID = 0x101B
    IDENTITY = 0X101C
    INDENTITY_PROOF = 0X101D 
    KEY_WRAP_AUTHENTICATOR = 0x101E
    KEY_IDENTIFIER = 0X101F
    MAC_ADDRESS = 0x1020
    MANUFACTURER = 0x1021
    MESSAGE_TYPE = 0x1022
    MODEL_NAME = 0x1023
    MODEL_NUMBER = 0x1024
    NETWORK_INDEX = 0x1026
    NETWORK_KEY = 0x1027
    NETWORK_KEY_INDEX = 0x1028
    NEW_DEVICE_NAME = 0x1029
    NEW_PASSWORD = 0x102A
    OOB_DEVICE_PASSWORD = 0X102C
    OS_VERSION= 0X102D
    POWER_LEVEL = 0X102F
    PSK_CURRENT = 0x1030
    PSK_MAX = 0x1031
    PUBLIC_KEY = 0x1032
    RADIO_ENABLED = 0x1033
    REBOOT = 0x1034
    REGISTRAR_CURRENT = 0x1035
    REGISTRAR_ESTABLISHED = 0x1036
    REGISTRAR_LIST = 0x1037
    REGISTRAR_MAX = 0x1038
    REGISTRAR_NONCE = 0x1039
    REQUEST_TYPE = 0x103A
    RESPONSE_TYPE = 0x103B
    RF_BANDS = 0X103C
    R_HASH1 = 0X103D
    R_HASH2 = 0X103E
    R_SNONCE1 = 0X103F
    R_SNONCE2 = 0x1040
    SELECTED_REGISTRAR = 0x1041
    SERIAL_NUMBER = 0x1042
    WPS_STATE = 0x1044
    SSID = 0x1045
    TOTAL_NETWORKS = 0x1046
    UUID_E = 0x1047
    UUID_R = 0x1048
    VENDOR_EXTENSION = 0x1049
    VERSION = 0x104A
    X_509_CERTIFICATE_REQUEST = 0x104B 
    X_509_CERTIFICATE = 0x104C
    EAP_IDENTITY = 0x104D
    MESSAGE_COUNTER = 0x104E
    PUBLIC_KEY_HASH = 0x104F
    REKEY_KEY = 0x1050
    KEY_LIFETIME = 0x1051
    PERMITTED_CONFIG_METHODS = 0x1052
    SELECTED_REGISTRAR_CONFIG_METHODS= 0x1053
    PRIMARY_DEVICE_TYPE = 0x1054
    SECONDARY_DEVICE_TYPE_LIST = 0x1055
    PORTABLE_DEVICE = 0x1056
    AP_SETUP_LOCKED = 0x1057
    APPLICATION_EXTENSION = 0x1058
    EAP_TYPE = 0x1059
    INITIALIZATION_VECTOR = 0x1060
    KEY_PROVIDED_AUTOMATICALLY = 0x1061
    _802_1X_ENABLED = 0x1062
    APP_SESSION_KEY = 0x1063
    WEP_TRANSMIT_KEY = 0x1064
    
class MessageType(object):
    """Message types according to WPS 1.0h spec, section 11"""
    
    BEACON = 0x01
    PROBE_REQUEST = 0x02
    PROBE_RESPONSE = 0x03
    M1 = 0x04
    M2 = 0x05
    M2D = 0x06
    M3 = 0x07
    M4 = 0x08
    M5 = 0x09
    M6 = 0x0A
    M7 = 0x0B
    M8 = 0x0C
    WSC_ACK = 0x0D
    WSC_NACK = 0x0E
    WSC_DONE = 0x0F
    
class AuthTypeFlag(object):
    OPEN = 0x0001
    WPAPSK = 0x0002
    SHARED = 0x0004
    WPA = 0x0008
    WPA2 = 0x0010
    WPA2PSK = 0x0020
    
AuthTypeFlag_ALL = AuthTypeFlag.OPEN | \
        AuthTypeFlag.WPAPSK | \
        AuthTypeFlag.SHARED | \
        AuthTypeFlag.WPA | \
        AuthTypeFlag.WPA2 | \
        AuthTypeFlag.WPA2PSK
        
class EncryptionTypeFlag(object):
    NONE = 0x0001
    WEP = 0x0002
    TKIP = 0x0004
    AES = 0x0008
    
EncryptionTypeFlag_ALL = EncryptionTypeFlag.NONE | EncryptionTypeFlag.WEP | EncryptionTypeFlag.TKIP | EncryptionTypeFlag.AES

class ConnectionTypeFlag(object):
    ESS = 0x01
    IBSS = 0x02
    
class ConfigMethod(object):
    USBA = 0x0001
    ETHERNET = 0x0002
    LABEL = 0x0004
    DISPLAY = 0x0008
    EXT_NFC_TOKEN = 0x0010
    INT_NFC_TOKEN = 0x0020
    NFC_INTERFACE = 0x0040
    PUSHBUTTON = 0x0080
    KEYPAD = 0x0100
    
    
class OpCode(object):
    WSC_START = 0x01
    WSC_ACK = 0x02
    WSC_NACK = 0x03
    WSC_MSG = 0x04
    WSC_DONE = 0x05
    WSC_FRAG_ACK = 0x06
    
class AssocState(object):
    NOT_ASSOC = 0
    CONN_SUCCESS = 1
    CFG_FAILURE = 2
    FAILURE = 3,
    IP_FAILURE = 4
    
class ConfigError(object):
    NO_ERROR = 0
    OOB_IFACE_READ_ERROR = 1
    DECRYPTION_CRC_FAILURE = 2
    _24_CHAN_NOT_SUPPORTED = 3
    _50_CHAN_NOT_SUPPORTED = 4
    SIGNAL_TOO_WEAK = 5
    NETWORK_AUTH_FAILURE = 6
    NETWORK_ASSOC_FAILURE = 7
    NO_DHCP_RESPONSE = 8
    FAILED_DHCP_CONFIG = 9
    IP_ADDR_CONFLICT = 10
    NO_CONN_TO_REGISTRAR = 11
    MULTIPLE_PBC_DETECTED = 12
    ROGUE_SUSPECTED = 13
    DEVICE_BUSY = 14
    SETUP_LOCKED = 15
    MSG_TIMEOUT = 16
    REG_SESS_TIMEOUT = 17
    DEV_PASSWORD_AUTH_FAILURE = 18
    
class DevicePasswordId(object):
    DEFAULT = 0x0000
    USER_SPECIFIED = 0x0001
    MACHINE_SPECIFIED = 0x0002
    REKEY = 0x0003
    PUSHBUTTON = 0x0004
    REGISTRAR_SPECIFIED = 0x0005
    
class WpsState(object):
    NOT_CONFIGURED = 0x01
    CONFIGURED = 0x02
    

class SimpleConfig(ProtocolPacket):
    "For now, it supports Simple configs with the bits more_fragments and length_field not set"
    
    header_size = 2
    tail_size = 0

    op_code = Byte(0)
    flags = Byte(1)
    more_fragments = Bit(1, 0)
    length_field = Bit(1,1)
    
    BUILDERS = {
        SCElem.CONNECTION_TYPE: ByteBuilder(),
        SCElem.CONNECTION_TYPE_FLAGS: ByteBuilder(),
        SCElem.VERSION: ByteBuilder(),
        SCElem.MESSAGE_TYPE: ByteBuilder(),
        SCElem.NETWORK_INDEX: ByteBuilder(),
        SCElem.NETWORK_KEY_INDEX: ByteBuilder(),
        SCElem.POWER_LEVEL: ByteBuilder(),
        SCElem.PSK_CURRENT: ByteBuilder(),
        SCElem.PSK_MAX: ByteBuilder(),
        SCElem.REGISTRAR_CURRENT: ByteBuilder(),
        SCElem.REGISTRAR_MAX: ByteBuilder(),
        SCElem.REQUEST_TYPE: ByteBuilder(),
        SCElem.RESPONSE_TYPE: ByteBuilder(),
        SCElem.RF_BANDS: ByteBuilder(),
        SCElem.WPS_STATE: ByteBuilder(),
        SCElem.TOTAL_NETWORKS: ByteBuilder(),
        SCElem.VERSION: ByteBuilder(),
        SCElem.WEP_TRANSMIT_KEY: ByteBuilder(),
        
        SCElem.CONFIRMATION_URL4: StringBuilder(),
        SCElem.CONFIRMATION_URL6: StringBuilder(),
        SCElem.DEVICE_NAME: StringBuilder(),
        SCElem.IDENTITY: StringBuilder(),
        SCElem.MANUFACTURER: StringBuilder(),
        SCElem.MODEL_NAME: StringBuilder(),
        SCElem.MODEL_NUMBER: StringBuilder(),
        SCElem.NEW_DEVICE_NAME: StringBuilder(),
        SCElem.NEW_PASSWORD: StringBuilder(),
        SCElem.SERIAL_NUMBER: StringBuilder(),
        SCElem.EAP_IDENTITY: StringBuilder(),
        SCElem.NETWORK_KEY: StringBuilder(),
            
        SCElem.AP_CHANNEL: NumBuilder(2),
        SCElem.ASSOCIATION_STATE: NumBuilder(2),
        SCElem.AUTHENTICATION_TYPE: NumBuilder(2),
        SCElem.AUTHENTICATION_TYPE_FLAGS: NumBuilder(2),
        SCElem.CONFIG_METHODS: NumBuilder(2),
        SCElem.CONFIGURATION_ERROR: NumBuilder(2),
        SCElem.DEVICE_PASSWORD_ID: NumBuilder(2),
        SCElem.ENCRYPTION_TYPE: NumBuilder(2),
        SCElem.ENCRYPTION_TYPE_FLAGS: NumBuilder(2),
        SCElem.MESSAGE_COUNTER: NumBuilder(8),       
        SCElem.KEY_LIFETIME: NumBuilder(4),
        SCElem.PERMITTED_CONFIG_METHODS: NumBuilder(2),
        SCElem.SELECTED_REGISTRAR_CONFIG_METHODS: NumBuilder(2),
        SCElem.PUBLIC_KEY: NumBuilder(192),

    }
    
    @classmethod
    def build_tlv_container(cls):
        return TLVContainer(
            builders=SimpleConfig.BUILDERS, 
            descs = dict( (v,k) for (k,v) in SCElem.__dict__.iteritems() )
        )
    
