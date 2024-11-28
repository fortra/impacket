# Impacket - Collection of Python classes for working with network protocols.
#
# Copyright Fortra, LLC and its affiliated companies 
#
# All rights reserved.
#
# This software is provided under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Description:
#   [MS-TSTS] Terminal Services Terminal Server Runtime Interface Protocol implementation
# 
# Interface Implementation based on:
#   [MS-TSTS] - v20210625: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-tsts/
#   [MS-TSTS] – v20080207: https://docplayer.net/22134151-Ms-tsts-terminal-services-terminal-server-runtime-interface-protocol-specification.html
# 
#   Some RPC Calls are marked with #COMMENT_LIKE tags with following meaning:
#       #NOT_IMPLEMENTED : RPC Call or Structure is not implemented in current revision.
#       #DOES_NOT_WORK   : I was unable to acheive documented response or properly construct RPC request.
#       #OLD             : RPC Call was taken from [MS-TSTS] – v20080207 documentation, which might be deprecated.
# 
#   Some not implemented RPC Calls and structures contains with multi-line comments for future work
# 
# Author:
#   Alexander Korznikov (@nopernik) https://korznikov.com
#

import struct
from datetime import datetime
from ldap3.protocol.formatters.formatters import format_sid

from impacket.dcerpc.v5 import transport
from impacket.uuid import uuidtup_to_bin, bin_to_string, string_to_bin
from impacket.dcerpc.v5.ndr import NDR, NDRCALL, NDRSTRUCT, NDRENUM, NDRUNION, NDRUniConformantArray, \
    NDRPOINTER, NDRUniConformantVaryingArray, UNKNOWNDATA
from impacket.dcerpc.v5.dtypes import NULL, BOOL, BOOLEAN, STR, WSTR, LPWSTR, WIDESTR, RPC_UNICODE_STRING, \
    LONG, UINT, ULONG, PULONG, LPDWORD, LARGE_INTEGER, DWORD, NDRHYPER, USHORT, UCHAR, PCHAR, BYTE, PBYTE, \
    UUID, GUID
from impacket import system_errors
from impacket.dcerpc.v5.enum import Enum
from impacket.dcerpc.v5.rpcrt import DCERPCException, RPC_C_AUTHN_GSS_NEGOTIATE, RPC_C_AUTHN_LEVEL_PKT_PRIVACY

################################################################################
# Constants
################################################################################

TermSrvSession_UUID      = uuidtup_to_bin(('484809d6-4239-471b-b5bc-61df8c23ac48','1.0'))
TermSrvNotification_UUID = uuidtup_to_bin(('11899a43-2b68-4a76-92e3-a3d6ad8c26ce','1.0'))
TermSrvEnumeration_UUID  = uuidtup_to_bin(('88143fd0-c28d-4b2b-8fef-8d882f6a9390','1.0'))
RCMPublic_UUID           = uuidtup_to_bin(('bde95fdf-eee0-45de-9e12-e5a61cd0d4fe','1.0'))
RcmListener_UUID         = uuidtup_to_bin(('497d95a6-2d27-4bf5-9bbd-a6046957133c','1.0'))
LegacyAPI_UUID           = uuidtup_to_bin(('5ca4a760-ebb1-11cf-8611-00a0245420ed','1.0'))

AUDIODRIVENAME_LENGTH                = 9
WDPREFIX_LENGTH                      = 12
STACK_ADDRESS_LENGTH                 = 128
MAX_BR_NAME                          = 65
DIRECTORY_LENGTH                     = 256
INITIALPROGRAM_LENGTH                = 256
USERNAME_LENGTH                      = 20
DOMAIN_LENGTH                        = 17
PASSWORD_LENGTH                      = 14
NASISPECIFICNAME_LENGTH              = 14
NASIUSERNAME_LENGTH                  = 47
NASIPASSWORD_LENGTH                  = 24
NASISESSIONNAME_LENGTH               = 16
NASIFILESERVER_LENGTH                = 47
CLIENTDATANAME_LENGTH                = 7
CLIENTNAME_LENGTH                    = 20
CLIENTADDRESS_LENGTH                 = 30
IMEFILENAME_LENGTH                   = 32
DIRECTORY_LENGTH                     = 256
CLIENTLICENSE_LENGTH                 = 32
CLIENTMODEM_LENGTH                   = 40
CLIENT_PRODUCT_ID_LENGTH             = 32
MAX_COUNTER_EXTENSIONS               = 2
WINSTATIONNAME_LENGTH                = 32
PROTOCOL_CONSOLE                     = 0
PROTOCOL_ICA                         = 1
PROTOCOL_TSHARE                      = 2
PROTOCOL_RDP                         = 2
PDNAME_LENGTH                        = 32
WDNAME_LENGTH                        = 32
CDNAME_LENGTH                        = 32
DEVICENAME_LENGTH                    = 128
MODEMNAME_LENGTH                     = DEVICENAME_LENGTH
CALLBACK_LENGTH                      = 50
DLLNAME_LENGTH                       = 32
WINSTATIONCOMMENT_LENGTH             = 60
MAX_LICENSE_SERVER_LENGTH            = 1024
LOGONID_CURRENT                      = ULONG
MAX_PDCONFIG                         = 10
TERMSRV_TOTAL_SESSIONS               = 1
TERMSRV_DISC_SESSIONS                = 2
TERMSRV_RECON_SESSIONS               = 3
TERMSRV_CURRENT_ACTIVE_SESSIONS      = 4
TERMSRV_CURRENT_DISC_SESSIONS        = 5
TERMSRV_PENDING_SESSIONS             = 6
TERMSRV_SUCC_TOTAL_LOGONS            = 7
TERMSRV_SUCC_LOCAL_LOGONS            = 8
TERMSRV_SUCC_REMOTE_LOGONS           = 9
TERMSRV_SUCC_SESSION0_LOGONS         = 10
TERMSRV_CURRENT_TERMINATING_SESSIONS = 11
TERMSRV_CURRENT_LOGGEDON_SESSIONS    = 12
NO_FALLBACK_DRIVERS                  = 0x0
FALLBACK_BESTGUESS                   = 0x1
FALLBACK_PCL                         = 0x2
FALLBACK_PS                          = 0x3
FALLBACK_PCLANDPS                    = 0x4
VIRTUALCHANNELNAME_LENGTH            = 7

WINSTATION_QUERY        = 0x00000001    # WinStationQueryInformation() 
WINSTATION_SET          = 0x00000002    # WinStationSetInformation() 
WINSTATION_RESET        = 0x00000004    # WinStationReset() 
WINSTATION_VIRTUAL      = 0x00000008    # read/write direct data 
WINSTATION_SHADOW       = 0x00000010    # WinStationShadow() 
WINSTATION_LOGON        = 0x00000020    # logon to WinStation 
WINSTATION_LOGOFF       = 0x00000040    # WinStationLogoff() 
WINSTATION_MSG          = 0x00000080    # WinStationMsg() 
WINSTATION_CONNECT      = 0x00000100    # WinStationConnect() 
WINSTATION_DISCONNECT   = 0x00000200    # WinStationDisconnect() 


################################################################################
# Types
################################################################################

_NDRENUM = NDRENUM
class NDRENUM(_NDRENUM):
    def dump(self, msg = None, indent = 0):
        if msg is None:
            msg = self.__class__.__name__
        if msg != '':
            print(msg, end=' ')

        try:
            print(" %s" % self.enumItems(self.fields['Data']).name, end=' ')
        except:
            print(" %s" % hex(self.fields['Data']), end=' ')

class TS_WCHAR(WSTR):
    commonHdr = (
        ('ActualCount','<L=len(Data)//2'),
    )
    commonHdr64 = (
        ('ActualCount','<Q=len(Data)//2'),
    )
    structure = (
        ('Data',':'),
    )
    def __getitem__(self, key):
        if key == 'Data':
            return self.fields[key].decode('utf-16le')
        else:
            return NDR.__getitem__(self,key)

class TS_LPWCHAR(NDRPOINTER):
    referent = (
        ('Data', TS_WCHAR),
    )

class TS_CHAR(STR):
    commonHdr = (
        ('ActualCount','<L=len(Data)'),
    )
    commonHdr64 = (
        ('ActualCount','<Q=len(Data)'),
    )
    structure = (
        ('Data',':'),
    )
    def __getitem__(self, key):
        if key == 'Data':
            return self.fields[key]
        else:
            return NDR.__getitem__(self,key)

class SYSTEM_TIMESTAMP(NDRHYPER):
    def __getitem__(self, key):
        if key == 'Data':
            return datetime.fromtimestamp(getUnixTime(int(str(self.fields[key]))))
        else:
            return NDR.__getitem__(self,key)


# 2.2.2.15.1.1 TS_UNICODE_STRING
class TS_UNICODE_STRING(NDRSTRUCT):
    '''
    typedef struct _TS_UNICODE_STRING {
        USHORT Length;
        USHORT MaximumLength;
        #ifdef __midl
            [size_is(MaximumLength),length_is(Length)]PWSTR Buffer;
        #else
            PWSTR Buffer;
        #endif
    } TS_UNICODE_STRING;
    '''
    structure = (
        ('Length', USHORT),
        ('MaximumLength', USHORT),
        ('Buffer', LPWSTR),
    )

class TS_LPCHAR(NDRPOINTER):
    referent = (
        ('Data', TS_CHAR),
    )
TS_PBYTE = TS_LPCHAR

class TS_WCHAR_STRIPPED(TS_WCHAR):
    def __getitem__(self, key):
        if key == 'Data':
            return self.fields[key].decode('utf-16le').strip('\x00')
        else:
            return NDR.__getitem__(self,key)


class WIDESTR_STRIPPED(WIDESTR):
    length = None
    def __getitem__(self, key):
        if key == 'Data':
            return self.fields[key].decode('utf-16le').rstrip('\x00')
        else:
            return NDR.__getitem__(self,key)
    def getDataLen(self, data, offset=0):
        if self.length is None:
            return super().getDataLen(data, offset)
        return self.length * 2

class WSTR_STRIPPED(WSTR):
    def __getitem__(self, key):
        if key == 'Data':
            return self.fields[key].decode('utf-16le').rstrip('\x00')
        else:
            return NDR.__getitem__(self,key)

class LPWCHAR_STRIPPED(NDRPOINTER):
    referent = ( 
        ('Data', WIDESTR_STRIPPED),
    )

class LONG_ARRAY(NDRUniConformantArray):
    item = 'L'
    def __getitem__(self, key):
        if key == 'Data':
            return b''.join(self.fields[key])
        else:
            return NDR.__getitem__(self,key)

class UCHAR_ARRAY(NDRUniConformantArray):
    item = 'c'

class LPUCHAR_ARRAY(NDRPOINTER):
    referent = (
        ('Data', UCHAR_ARRAY),
    )
class WCHAR_ARRAY_32(WIDESTR_STRIPPED):
    length = 32
class WCHAR_ARRAY_256(WIDESTR_STRIPPED):
    length = 256
class WCHAR_ARRAY_33(WIDESTR_STRIPPED):
    length = 33    
class WCHAR_ARRAY_21(WIDESTR_STRIPPED):
    length = 21
class WCHAR_ARRAY_18(WIDESTR_STRIPPED):
    length = 18
class WCHAR_ARRAY_4(WIDESTR_STRIPPED):
    length = 4
class WCHAR_CLIENTNAME_LENGTH(WIDESTR_STRIPPED):
    length = CLIENTNAME_LENGTH + 1
class WCHAR_DOMAIN_LENGTH(WIDESTR_STRIPPED):
    length = DOMAIN_LENGTH + 1
class WCHAR_USERNAME_LENGTH(WIDESTR_STRIPPED):
    length = USERNAME_LENGTH + 1
class WCHAR_PASSWORD_LENGTH(WIDESTR_STRIPPED):
    length = PASSWORD_LENGTH + 1
class WCHAR_DIRECTORY_LENGTH(WIDESTR_STRIPPED):
    length = DIRECTORY_LENGTH + 1
class WCHAR_INITIALPROGRAM_LENGTH(WIDESTR_STRIPPED):
    length = INITIALPROGRAM_LENGTH + 1
class WCHAR_CLIENTADDRESS_LENGTH(WIDESTR_STRIPPED):
    length = CLIENTADDRESS_LENGTH + 1
class WCHAR_IMEFILENAME_LENGTH(WIDESTR_STRIPPED):
    length = IMEFILENAME_LENGTH + 1
class WCHAR_CLIENTLICENSE_LENGTH(WIDESTR_STRIPPED):
    length = CLIENTLICENSE_LENGTH + 1
class WCHAR_CLIENTMODEM_LENGTH(WIDESTR_STRIPPED):
    length = CLIENTMODEM_LENGTH + 1
class WCHAR_AUDIODRIVENAME_LENGTH(WIDESTR_STRIPPED):
    length = AUDIODRIVENAME_LENGTH
class WCHAR_CLIENT_PRODUCT_ID_LENGTH(WIDESTR_STRIPPED):
    length = CLIENT_PRODUCT_ID_LENGTH
class WCHAR_NASIFILESERVER_LENGTH(WIDESTR_STRIPPED):
    length = NASIFILESERVER_LENGTH + 1
class WCHAR_CALLBACK_LENGTH(WIDESTR_STRIPPED):
    length = CALLBACK_LENGTH + 1
class WCHAR_MAX_BR_NAME(WIDESTR_STRIPPED):
    length = MAX_BR_NAME
class WCHAR_WINSTATIONCOMMENT_LENGTH(WIDESTR_STRIPPED):
    length = WINSTATIONCOMMENT_LENGTH + 1

################################################################################
# Helpers
################################################################################

class DCERPCSessionError(DCERPCException):
    def __init__(self, error_string=None, error_code=None, packet=None):
        DCERPCException.__init__(self, error_string, error_code, packet)
    def __str__( self ):
        key = self.error_code & 0xffff
        if key in system_errors.ERROR_MESSAGES:
            error_msg_short = system_errors.ERROR_MESSAGES[key][0]
            error_msg_verbose = system_errors.ERROR_MESSAGES[key][1] 
            return 'TSTS SessionError: code: 0x%x - %s - %s' % (self.error_code, error_msg_short, error_msg_verbose)
        else:
            return 'TSTS SessionError: unknown error code: 0x%x' % self.error_code

def ZEROPAD(data, size = None):
    if size is None:
        size = len(data)+1
    assert len(data) <= size, 'Invalid data size!'
    data += '\0' * ( size - len(data) )
    return data

def getUnixTime(t):
    t -= 116444736000000000
    t /= 10000000
    return t

def enum2value(enum, key):
    return enum.enumItems._value2member_map_[key]._name_
    
class SID(TS_CHAR):
    def known_sid(self, sid):
        knownSids = {
            'S-1-5-10': r'SELF',
            'S-1-5-13': r'TERMINAL SERVER USER',
            'S-1-5-11': r'Authenticated Users',
            'S-1-5-12': r'RESTRICTED',
            'S-1-5-14': r'Authenticated Users',
            'S-1-5-15': r'This Organization',
            'S-1-5-17': r'IUSR',
            'S-1-5-18': r'SYSTEM',
            'S-1-5-19': r'LOCAL SERVICE',
            'S-1-5-20': r'NETWORK SERVICE',
        }
        if sid.startswith('S-1-5-90-0-') and len(sid.split('-')) == 6:
            return 'DWM-{}'.format(int(sid.split('-')[-1]))
        elif sid.startswith('S-1-5-96-0-') and len(sid.split('-')) == 6:
            return 'UMFD-{}'.format(int(sid.split('-')[-1]))
        elif sid in knownSids:
            return knownSids[sid]
        return sid
    def __getitem__(self, key):
        if key == 'Data':
            sid = format_sid(self.fields[key])
            if not len(sid):
                return ''
            return self.known_sid(sid)
        else:
            return NDR.__getitem__(self,key)

################################################################################
# Handles
################################################################################

class context_handle(NDRSTRUCT):
    structure = (
         ('context_handle_attributes',ULONG),
         ('context_handle_uuid',UUID),
    )
    def getUUID(self):
        return bin_to_string(self['context_handle_uuid'])
    def tuple(self):
        return (bin_to_string(self['context_handle_uuid']),self['context_handle_attributes'])
    def from_tuple(self, tup):
        self['context_handle_uuid'], self['context_handle_attributes'] = (string_to_bin(tup[0]), tup[1])
    def __init__(self, data=None, isNDR64=False):
        NDRSTRUCT.__init__(self, data, isNDR64)
        self['context_handle_uuid'] = b'\x00'*16
    def isNull(self):
        return self['context_handle_uuid'] == b'\x00'*16
    def __str__(self):
        return bin_to_string(self['context_handle_uuid'])

class handle_t(NDRSTRUCT):
    structure =  (
        ('Data','20s=b""'),
    )
    def getAlignment(self):
        if self._isNDR64 is True:
            return 8
        else:
            return 4

# 2.2.1.2 ENUM_HANDLE
ENUM_HANDLE = context_handle

class pHandle(NDRPOINTER):
    referent =  (
        ('Data', handle_t),
    )
# 2.2.1.3 HLISTENER
HLISTENER = context_handle

# 2.2.1.4 SERVER_HANDLE
SERVER_HANDLE = context_handle

# 2.2.1.15 NOTIFY_HANDLE
NOTIFY_HANDLE = context_handle

# 2.2.1.1 SESSION_HANDLE
SESSION_HANDLE = context_handle

################################################################################
# Structures
################################################################################

class MSGBOX_ENUM(NDRENUM):
    class enumItems(Enum):
        IDABORT     = 3     # The Abort button was selected.
        IDCANCEL    = 2     # The Cancel button was selected.
        IDIGNORE    = 5     # The Ignore button was selected.
        IDNO        = 7     # The No button was selected.
        IDOK        = 1     # The OK button was selected.
        IDRETRY     = 4     # The Retry button was selected.
        IDYES       = 6     # The Yes button was selected.
        IDASYNC     = 32001 # The bDoNotWait parameter was TRUE, so the function returned without waiting for a response.
        IDTIMEOUT   = 32000 # The bDoNotWait parameter was FALSE and the time-out interval elapsed.

class ShutdownFlags(NDRENUM):
    structure = (
        ('Data','<L'),
    )
    class enumItems(Enum):
        WSD_LOGOFF   = 0x00000001 # Forces sessions to logoff.
        WSD_SHUTDOWN = 0x00000002 # Shuts down the system.
        WSD_REBOOT   = 0x00000004 # Reboots after shutdown.
        WSD_POWEROFF = 0x00000008 # Powers off after shutdown.

class HotKeyModifiers(NDRENUM):
    structure = (
        ('Data', '<H'),
    )
    NONE        = 0
    Alt         = 1     # MOD_ALT
    Control     = 2     # MOD_CONTROL
    Shift       = 4     # MOD_SHIFT
    WindowsKey  = 8     # MOD_WIN


class EventFlags(NDRENUM):
    structure = (
        ('Data','<L'),
    )
    class enumItems(Enum):
        WEVENT_NONE         = 0x00000000    # The client requests to clear its event wait block. This MUST be called when completing waiting for the event. When RpcWinStationCloseServer is called for hServer, this method and mask value is called on the client's behalf.
        WEVENT_CREATE       = 0x00000001    # Wait for a new session to be created.
        WEVENT_DELETE       = 0x00000002    # Wait for an existing session to be deleted.
        WEVENT_RENAME       = 0x00000004    # Wait for a session to be renamed.
        WEVENT_CONNECT      = 0x00000008    # The session connected to a client.
        WEVENT_DISCONNECT   = 0x00000010    # A client disconnected from the session.
        WEVENT_LOGON        = 0x00000020    # A user logged on to the session.
        WEVENT_LOGOFF       = 0x00000040    # A user logged off from the session.
        WEVENT_STATECHANGE  = 0x00000080    # The session state changed.
        WEVENT_LICENSE      = 0x00000100    # The license state changed.<183>
        WEVENT_ALL          = 0x7fffffff    # Wait for all event types.
        WEVENT_FLUSH        = 0x80000000    # Release all waiting clients.

class ADDRESSFAMILY_ENUM(NDRENUM):
    structure = (
        ('Data','<L'),
    )
    class enumItems(Enum):
        AppleTalk               = 16
        Atm                     = 22
        Banyan                  = 21
        Ccitt                   = 10
        Chaos                   = 5
        Cluster                 = 24
        ControllerAreaNetwork   = 65537
        DataKit                 = 9
        DataLink                = 13
        DecNet                  = 12
        Ecma                    = 8
        FireFox                 = 19
        HyperChannel            = 15
        Ieee12844               = 25
        ImpLink                 = 3
        InterNetwork            = 2
        InterNetworkV6          = 23
        Ipx                     = 6
        Irda                    = 26
        Iso                     = 7
        Lat                     = 14
        Max                     = 29
        NetBios                 = 17
        NetworkDesigners        = 28
        NS                      = 6
        Osi                     = 7
        Packet                  = 65536
        Pup                     = 4
        Sna                     = 11
        Unix	                = 1	
        Unspecified             = 0
        VoiceView               = 18

# 2.2.1.5 WINSTATIONNAME #FIXME
class WINSTATIONNAME(WIDESTR_STRIPPED):
    length = WINSTATIONNAME_LENGTH + 1

# 2.2.1.6 DLLNAME
class DLLNAME(WIDESTR):
    def getDataLen(self, data, offset=0):
        return DLLNAME_LENGTH + 1

class PDLLNAME(NDRPOINTER):
    referent = (
        ('Data', DLLNAME),
    )

# 2.2.1.7 DLLNAME
class DEVICENAME(WIDESTR):
    def getDataLen(self, data, offset=0):
        return DEVICENAME_LENGTH + 1

class PDEVICENAME(NDRPOINTER):
    referent = (
        ('Data', DEVICENAME),
    )


# 2.2.1.13 CLIENTDATANAME #FIXME
class CLIENTDATANAME(STR):
    def getDataLen(self, data, offset=0):
        return CLIENTDATANAME_LENGTH + 1

class PCLIENTDATANAME(NDRPOINTER):
    referent = (
        ('Data', CLIENTDATANAME),
    )


# 2.2.1.8 WINSTATIONINFOCLASS
class WINSTATIONINFOCLASS(NDRENUM):
    class enumItems(Enum):
        WinStationCreateData                = 0
        WinStationConfiguration             = 1
        WinStationPdParams                  = 2
        WinStationWd                        = 3
        WinStationPd                        = 4
        WinStationPrinter                   = 5
        WinStationClient                    = 6
        WinStationModules                   = 7
        WinStationInformation               = 8
        WinStationTrace                     = 9
        WinStationBeep                      = 10
        WinStationEncryptionOff             = 11
        WinStationEncryptionPerm            = 12
        WinStationNtSecurity                = 13
        WinStationUserToken                 = 14
        WinStationUnused1                   = 15
        WinStationVideoData                 = 16
        WinStationInitialProgram            = 17
        WinStationCd                        = 18
        WinStationSystemTrace               = 19
        WinStationVirtualData               = 20
        WinStationClientData                = 21
        WinStationSecureDesktopEnter        = 22
        WinStationSecureDesktopExit         = 23
        WinStationLoadBalanceSessionTarget  = 24
        WinStationLoadIndicator             = 25
        WinStationShadowInfo                = 26
        WinStationDigProductId              = 27
        WinStationLockedState               = 28
        WinStationRemoteAddress             = 29
        WinStationIdleTime                  = 30
        WinStationLastReconnectType         = 31
        WinStationDisallowAutoReconnect     = 32
        WinStationUnused2                   = 33
        WinStationUnused3                   = 34
        WinStationUnused4                   = 35
        WinStationUnused5                   = 36
        WinStationReconnectedFromId         = 37
        WinStationEffectsPolicy             = 38
        WinStationType                      = 39
        WinStationInformationEx             = 40

# 2.2.1.9 WINSTATIONSTATECLASS
class WINSTATIONSTATECLASS(NDRENUM):
    structure = (
        ('Data', '<L'),
    )
    class enumItems(Enum):
        State_Active        = 0 # A user is logged on to a session and the client is connected.
        State_Connected     = 1 # A client is connected to a session but the user has not yet logged on.
        State_ConnectQuery  = 2 # A session is in the process of connecting to a client.
        State_Shadow        = 3 # A session is shadowing another session
        State_Disconnected  = 4 # A user is logged on to the session but the client is currently disconnected from the server.
        State_Idle          = 5 # A session is waiting for a client to connect to the server.
        State_Listen        = 6 # A listener is waiting for connections from the Terminal Services client.
        State_Reset         = 7 # A session is being reset. As a result, the user is logged off, the session is terminated, and the client is disconnected.
        State_Down          = 8 # A session is currently tearing down or is in the down state, indicating an error.
        State_Init          = 9 # A session is in the process of being initialized.

# 2.2.1.10 SDCLASS
class SDCLASS(NDRENUM):
    class enumItems(Enum):
        SdNone          = 0
        SdConsole       = 1
        SdNetwork       = 2
        SdAsync         = 3
        SdOemTransport  = 4

# 2.2.1.11 SHADOWCLASS
class SHADOWCLASS(NDRENUM):
    class enumItems(Enum):
        Shadow_Disable                  = 0
        Shadow_EnableInputNotify        = 1
        Shadow_EnableInputNoNotify      = 2
        Shadow_EnableNoInputNotify      = 3
        Shadow_EnableNoInputNoNotify    = 4

# 2.2.1.12 SHADOWCLASS
class RECONNECT_TYPE(NDRENUM):
    class enumItems(Enum):
        NeverReconnected = 0
        ManualReconnect  = 1
        AutoReconnect    = 2

class PRECONNECT_TYPE(NDRPOINTER):
    referent = (
        ('Data', RECONNECT_TYPE),
    )

# 2.2.1.6 BOUNDED_ULONG
BOUNDED_ULONG = ULONG #FIXME: typedef [range(0, 0x8000)] ULONG BOUNDED_ULONG; as scmr.py@282 it should work

# 2.2.1.17 UINT_PTR
class UINT_PTR(NDRPOINTER):
    referent = ( 
        ('Data', UINT),
    )

# 2.2.1.18 SESSIONTYPE
class SESSIONTYPE(NDRENUM):
    class enumItems(Enum):
        SESSIONTYPE_UNKNOWN         = 0 # The type of the session cannot be determined.
        SESSIONTYPE_SERVICES        = 1 # The session is used only to run the operating system services, and that no user can be logged on to the session.
        SESSIONTYPE_LISTENER        = 2 # The session is used only to run the Terminal Services listeners, and that no user can be logged on to the session.
        SESSIONTYPE_REGULARDESKTOP  = 3 # The session is connected by using Terminal Services and is running the standard shell.
        SESSIONTYPE_ALTERNATESHELL  = 4 # The session is connected by using Terminal Services and is running an alternate shell instead of the standard shell
        SESSIONTYPE_REMOTEAPP       = 5 # The session is a RAIL (Remote Applications Integrated Locally) session as defined in [MS-RDPERP].
        SESSIONTYPE_MEDIACENTEREXT  = 6 # The session was connected by using a media center extender device. For more information about the media center, see [MSFT-WINMCE].

# 2.2.1.19 SHADOW_CONTROL_REQUEST
class SHADOW_CONTROL_REQUEST(NDRENUM):
    class enumItems(Enum):
        SHADOW_CONTROL_REQUEST_VIEW         = 0 # The shadow request is for a view-only session. User input is not being requested.
        SHADOW_CONTROL_REQUEST_TAKECONTROL  = 1 # User input control is being requested.
        SHADOW_CONTROL_REQUEST_Count        = 2 # Count of enum values.

# 2.2.1.20 SHADOW_PERMISSION_REQUEST
class SHADOW_PERMISSION_REQUEST(NDRENUM):
    class enumItems(Enum):
        SHADOW_PERMISSION_REQUEST_SILENT            = 0 # Permission is not requested.
        SHADOW_PERMISSION_REQUEST_REQUESTPERMISSION = 1 # User permission will be requested before the shadow session begins.
        SHADOW_PERMISSION_REQUEST_Count             = 2 # Count of enum values.

# 2.2.1.21 SHADOW_REQUEST_RESPONSE
class SHADOW_REQUEST_RESPONSE(NDRENUM):
    class enumItems(Enum):
        SHADOW_REQUEST_RESPONSE_ALLOW                                   = 0 # The user has granted the request for permission to shadow the session.
        SHADOW_REQUEST_RESPONSE_DECLINE                                 = 1 # The user has declined the request for permission to shadow the session.
        SHADOW_REQUEST_RESPONSE_POLICY_PERMISSION_REQUIRED              = 2 # Permission was not requested, but group policy specifies that permission is required.
        SHADOW_REQUEST_RESPONSE_POLICY_DISABLED                         = 3 # Shadowing has been disabled by group policy.
        SHADOW_REQUEST_RESPONSE_POLICY_VIEW_ONLY                        = 4 # A request for control was made, but group policy exclusively allows view-only shadowing.
        SHADOW_REQUEST_RESPONSE_POLICY_VIEW_ONLY_PERMISSION_REQUIRED    = 5 # A request was made to take control without requesting permission,
                                                                            # but group policy exclusively allows viewonly shadowing and also requires permission.
        SHADOW_REQUEST_RESPONSE_SESSION_ALREADY_CONTROLLED              = 6 # The session cannot be shadowed because another shadow session is currently controlling the session.

# 2.2.2.1 SESSION_FILTER #FIXME
class SESSION_FILTER(NDRENUM):
    class enumItems(Enum):
        SF_SERVICES_SESSION_POPUP = 0

# 2.2.2.2 PROTOCOLSTATUS_INFO_TYPE
class PROTOCOLSTATUS_INFO_TYPE(NDRENUM):
    class enumItems(Enum):
        PROTOCOLSTATUS_INFO_BASIC    = 0
        PROTOCOLSTATUS_INFO_EXTENDED = 1

# 2.2.2.3 QUERY_SESSION_DATA_TYPE
class QUERY_SESSION_DATA_TYPE(NDRENUM):
    class enumItems(Enum):
        QUERY_SESSION_DATA_MODULE               = 0
        QUERY_SESSION_DATA_WDCONFIG             = 1
        QUERY_SESSION_DATA_VIRTUALDATA          = 2
        QUERY_SESSION_DATA_LICENSE              = 3
        QUERY_SESSION_DATA_DEVICEID             = 4
        QUERY_SESSION_DATA_LICENSE_VALIDATION   = 5


# 2.2.2.4.1.1 SESSIONENUM_LEVEL1
class SESSIONENUM_LEVEL1(NDRSTRUCT):
    structure = (
        ('SessionId', LONG),
        ('State', WINSTATIONSTATECLASS),
        ('Name', WCHAR_ARRAY_33)
    )

# 2.2.2.4.1.2 SESSIONENUM_LEVEL2
class SESSIONENUM_LEVEL2(NDRSTRUCT):
    structure = (
        ('SessionId', LONG),
        ('State', WINSTATIONSTATECLASS),
        ('Name', WCHAR_ARRAY_33), # WCHAR Name[33]
        ('Source', ULONG),
        ('bFullDesktop', BOOLEAN),
        ('SessionType', GUID),
    )

# 2.2.2.4.1.3 SESSIONENUM_LEVEL3
class SESSIONENUM_LEVEL3(NDRSTRUCT):
    structure = (
        ('SessionId', LONG),
        ('State', WINSTATIONSTATECLASS),
        ('Name', WCHAR_ARRAY_33),
        ('Source', ULONG),
        ('bFullDesktop', BOOLEAN),
        ('SessionType', GUID),
        ('ProtoDataSize', ULONG),
        ('pProtocolData', UCHAR),
    )


# 2.2.2.4.1 SessionInfo
class SessionInfo(NDRUNION):
    commonHdr = (
        ('tag', DWORD),
    )
    union = {
        1: ('SessionEnum_Level1', SESSIONENUM_LEVEL1),
        2: ('SessionEnum_Level2', SESSIONENUM_LEVEL2),
        3: ('SessionEnum_Level3', SESSIONENUM_LEVEL3),
    }

class SessionInfo_STRUCT(NDRSTRUCT):
    structure = (
        ('Level', DWORD),
        ('SessionInfo', SessionInfo),
    )

# 2.2.2.4 PSESSIONENUM
class SESSIONENUM(NDRUniConformantArray):
    item = SessionInfo_STRUCT

class PSESSIONENUM(NDRPOINTER):
    referent = (
        ('Data', SESSIONENUM),
    )

# 2.2.2.5.1 SessionInfo_Ex
SessionInfo_Ex = SessionInfo

# 2.2.2.5 PSESSIONENUM_EX
PSESSIONENUM_EX = SESSIONENUM

# 2.2.2.6.1.1 EXECENVDATA_LEVEL1
class EXECENVDATA_LEVEL1(NDRSTRUCT):
    structure = (
        ('ExecEnvId', LONG),
        ('State', WINSTATIONSTATECLASS),
        ('SessionName', WCHAR_ARRAY_33),
    )
class PEXECENVDATA_LEVEL1(NDRPOINTER):
    referent =  ( 
        ('Data', EXECENVDATA_LEVEL1),
    )
# 2.2.2.6.1.2 EXECENVDATA_LEVEL2
class EXECENVDATA_LEVEL2(NDRSTRUCT):
    structure = (
        ('ExecEnvId', LONG),
        ('State', WINSTATIONSTATECLASS),
        ('SessionName', WCHAR_ARRAY_33),
        ('AbsSessionId', LONG),
        ('HostName', WCHAR_ARRAY_33),
        ('UserName', WCHAR_ARRAY_33),
        ('DomainName', WCHAR_ARRAY_33),
        ('FarmName', WCHAR_ARRAY_33),
    )
class PEXECENVDATA_LEVEL2(NDRPOINTER):
    referent =  ( 
        ('Data', EXECENVDATA_LEVEL2),
    )
# 2.2.2.6.1 ExecEnvData
class ExecEnvData(NDRUNION):
    commonHdr = (
        ('tag', DWORD),
    )
    union = {
        1: ('ExecEnvEnum_Level1', EXECENVDATA_LEVEL1),
        2: ('ExecEnvEnum_Level2', EXECENVDATA_LEVEL2),
    }

class ExecEnvData_STRUCT(NDRSTRUCT):
    structure = (
        ('Level', DWORD),
        ('ExecEnvData', ExecEnvData),
    )

# 2.2.2.6 PEXECENVDATA
class EXECENVDATA(NDRUniConformantArray):
    item = ExecEnvData_STRUCT

class PEXECENVDATA(NDRPOINTER):
    referent =  ( 
        ('Data', EXECENVDATA),
    )


# 2.2.2.7.1.1 EXECENVDATAEX_LEVEL1
class EXECENVDATAEX_LEVEL1(NDRSTRUCT):
    #FIXME this structure does not work :(
    '''
        structure = (
            ('ExecEnvId', LONG),
            ('State', WINSTATIONSTATECLASS),
            ('AbsSessionId', LONG),
            ('pszSessionName', WIDESTR),
            ('pszHostName', WIDESTR),
            ('pszUserName', WIDESTR),
            ('pszFarmName', WIDESTR),
        )
    '''
    pass

# 2.2.2.7.1 ExecEnvDataEx
class ExecEnvDataEx(NDRUNION):
    commonHdr = (
        ('tag', DWORD),
    )
    union = {
        1: ('ExecEnvEnum_Level1', EXECENVDATAEX_LEVEL1),
    }

# 2.2.2.7 PEXECENVDATAEX
class EXECENVDATAEX(NDRUniConformantArray):
    item = ExecEnvDataEx

class PEXECENVDATAEX(NDRPOINTER):
    referent =  ( 
        ('Data', EXECENVDATAEX),
    )

# 2.2.2.12.1.1 LISTENERENUM_LEVEL1
class LISTENERENUM_LEVEL1(NDRSTRUCT):
    structure = (
        ('Id', LONG),
        ('bListening', BOOL),
        ('Name', WCHAR_ARRAY_33),
    )

# 2.2.2.12.1 ListenerInfo
class ListenerInfo(NDRUNION):
    commonHdr = (
        ('tag', DWORD),
    )
    union = {
        1: ('ListenerEnum_Level1', LISTENERENUM_LEVEL1),
    }

class ListenerInfo_STRUCT(NDRSTRUCT):
    structure = (
        ('Level', DWORD),
        ('ListenerInfo', ListenerInfo),
    )

# 2.2.2.12 PLISTENERENUM
class LISTENERENUM(NDRUniConformantArray):
    item = ListenerInfo_STRUCT

class PLISTENERENUM(NDRPOINTER):
    referent = (
        ('Data', LISTENERENUM),
    )    
# 2.2.2.8 PLSMSESSIONINFORMATION
class LSMSESSIONINFORMATION(NDRSTRUCT):
    structure = (
        ('pszUserName', LPWCHAR_STRIPPED),
        ('pszDomain', LPWCHAR_STRIPPED),
        ('pszTerminalName', LPWCHAR_STRIPPED),
        ('SessionState', WINSTATIONSTATECLASS),
        ('DesktopLocked', BOOLEAN),
        ('ConnectTime', SYSTEM_TIMESTAMP),
        ('DisconnectTime', SYSTEM_TIMESTAMP),
        ('LogonTime', SYSTEM_TIMESTAMP),
    )


# 2.2.2.19.1.1 TS_SYSTEMTIME
class TS_SYSTEMTIME(NDRSTRUCT):
    structure = (
        ('wYear', USHORT),
        ('wMonth', USHORT),
        ('wDayOfWeek', USHORT),
        ('wDay', USHORT),
        ('wHour', USHORT),
        ('wMinute', USHORT),
        ('wSecond', USHORT),
        ('wMilliseconds', USHORT),
    )  

# 2.2.2.19.1 TS_TIME_ZONE_INFORMATION
class TS_TIME_ZONE_INFORMATION(NDRSTRUCT):
    structure = (
        ('Bias', ULONG),
        ('StandardName', WCHAR_ARRAY_32),
        ('StandardDate', TS_SYSTEMTIME),
        ('StandardBias', ULONG),
        ('DaylightName', WCHAR_ARRAY_32),
        ('DaylightDate', TS_SYSTEMTIME),
        ('DaylightBias', ULONG),
    )  


# 2.2.2.19 WINSTATIONCLIENT
class WINSTATIONCLIENT(NDRSTRUCT):
    class FLAGS(NDRSTRUCT):
        # a little hack to extrack bit flags
        structure = (
            ('flags','6s=b""'),
        )
        def __getitem__(self, key):
            if key == 'flags':
                flagsInt = int.from_bytes(self.fields[key][2:],'little')
                keys = {'fTextOnly'           : False,
                        'fDisableCtrlAltDel'  : False,
                        'fMouse'              : False,
                        'fDoubleClickDetect'  : False,
                        'fINetClient'         : False,
                        'fPromptForPassword'  : False,
                        'fMaximizeShell'      : False,
                        'fEnableWindowsKey'   : False,
                        'fRemoteConsoleAudio' : False,
                        'fPasswordIsScPin'    : False,
                        'fNoAudioPlayback'    : False,
                        'fUsingSavedCreds'    : False,
                        'fRestrictedLogon'    : False
                }
                for k in keys:
                    keys[k] = bool(flagsInt & 1)
                    flagsInt >>= 1
                return keys
            else:
                return NDR.__getitem__(self,key)

    structure = (
        # I have no idea to to do it properly, so i'm parsing bit flags inside another structure class
        ('flags', FLAGS),
        ('ClientName', WCHAR_CLIENTNAME_LENGTH),
        ('Domain', WCHAR_DOMAIN_LENGTH),
        ('UserName', WCHAR_USERNAME_LENGTH),
        ('Password', WCHAR_PASSWORD_LENGTH),
        ('WorkDirectory', WCHAR_DIRECTORY_LENGTH),
        ('InitialProgram', WCHAR_INITIALPROGRAM_LENGTH),
        ('SerialNumber', ULONG),
        ('EncryptionLevel', BYTE),
        ('ClientAddressFamily', ADDRESSFAMILY_ENUM),
        ('ClientAddress', WCHAR_CLIENTADDRESS_LENGTH),
        ('HRes', USHORT),
        ('VRes', USHORT),
        ('ColorDepth', USHORT),
        ('ProtocolType', USHORT),
        ('KeyboardLayout', ULONG),
        ('KeyboardType', ULONG),
        ('KeyboardSubType', ULONG),
        ('KeyboardFunctionKey', ULONG),
        ('imeFileName', WCHAR_IMEFILENAME_LENGTH),
        ('ClientDirectory', WCHAR_DIRECTORY_LENGTH),
        ('ClientLicense', WCHAR_CLIENTLICENSE_LENGTH),
        ('ClientModem', WCHAR_CLIENTMODEM_LENGTH),
        ('ClientBuildNumber', ULONG),
        ('ClientHardwareId', ULONG),
        ('ClientProductId', USHORT),
        ('OutBufCountHost', USHORT),
        ('OutBufCountClient', USHORT),
        ('OutBufLength', USHORT),
        ('AudioDriverName', WCHAR_AUDIODRIVENAME_LENGTH),
        ('ClientTimeZone', TS_TIME_ZONE_INFORMATION),
        ('ClientSessionId', ULONG),
        ('clientDigProductId', WCHAR_CLIENT_PRODUCT_ID_LENGTH),
        ('PerformanceFlags', ULONG),
        ('ActiveInputLocale', ULONG),
    )  

class PWINSTATIONCLIENT(NDRPOINTER):
    referent = (
        ('Data', WINSTATIONCLIENT),
    )

# 2.2.2.17.1 TS_COUNTER_HEADER
class TS_COUNTER_HEADER(NDRSTRUCT):
    structure = (
        ('dwCounterID', DWORD),
        ('bResult', BOOLEAN),
    )

# 2.2.2.17 TS_COUNTER
class TS_COUNTER(NDRSTRUCT):
    structure = (
        ('counterHead', TS_COUNTER_HEADER),
        ('dwValue', DWORD),
        ('startTime', LARGE_INTEGER),
    )

class TS_COUNTER_ARRAY(NDRUniConformantArray):
    item = TS_COUNTER

class PTS_COUNTER(NDRPOINTER):
    referent = (
        ('Data', TS_COUNTER_ARRAY),
    )

# 2.2.2.11 LSM_SESSIONINFO_EX_LEVEL1
class SESSIONFLAGS(NDRENUM):
    structure = (
        ('Data', '<L'),
    )
    class enumItems(Enum):
        WTS_SESSIONSTATE_UNKNOWN    = 0xFFFFFFFF
        WTS_SESSIONSTATE_LOCK       = 0x00000000
        WTS_SESSIONSTATE_UNLOCK     = 0x00000001

class LSM_SESSIONINFO_EX_LEVEL1(NDRSTRUCT):
    structure = (
        ('SessionState', WINSTATIONSTATECLASS),
        ('SessionFlags', SESSIONFLAGS),
        ('SessionName', WCHAR_ARRAY_33),
        ('DomainName', WCHAR_ARRAY_18),
        ('UserName', WCHAR_ARRAY_21),
        ('ConnectTime', SYSTEM_TIMESTAMP),
        ('DisconnectTime', SYSTEM_TIMESTAMP),
        ('LogonTime', SYSTEM_TIMESTAMP),
        ('LastInputTime', SYSTEM_TIMESTAMP),
        ('ProtocolDataSize', ULONG),
        ('ProtocolData', TS_LPCHAR),
    )

# 2.2.2.10 LSM_SESSIONINFO_EX
class LSM_SESSIONINFO_EX(NDRUNION):
    commonHdr = (
        ('tag', DWORD),
    )
    union = {
        1: ('LSM_SessionInfo_Level1', LSM_SESSIONINFO_EX_LEVEL1),
    }
    

# 2.2.2.9 PLSMSESSIONINFORMATION_EX
class PLSMSESSIONINFORMATION_EX(NDRPOINTER):
    referent = (
        ('Data', LSM_SESSIONINFO_EX ),
    )

# 2.2.1.14 TNotificationId
class TNotificationId(NDRENUM):
    structure = (
        ('Data', '<L'),
    )
    class enumItems(Enum):
        WTS_NOTIFY_NONE                 = 0x0        #No notification
        WTS_NOTIFY_CREATE               = 0x1        #Session creation notification
        WTS_NOTIFY_CONNECT              = 0x2        #Session connection notification
        WTS_NOTIFY_DISCONNECT           = 0x4        #Session disconnection notification
        WTS_NOTIFY_LOGON                = 0x8        #Session logon notification
        WTS_NOTIFY_LOGOFF               = 0x10       #Session logoff notification
        WTS_NOTIFY_SHADOW_START         = 0x20       #Session shadow start notification
        WTS_NOTIFY_SHADOW_STOP          = 0x40       #Session shadow stop notification 
        WTS_NOTIFY_TERMINATE            = 0x80       #Session termination notification
        WTS_NOTIFY_CONSOLE_CONNECT      = 0x100      #Console session connection notification
        WTS_NOTIFY_CONSOLE_DISCONNECT   = 0x200      #Console session disconnect notification
        WTS_NOTIFY_LOCK                 = 0x400      #Session lock notification
        WTS_NOTIFY_UNLOCK               = 0x800      #Session unlock notification
        WTS_NOTIFY_ALL                  = 0xffffffff #All notifications

# 2.2.2.42 SESSION_CHANGE
class SESSION_CHANGE(NDRSTRUCT):
    structure = (
        ('SessionId', LONG),
        ('TNotificationId', TNotificationId),
    )
    
class SESSION_CHANGE_ARRAY(NDRUniConformantArray):
    item = SESSION_CHANGE

class PSESSION_CHANGE(NDRPOINTER):
    referent = (
        ('Data', SESSION_CHANGE_ARRAY),
    )


# 2.2.2.18.1 CALLBACKCLASS
class CALLBACKCLASS(NDRENUM):
    structure = (
        ('Data', '<L'),
    )
    class enumItems(Enum):
        Callback_Disable = 0
        Callback_Roving  = 1
        Callback_Fixed   = 2

# 2.2.2.18 USERCONFIG
class USERCONFIG(NDRSTRUCT):
    class FLAGS(NDRSTRUCT):
        # a little hack to extrack bit flags
        structure = (
            ('flags','7s=b""'),
        )
        def __getitem__(self, key):
            if key == 'flags':
                # Hope that works as intended. If no, try to parse less data in that 7byte array
                flagsInt = int.from_bytes(self.fields[key][:],'little')
                tmp  = [('fInheritAutoLogon'             ,1),
                        ('fInheritResetBroken'           ,1),
                        ('fInheritReconnectSame'         ,1),
                        ('fInheritInitialProgram'        ,1),
                        ('fInheritCallback'              ,1),
                        ('fInheritCallbackNumber'        ,1),
                        ('fInheritShadow'                ,1),
                        ('fInheritMaxSessionTime'        ,1),
                        ('fInheritMaxDisconnectionTime'  ,1),
                        ('fInheritMaxIdleTime'           ,1),
                        ('fInheritAutoClient'            ,1),
                        ('fInheritSecurity'              ,1),
                        ('fPromptForPassword'            ,1),
                        ('fResetBroken'                  ,1),
                        ('fReconnectSame'                ,1),
                        ('fLogonDisabled'                ,1),
                        ('fWallPaperDisabled'            ,1),
                        ('fAutoClientDrives'             ,1),
                        ('fAutoClientLpts'               ,1),
                        ('fForceClientLptDef'            ,1),
                        ('fRequireEncryption'            ,1),
                        ('fDisableEncryption'            ,1),
                        ('fUnused1'                      ,1),
                        ('fHomeDirectoryMapRoot'         ,1),
                        ('fUseDefaultGina'               ,1),
                        ('fCursorBlinkDisabled'          ,1),
                        ('fPublishedApp'                 ,1),
                        ('fHideTitleBar'                 ,1),
                        ('fMaximize'                     ,1),
                        ('fDisableCpm'                   ,1),
                        ('fDisableCdm'                   ,1),
                        ('fDisableCcm'                   ,1),
                        ('fDisableLPT'                   ,1),
                        ('fDisableClip'                  ,1),
                        ('fDisableExe'                   ,1),
                        ('fDisableCam'                   ,1),
                        ('fDisableAutoReconnect'         ,1),
                        ('ColorDepth'                    ,3),
                        ('fInheritColorDepth'            ,1),
                        ('fErrorInvalidProfile'          ,1),
                        ('fPasswordIsScPin'              ,1),
                        ('fDisablePNPRedir'              ,1)
                    ]
                keys = {}
                for k,bits in tmp:
                    if bits == 1:
                        keys[k] = flagsInt & 1
                    else:
                        keys[k] = flagsInt & ((1<<bits)-1)
                    flagsInt >>= bits
                return keys
            else:
                return NDR.__getitem__(self,key)

    structure = (
        # I have no idea to to do it properly, so i'm parsing bit flags inside another structure class
        ('flags', FLAGS),
        ('UserName', WCHAR_USERNAME_LENGTH),
        ('Domain', WCHAR_DOMAIN_LENGTH),
        ('Password', WCHAR_PASSWORD_LENGTH),
        ('WorkDirectory', WCHAR_DIRECTORY_LENGTH),
        ('InitialProgram', WCHAR_INITIALPROGRAM_LENGTH),
        ('CallbackNumber', WCHAR_CALLBACK_LENGTH),
        ('Callback', CALLBACKCLASS),
        ('Shadow', SHADOWCLASS),
        ('MaxConnectionTime', ULONG),
        ('MaxDisconnectionTime', ULONG),
        ('MaxIdleTime', ULONG),
        ('KeyboardLayout', ULONG),
        ('MinEncryptionLevel', BYTE),
        ('NWLogonServer', WCHAR_NASIFILESERVER_LENGTH),
        ('PublishedName', WCHAR_MAX_BR_NAME),
        ('WFProfilePath', WCHAR_DIRECTORY_LENGTH),
        ('WFHomeDir', WCHAR_DIRECTORY_LENGTH),
        ('WFHomeDirDrive', WCHAR_ARRAY_4),
    )


class OEMId(NDRSTRUCT):
    structure = (
        ('OEMId', '4s=""'),
    )
# 2.2.2.30.1 WINSTATIONCONFIG
class WINSTATIONCONFIG(NDRSTRUCT):
    pass
    structure = (
        ('Comment', WCHAR_WINSTATIONCOMMENT_LENGTH),
        ('User', USERCONFIG),
        ('OEMId', OEMId),
    )
class PWINSTATIONCONFIG(NDRPOINTER):
    referent = (
        ('Data', WINSTATIONCONFIG),
    )

#NOT_IMPLEMETED 2.2.2.20.1.2 PROTOCOLCOUNTERS
class PROTOCOLCOUNTERS(NDRSTRUCT):
    pass


#NOT_IMPLEMENTED 2.2.2.20.1.3 CACHE_STATISTICS
class CACHE_STATISTICS(NDRSTRUCT):
    pass

#NOT_IMPLEMENTED 2.2.2.20.1 PROTOCOLSTATUS
class PROTOCOLSTATUS(NDRSTRUCT):
    pass

class PPROTOCOLSTATUS(NDRPOINTER):
    referent = (
        ('Data', PROTOCOLSTATUS),
    )

# 2.2.2.43 RCM_REMOTEADDRESS
class IPv4ADDRESS(NDRSTRUCT):
    structure = (
        ('Data', '<L'),
    )
    def __getitem__(self, key):
        if key == 'Data':
            x = self.fields[key]
            y = []
            while x:
               y += [str(x & 0xff)]
               x >>= 8
            return '.'.join(y)
        else:
            return super().__getitem__(key)

class RCM_REMOTEADDRESS_UNION_CASE_IPV4(NDRSTRUCT):
    class _4CHAR(NDRSTRUCT):
        structure = (
            ('sin_zero', '4s=b""'),
        )    
    structure = (
        ('sin_port', USHORT),
        ('sin_port2', USHORT),
        ('in_addr', IPv4ADDRESS),
        ('sin_zero', _4CHAR),
    )

class RCM_REMOTEADDRESS_UNION_CASE_IPV6(NDRSTRUCT):
    class _8CHAR(NDRSTRUCT):
        structure = (
            ('sin_zero', '8s=b""'),
        )    
    structure = (
        ('sin_port', USHORT),
        ('in_addr', ULONG),
        ('sin_zero', _8CHAR),
        ('sin6_scope_id', ULONG),
    )

class RCM_REMOTEADDRESS(NDRUNION):
    commonHdr = (
        ('tag', USHORT),
    )
    union = {
        2 : ('ipv4', RCM_REMOTEADDRESS_UNION_CASE_IPV4),
        23: ('ipv6', RCM_REMOTEADDRESS_UNION_CASE_IPV6),
    }

class pResult_ENUM(NDRENUM):
    structure = (
        ('Data', '<L'),
    )
    class enumItems(Enum):
        STATUS_SUCCESS                                      = 0x00000000     # Successful call.
        STATUS_INVALID_PARAMETER                            = 0xC000000D
        STATUS_CANCELLED                                    = 0xC0000120     # The server is shutting down.
        STATUS_INVALID_INFO_CLASS                           = 0xC0000003
        STATUS_NO_MEMORY                                    = 0xC0000017     # Not enough memory to complete the operation
        STATUS_ACCESS_DENIED                                = 0xC0000022
        STATUS_BUFFER_TOO_SMALL                             = 0xC0000023
        STATUS_NOT_IMPLEMENTED                              = 0xC0000002
        STATUS_INFO_LENGTH_MISMATCH                         = 0xC0000004
        STATUS_UNSUCCESSFUL                                 = 0xC0000001
        STATUS_CTX_WINSTATION_NOT_FOUND                     = 0xC00A0015
        STATUS_WRONG_PASSWORD                               = 0xC000006A
        DOES_NOT_EXISTS_OR_INSUFFICIENT_PERMISSIONS         = 0x80071B6E
        INVALID_PARAMETER2                                  = 0x80070057
        ERROR_ACCESS_DENIED                                 = 0x80070005
        ERROR_INVALID_STATE                                 = 0x8007139f
        ERROR_LOGON_FAILURE                                 = 0x8007052e
        ERROR_FILE_NOT_FOUND                                = 0x80070002
        ERROR_STATUS_BUFFER_TOO_SMALL                       = 0x8007007A



# 2.2.2.15.1 TS_SYS_PROCESS_INFORMATION
class TS_SYS_PROCESS_INFORMATION(NDRSTRUCT):
    structure = (
         ('NextEntryOffset', ULONG),
         ('NumberOfThreads', ULONG),
         ('SpareLi1', LARGE_INTEGER),
         ('SpareLi2', LARGE_INTEGER),
         ('SpareLi3', LARGE_INTEGER),
         ('CreateTime', LARGE_INTEGER),
         ('UserTime', LARGE_INTEGER),
         ('KernelTime', LARGE_INTEGER),
         ('ImageNameSize', RPC_UNICODE_STRING), 
         ('BasePriority', LONG),
         ('UniqueProcessId', DWORD),
         ('InheritedFromUniqueProcessId', DWORD),
         ('HandleCount', ULONG),
         ('SessionId', ULONG),
         ('SpareUl3', ULONG),
         ('PeakVirtualSize', ULONG), #SIZE_T
         ('VirtualSize', ULONG), #SIZE_T
         ('PageFaultCount', ULONG),
         ('PeakWorkingSetSize', ULONG),
         ('WorkingSetSize', ULONG),
         ('QuotaPeakPagedPoolUsage', ULONG), #SIZE_T
         ('QuotaPagedPoolUsage', ULONG), #SIZE_T
         ('QuotaPeakNonPagedPoolUsage', ULONG), #SIZE_T
         ('QuotaNonPagedPoolUsage', ULONG), #SIZE_T
         ('PagefileUsage', ULONG), #SIZE_T
         ('PeakPagefileUsage', ULONG), #SIZE_T
         ('PrivatePageCount', ULONG), #SIZE_T
         ('ImageName', WSTR_STRIPPED), # THIS SHOULD NOT BE HERE
         ('pSid', SID), # THIS SHOULD NOT BE HERE
    )


class PTS_SYS_PROCESS_INFORMATION(NDRPOINTER):
    referent = (
        ('Data', TS_SYS_PROCESS_INFORMATION),
    )

# 2.2.2.15 TS_ALL_PROCESSES_INFO
class TS_ALL_PROCESSES_INFO(NDRSTRUCT):
    structure = (
        ('pTsProcessInfo', TS_SYS_PROCESS_INFORMATION),
        ('SizeOfSid', DWORD),
        ('pSid', TS_CHAR),
    )
 
class TS_ALL_PROCESSES_INFO_ARRAY(NDRUniConformantVaryingArray):
    item = TS_SYS_PROCESS_INFORMATION

class PTS_ALL_PROCESSES_INFO(NDRPOINTER):
    referent = (
        ('Data', TS_ALL_PROCESSES_INFO_ARRAY),
    )    


#NOT_IMPLEMENTED 2.2.2.30 WINSTATIONCONFIG2
class WINSTATIONCONFIG2(NDRSTRUCT):
    pass

#NOT_IMPLEMENTED 2.2.2.44 CLIENT_STACK_ADDRESS
class CLIENT_STACK_ADDRESS(NDRSTRUCT):
    pass


################################################################################
# RPC CALLS
################################################################################

# 3.3.4.1 TermSrvSession Methods 484809d6-4239-471b-b5bc-61df8c23ac48 \pipe\LSM_API_service
# 3.3.4.1.1 RpcOpenSession (Opnum 0)
class RpcOpenSession(NDRCALL):
    opnum = 0
    structure = (
        ('SessionId', ULONG),
        ('phSession', handle_t),
    )

class RpcOpenSessionResponse(NDRCALL):
    structure = (
        ('phSession', SESSION_HANDLE),
        ('ErrorCode', ULONG),
    )

# 3.3.4.1.2 RpcCloseSession (Opnum 1)
class RpcCloseSession(NDRCALL):
    opnum = 1
    structure = (
        ('phSession', SESSION_HANDLE),
    )

class RpcCloseSessionResponse(NDRCALL):
    structure = (
        ('ErrorCode', ULONG),
    )

# 3.3.4.1.3 RpcConnect (Opnum 2)
class RpcConnect(NDRCALL):
    opnum = 2
    structure = (
        ('hSession', SESSION_HANDLE),
        ('TargetSessionId', LONG),
        ('szPassword', WSTR)
    )

class RpcConnectResponse(NDRCALL):
    structure = (
        ('ErrorCode', ULONG),
    )

# 3.3.4.1.4 RpcDisconnect (Opnum 3)
class RpcDisconnect(NDRCALL):
    opnum = 3
    structure = (
        ('hSession', SESSION_HANDLE),
    )

class RpcDisconnectResponse(NDRCALL):
    structure = (
        ('ErrorCode', ULONG),
    )

# 3.3.4.1.5 RpcLogoff (Opnum 4)
class RpcLogoff(NDRCALL):
    opnum = 4
    structure = (
        ('hSession', SESSION_HANDLE),
    )

class RpcLogoffResponse(NDRCALL):
    structure = (
        ('ErrorCode', ULONG),
    )

# 3.3.4.1.6 RpcGetUserName (Opnum 5)
class RpcGetUserName(NDRCALL):
    opnum = 5
    structure = (
        ('hSession', SESSION_HANDLE),
    )

class RpcGetUserNameResponse(NDRCALL):
    structure = (
        ('pszUserName', LPWCHAR_STRIPPED
        ),
        ('pszDomain', LPWCHAR_STRIPPED),
        ('ErrorCode', ULONG),
    )

# 3.3.4.1.7 RpcGetTerminalName (Opnum 6)
class RpcGetTerminalName(NDRCALL):
    opnum = 6
    structure = (
        ('hSession', SESSION_HANDLE),
    )

class RpcGetTerminalNameResponse(NDRCALL):
    structure = (
        ('pszTerminalName', LPWCHAR_STRIPPED),
        ('ErrorCode', ULONG),
    )

# 3.3.4.1.8 RpcGetState (Opnum 7)
class RpcGetState(NDRCALL):
    opnum = 7
    structure = (
        ('hSession', SESSION_HANDLE),
    )

class RpcGetStateResponse(NDRCALL):
    structure = (
        ('plState', WINSTATIONSTATECLASS),
        ('ErrorCode', ULONG),
    )

# 3.3.4.1.9 RpcIsSessionDesktopLocked (Opnum 8)
class RpcIsSessionDesktopLocked(NDRCALL):
    opnum = 8
    structure = (
        ('hSession', SESSION_HANDLE),
    )

class RpcIsSessionDesktopLockedResponse(NDRCALL):
    structure = (
        ('ErrorCode', ULONG),
    )

# 3.3.4.1.10 RpcShowMessageBox (Opnum 9)
class RpcShowMessageBox(NDRCALL):
    opnum = 9
    structure = (
        ('hSession', SESSION_HANDLE),
        ('szTitle', WSTR),
        ('szMessage', WSTR),
        ('ulStyle', ULONG),
        ('ulTimeout', ULONG),
        ('bDoNotWait', BOOL),
    )

class RpcShowMessageBoxResponse(NDRCALL):
    structure = (
        ('pulResponse', MSGBOX_ENUM),
        ('ErrorCode', ULONG),
    )

# 3.3.4.1.11 RpcGetTimes (Opnum 10)
class RpcGetTimes(NDRCALL):
    opnum = 10
    structure = (
        ('hSession', SESSION_HANDLE),
    )

class RpcGetTimesResponse(NDRCALL):
    structure = (
        ('pConnectTime', SYSTEM_TIMESTAMP),
        ('pDisconnectTime', SYSTEM_TIMESTAMP),
        ('pLogonTime', SYSTEM_TIMESTAMP),
        ('ErrorCode', ULONG),
    )

# 3.3.4.1.12 RpcGetSessionCounters (Opnum 11)
class RpcGetSessionCounters(NDRCALL):
    opnum = 11
    structure = (
        ('hBinding', handle_t),
        ('uEntries', LONG),
    )

class RpcGetSessionCountersResponse(NDRCALL):
    structure = (
        ('pCounter', PTS_COUNTER),
        ('ErrorCode', ULONG),
    )

# 3.3.4.1.13 RpcGetSessionInformation (Opnum 12)
class RpcGetSessionInformation(NDRCALL):
    opnum = 12
    structure = (
        ('SessionId', LONG),
    )
class RpcGetSessionInformationResponse(NDRCALL):
    structure = (
        ('pSessionInfo', LSMSESSIONINFORMATION),
        ('ErrorCode', ULONG),
    )

#OLD 3.2.4.1.14 RpcSwitchToServicesSession (Opnum 13)
class RpcSwitchToServicesSession(NDRCALL):
    opnum = 13
    structure = (
        ('hBinding', handle_t),
    )

class RpcSwitchToServicesSessionResponse(NDRCALL):
    structure = (
        ('ErrorCode', ULONG),
    )
#OLD 3.2.4.1.15 RpcRevertFromServicesSession (Opnum 14)
class RpcRevertFromServicesSession(NDRCALL):
    opnum = 14
    structure = (
        ('hBinding', handle_t),
    )

class RpcRevertFromServicesSessionResponse(NDRCALL):
    structure = (
        ('ErrorCode', ULONG),
    )

# 3.3.4.1.14 RpcGetLoggedOnCount (Opnum 15)
class RpcGetLoggedOnCount(NDRCALL):
    opnum = 15
    structure = (
        ('hBinding', handle_t),
    )

class RpcGetLoggedOnCountResponse(NDRCALL):
    structure = (
        ('pUserSessions', ULONG),
        ('pDeviceSessions', ULONG),
        ('ErrorCode', ULONG),
    )

# 3.3.4.1.15 RpcGetSessionType (Opnum 16)
class RpcGetSessionType(NDRCALL):
    opnum = 16
    structure = (
        ('SessionId', LONG),
    )

class RpcGetSessionTypeResponse(NDRCALL):
    structure = (
        ('pSessionType', SESSIONTYPE),
        ('ErrorCode', ULONG),
    )

# 3.3.4.1.16 RpcGetSessionInformationEx (Opnum 17)
class RpcGetSessionInformationEx(NDRCALL):
    opnum = 17
    structure = (
        ('SessionId', LONG),
        ('Level', DWORD),
    )

class RpcGetSessionInformationExResponse(NDRCALL):
    structure = (
        ('LSMSessionInfoExPtr', PLSMSESSIONINFORMATION_EX),
        ('ErrorCode', ULONG),
    )


# 3.3.4.2 TermSrvNotification (LSM Notification); \PIPE\LSM_API_service; 11899a43-2b68-4a76-92e3-a3d6ad8c26ce
# 3.3.4.2.1 RpcWaitForSessionState (Opnum 0)
class RpcWaitForSessionState(NDRCALL):
    opnum = 0
    structure = (
        ('SessionId', LONG),
        ('State', LONG),
        ('Timeout', ULONG),
    )

class RpcWaitForSessionStateResponse(NDRCALL):
    structure = (
        ('ErrorCode', ULONG),
    )

# 3.3.4.2.2 RpcRegisterAsyncNotification (Opnum 1)
class RpcRegisterAsyncNotification(NDRCALL):
    opnum = 1
    structure = (
        ('SessionId', LONG),
        ('Mask', ULONG),
    )

class RpcRegisterAsyncNotificationResponse(NDRCALL):
    structure = (
        ('phNotify', NOTIFY_HANDLE),
        ('ErrorCode', ULONG),
    )

# 3.3.4.2.3 RpcWaitAsyncNotification (Opnum 2)
class RpcWaitAsyncNotification(NDRCALL):
    opnum = 2
    structure = (
        ('hNotify', context_handle),
    )

class RpcWaitAsyncNotificationResponse(NDRCALL):
    structure = (
        ('SessionChange', PSESSION_CHANGE),
        ('pEntries', ULONG),
        ('ErrorCode', ULONG),
    )

# 3.3.4.2.4 RpcUnRegisterAsyncNotification (Opnum 3)
class RpcUnRegisterAsyncNotification(NDRCALL):
    opnum = 3
    structure = (
        ('hNotify', NOTIFY_HANDLE),
    )

class RpcUnRegisterAsyncNotificationResponse(NDRCALL):
    structure = (
        ('hNotify', NOTIFY_HANDLE),
        ('ErrorCode', ULONG),
    )

# 3.3.4.3 TermSrvEnumeration; 88143fd0-c28d-4b2b-8fef-8d882f6a9390; \pipe\LSM_API_service
# 3.3.4.3.1 RpcOpenEnum (Opnum 0)
class RpcOpenEnum(NDRCALL):
    opnum = 0
    structure = (
        ('hBinding', handle_t),
    )
class RpcOpenEnumResponse(NDRCALL):
    structure = (
        ('phEnum', ENUM_HANDLE),
        ('ErrorCode', ULONG),
    )

# 3.3.4.3.2 RpcCloseEnum (Opnum 1)
class RpcCloseEnum(NDRCALL):
    opnum = 1
    structure = (
        ('phEnum', ENUM_HANDLE),
    )
class RpcCloseEnumResponse(NDRCALL):
    structure = (
        ('phEnum', ENUM_HANDLE),
        ('ErrorCode', ULONG),
    )

#NOT_TESTED 3.3.4.3.3 RpcFilterByState (Opnum 2)
class RpcFilterByState(NDRCALL):
    opnum = 2
    structure = (
        ('hEnum', ENUM_HANDLE),
        ('State', LONG),
        ('bInvert', BOOL),
    )
class RpcFilterByStateResponse(NDRCALL):
    structure = (
        ('ErrorCode', ULONG),
    )

#NOT_TESTED 3.3.4.3.4 RpcFilterByCallersName (Opnum 3)
class RpcFilterByCallersName(NDRCALL):
    opnum = 3
    structure = (
        ('hEnum', ENUM_HANDLE),
    )
class RpcFilterByCallersNameResponse(NDRCALL):
    structure = (
        ('ErrorCode', ULONG),
    )

#NOT_TESTED 3.3.4.3.5 RpcEnumAddFilter (Opnum 4)
class RpcEnumAddFilter(NDRCALL):
    opnum = 4
    structure = (
        ('hEnum', ENUM_HANDLE),
        ('hSubEnum', ENUM_HANDLE),
    )
class RpcEnumAddFilterResponse(NDRCALL):
    structure = (
        ('ErrorCode', ULONG),
    )

# 3.3.4.3.6 RpcGetEnumResult (Opnum 5)
class RpcGetEnumResult(NDRCALL):
    opnum = 5
    structure = (
        ('hEnum', ENUM_HANDLE),
        ('Level', DWORD),
    )

class RpcGetEnumResultResponse(NDRCALL): # strange double tag in union
    structure = (
        ('ppSessionEnumResult', PSESSIONENUM),
        ('pEntries', ULONG),
        ('ErrorCode', ULONG),
    )

#NOT_TESTED 3.3.4.3.7 RpcFilterBySessionType (Opnum 6)
class RpcFilterBySessionType(NDRCALL):
    opnum = 6
    structure = (
        ('hEnum', ENUM_HANDLE),
        ('pSessionType', GUID), # The session GUID to be used to filter out the enumeration result.
                                # Only the session with the specified GUID will be returned
    )
class RpcFilterBySessionTypeResponse(NDRCALL):
    structure = (
        ('ErrorCode', ULONG),
    )

#NOT_TESTED 3.3.4.3.8 RpcGetSessionIds (Opnum 8)
class RpcGetSessionIds(NDRCALL):
    opnum = 8
    structure = (
        ('handle_t', handle_t),
        ('Filter', SESSION_FILTER), # who knows... 
        ('MaxEntries', ULONG),
    )
class RpcGetSessionIdsResponse(NDRCALL):
    structure = (
        ('pSessionIds', LONG_ARRAY),
        ('pcSessionIds', ULONG),
        ('ErrorCode', ULONG),
    )

# 3.3.4.3.9 RpcGetEnumResultEx (Opnum 9)
class RpcGetEnumResultEx(NDRCALL):
    opnum = 9
    structure = (
        ('hEnum', ENUM_HANDLE),
        ('Level', DWORD),
    )

class RpcGetEnumResultExResponse(NDRCALL):
    structure = (
        ('ppSessionEnumResult', PSESSIONENUM),
        ('pEntries', ULONG),
        ('ErrorCode', ULONG),
    )

# 3.3.4.3.10 RpcGetAllSessions (Opnum 10)
class RpcGetAllSessions(NDRCALL):
    opnum = 10
    structure = (
        ('pLevel', ULONG),
    )

class RpcGetAllSessionsResponse(NDRCALL):
    # strange double tag in union
    structure = (
        ('pLevel', ULONG),
        ('ppSessionData', PEXECENVDATA),
        ('pcEntries', ULONG),
        ('ErrorCode', ULONG),
    )

#NOT_IMPLEMENTED 3.3.4.3.11 RpcGetAllSessionsEx (Opnum 11)
class RpcGetAllSessionsEx(NDRCALL):
    opnum = 11
    structure = (
        ('Level', ULONG),
    )

class RpcGetAllSessionsExResponse(NDRCALL):
    # giving up to parse it
    structure = (
        ('Buffer', UNKNOWNDATA),
    )
    
# 3.5.4.1 RCMPublic bde95fdf-eee0-45de-9e12-e5a61cd0d4fe \pipe\TermSrv_API_service
# 3.5.4.1.1 RpcGetClientData (Opnum 0)
class RpcGetClientData(NDRCALL):
    opnum = 0
    structure = (
        ('SessionId', ULONG),
    )

class RpcGetClientDataResponse(NDRCALL):
    structure = (
        ('ppBuff', PWINSTATIONCLIENT),
        ('pOutBuffByteLen', ULONG),
        ('ErrorCode', ULONG),
    )

# 3.5.4.1.2 RpcGetConfigData (Opnum 1)
class RpcGetConfigData(NDRCALL):
    opnum = 1
    structure = (
        ('SessionId', ULONG),
    )

class RpcGetConfigDataResponse(NDRCALL):
    # Note: there is a probability of wrong flags parsing.
    structure = (
        ('ppBuff', PWINSTATIONCONFIG),
        ('pOutBuffByteLen', ULONG),
        ('ErrorCode', ULONG),
    )

#NOT_IMPLEMENTED 3.5.4.1.3 RpcGetProtocolStatus (Opnum 2)
class RpcGetProtocolStatus(NDRCALL):
    opnum = 2
    structure = (
        ('SessionId', ULONG),
        ('InfoType', PROTOCOLSTATUS_INFO_TYPE),
    )

class RpcGetProtocolStatusResponse(NDRCALL):
    structure = (
        ('ppProtoStatus', PROTOCOLSTATUS_INFO_TYPE),
        ('pcbProtoStatus', PPROTOCOLSTATUS),
        ('ErrorCode', ULONG),
    )

# 3.5.4.1.4 RpcGetLastInputTime (Opnum 3)
class RpcGetLastInputTime(NDRCALL):
    opnum = 3
    structure = (
        ('SessionId', ULONG),
    )

class RpcGetLastInputTimeResponse(NDRCALL):
    structure = (
        ('pLastInputTime', SYSTEM_TIMESTAMP),
        ('ErrorCode', ULONG),
    )

# 3.5.4.1.5 RpcGetRemoteAddress (Opnum 4)
class RpcGetRemoteAddress(NDRCALL):
    opnum = 4
    structure = (
        ('SessionId', ULONG),
    )

class RpcGetRemoteAddressResponse(NDRCALL):
    structure = (
        ('pRemoteAddress', RCM_REMOTEADDRESS),
        ('ErrorCode', ULONG),
    )

#OLD 3.4.4.1.6 RpcShadow (Opnum 5)
# Probably deprecated. Taken from [MS-TSTS] – v20080207
class RpcShadow(NDRCALL):
    opnum = 5
    structure = (
        ('szTargetServerName', WSTR),
        ('TargetSessionId', ULONG),
        ('HotKeyVk', BYTE),
        ('HotkeyModifiers', USHORT),
    )

class RpcShadowResponse(NDRCALL):
    structure = (
        ('ErrorCode', ULONG),
    )

#OLD 3.4.4.1.7 RpcShadowTarget (Opnum 6)
# Probably deprecated. Taken from [MS-TSTS] – v20080207
class RpcShadowTarget(NDRCALL):
    '''
    HRESULT RpcShadowTarget(
    [in] handle_t hBinding,
    [in] ULONG SessionId,
    [in, size_is(ConfigSize)] PBYTE pConfig,
    [in, range(0, 0x8000)] ULONG ConfigSize,
    [in, size_is(AddressSize)] PBYTE pAddress,
    [in, range(0, 0x1000)] ULONG AddressSize,
    [in, size_is(ModuleDataSize)] PBYTE pModuleData,
    [in, range(0, 0x1000)] ULONG ModuleDataSize,
    [in, size_is(ThinwireDataSize)]
    PBYTE pThinwireData,
    [in, range(0, 0x1000)] ULONG ThinwireDataSize,
    [in, string] WCHAR* szClientName
    );
    '''
    opnum = 6

class RpcShadowTargetResponse(NDRCALL):
    structure = (
        ('Buffer', UNKNOWNDATA),
    )

#OLD 3.4.4.1.8 RpcShadowStop (Opnum 7)
# Probably deprecated. Taken from [MS-TSTS] – v20080207
class RpcShadowStop(NDRCALL):
    opnum = 7
    structure = (
        ('SessionId', ULONG),
    )

class RpcShadowStopResponse(NDRCALL):
    structure = (
        ('ErrorCode', ULONG),
    )


# 3.5.4.1.6 RpcGetAllListeners (Opnum 8)
class RpcGetAllListeners(NDRCALL):
    opnum = 8
    structure = (
        ('Level', DWORD),
    )

class RpcGetAllListenersResponse(NDRCALL):
    structure = (
        ('ppListeners', PLISTENERENUM),
        ('pNumListeners', ULONG),
        ('ErrorCode', ULONG),
    )

#NOT_IMPLEMENTED 3.5.4.1.7 RpcGetSessionProtocolLastInputTime (Opnum 9)
class RpcGetSessionProtocolLastInputTime(NDRCALL):
    opnum = 9
    '''
    HRESULT RpcGetSessionProtocolLastInputTime(
    [in] handle_t hBinding,
    [in] ULONG SessionId,
    [in] PROTOCOLSTATUS_INFO_TYPE InfoType,
    [out, size_is(,*pcbProtoStatus )]
    unsigned char** ppProtoStatus,
    [out] ULONG* pcbProtoStatus,
    [out] hyper* pLastInputTime
    );
    '''

class RpcGetSessionProtocolLastInputTimeResponse(NDRCALL):
    structure = (
        ('Data', UNKNOWNDATA),
    )

#NOT_IMPLEMENTED 3.5.4.1.8 RpcGetUserCertificates (Opnum 10)
class RpcGetUserCertificates(NDRCALL):
    opnum = 10
    '''
    HRESULT RpcGetUserCertificates(
    [in] handle_t hBinding,
    [in] ULONG SessionId,
    [out] ULONG* pcCerts,
    [out, size_is(, *pcbCerts)] byte** ppbCerts,
    [out] ULONG* pcbCerts
    );'''

class RpcGetUserCertificatesResponse(NDRCALL):
    structure = (
        ('Data', UNKNOWNDATA),
    )

#NOT_IMPLEMENTED 3.5.4.1.9 RpcQuerySessionData (Opnum 11)
class RpcQuerySessionData(NDRCALL):
    # Was unsuccess to implement this
    '''
    HRESULT RpcQuerySessionData(
        [in] handle_t hBinding,
        [in] ULONG SessionId,
        [in] QUERY_SESSION_DATA_TYPE type,
        [in, unique, size_is(cbInputData )] byte* pbInputData,
        [in, range(0, 8192)] DWORD cbInputData,
        [out, ref, size_is(cbSessionData), length_is(*pcbReturnLength)] byte* pbSessionData,
        [in, range(0, 8192)] ULONG cbSessionData,
        [out, ref] ULONG* pcbReturnLength,
        [out, ref] ULONG* pcbRequireBufferSize
    );
    '''
    opnum = 11

class RpcQuerySessionDataResponse(NDRCALL):
    structure = (
        ('Buffer', UNKNOWNDATA),
    )


# 3.5.4.2 RCMListener 497d95a6-2d27-4bf5-9bbd-a6046957133c \pipe\TermSrv_API_service or \pipe\Ctx_WinStation_API_service
# 3.5.4.2.1 RpcOpenListener (Opnum 0)
class RpcOpenListener(NDRCALL):
    opnum = 0
    structure = (
        ('szListenerName', WSTR),
    )

class RpcOpenListenerResponse(NDRCALL):
    structure = (
        ('phListener', HLISTENER),
        ('ErrorCode', ULONG),
    )

# 3.5.4.2.2 RpcCloseListener (Opnum 1)
class RpcCloseListener(NDRCALL):
    opnum = 1
    structure = (
        ('phListener', HLISTENER),
    )

class RpcCloseListenerResponse(NDRCALL):
    structure = (
        ('phListener', HLISTENER),
        ('ErrorCode', ULONG),
    )

# 3.5.4.2.3 RpcStopListener (Opnum 2)
class RpcStopListener(NDRCALL):
    opnum = 2
    structure = (
        ('phListener', HLISTENER),
    )

class RpcStopListenerResponse(NDRCALL):
    structure = (
        ('ErrorCode', ULONG),
    )

# 3.5.4.2.4 RpcStartListener (Opnum 3)
class RpcStartListener(NDRCALL):
    opnum = 3
    structure = (
        ('phListener', HLISTENER),
    )

class RpcStartListenerResponse(NDRCALL):
    structure = (
        ('ErrorCode', ULONG),
    )

# 3.5.4.2.5 RpcIsListening (Opnum 4)
class RpcIsListening(NDRCALL):
    opnum = 4
    structure = (
        ('phListener', HLISTENER),
    )

class RpcIsListeningResponse(NDRCALL):
    structure = (
        ('pbIsListening', BOOLEAN),
        ('ErrorCode', ULONG),
    )

# 3.7.4.1 LegacyApi 5ca4a760-ebb1-11cf-8611-00a0245420ed \pipe\Ctx_WinStation_API_service
# 3.7.4.1.1 RpcWinStationOpenServer (Opnum 0)
class RpcWinStationOpenServer(NDRCALL):
    opnum = 0
    structure = (
        ('hBinding', handle_t),
    )

class RpcWinStationOpenServerResponse(NDRCALL):
    structure = (
        ('pResult', pResult_ENUM),
        ('phServer', SERVER_HANDLE),
        ('ErrorCode', BOOLEAN),
    )

# 3.7.4.1.2 RpcWinStationCloseServer (Opnum 1)
class RpcWinStationCloseServer(NDRCALL):
    opnum = 1
    structure = (
        ('hServer', SERVER_HANDLE),
    )

class RpcWinStationCloseServerResponse(NDRCALL):
    structure = (
        ('pResult', pResult_ENUM),
        ('ErrorCode', BOOLEAN),
    )

#FIXME 3.7.4.1.3 RpcIcaServerPing (Opnum 2) 
# Expected TRUE got FALSE
class RpcIcaServerPing(NDRCALL):
    opnum = 2
    structure = (
        ('hServer', SERVER_HANDLE),
    )

class RpcIcaServerPingResponse(NDRCALL):
    structure = (
        ('pResult', pResult_ENUM),
        ('ErrorCode', BOOLEAN),
    )

#NOT_IMPLEMENTED 3.7.4.1.4 RpcWinStationEnumerate (Opnum 3)
# Could not guess input types :(
class RpcWinStationEnumerate(NDRCALL):
    '''
    BOOLEAN RpcWinStationEnumerate(
    [in] SERVER_HANDLE hServer,
    [out] DWORD* pResult,
    [in, out] PULONG pEntries,
    [in, out, unique, size_is(*pByteCount)]
    PCHAR pLogonId,
    [in, out] PULONG pByteCount,
    [in, out] PULONG pIndex
    );
    '''    
    opnum = 3
    structure = (
        ('hServer', SERVER_HANDLE),
        ('pEntries', PULONG),
        ('pLogonId', PCHAR),
        ('pByteCount', PULONG),
        ('pIndex', PULONG),
    )

class RpcWinStationEnumerateResponse(NDRCALL):
    structure = (
        ('pResult', UNKNOWNDATA),
    )

#NOT_IMPLEMENTED 3.7.4.1.5 RpcWinStationRename (Opnum 4)
# return: 0x00000000, False. Nothing was changed. No error :(
class RpcWinStationRename(NDRCALL):
    '''
    BOOLEAN RpcWinStationRename(
        [in] SERVER_HANDLE hServer,
        [out] DWORD* pResult,
        [in, size_is(NameOldSize)] PWCHAR pWinStationNameOld,
        [in, range(0, 256)] DWORD NameOldSize,
        [in, size_is(NameNewSize)] PWCHAR pWinStationNameNew,
        [in, range(0, 256)] DWORD NameNewSize
    );
    '''
    opnum = 4
    structure = (
        ('hServer', SERVER_HANDLE),
        ('pWinStationNameOld', TS_WCHAR),
        ('NameOldSize', '<L=len(pWinStationNameOld["Data"])'),
        ('pWinStationNameNew', TS_WCHAR),
        ('NameNewSize', '<L=len(pWinStationNameNew["Data"])'),
    )

class RpcWinStationRenameResponse(NDRCALL):
    structure = (
        ('pResult', pResult_ENUM),
        ('ErrorCode', BOOLEAN),
    )

#NOT_IMPLEMENTED 3.7.4.1.6 RpcWinStationQueryInformation (Opnum 5)
#TODO needs implementing a lot of different structures to meet requirements in the call
class RpcWinStationQueryInformation(NDRCALL):
    '''
    BOOLEAN RpcWinStationQueryInformation(
        [in] SERVER_HANDLE hServer,
        [out] DWORD* pResult,
        [in] DWORD LogonId,
        [in] DWORD WinStationInformationClass,
        [in, out, unique, size_is(WinStationInformationLength)]
        PCHAR pWinStationInformation,
        [in, range(0, 0x8000)] DWORD WinStationInformationLength,
        [out] DWORD* pReturnLength
    );
    '''
    opnum = 5
    structure = (
        ('hServer', SERVER_HANDLE),
        ('LogonId', DWORD),
        ('WinStationInformationClass', DWORD),
        # ('pWinStationInformation', TS_WCHAR),
        # ('WinStationInformationLength', DWORD),
        ('buff', ':'),
    )

class RpcWinStationQueryInformationResponse(NDRCALL):
    structure = (
        ('Buffer', UNKNOWNDATA),
    )

#NOT_IMPLEMENTED 3.7.4.1.7 RpcWinStationSetInformation (Opnum 6)
#TODO needs implementing a lot of different structures to meet requirements in the call
class RpcWinStationSetInformation(NDRCALL):
    '''
    BOOLEAN RpcWinStationSetInformation(
    [in] SERVER_HANDLE hServer,
    [out] DWORD* pResult,
    [in] DWORD LogonId,
    [in] DWORD WinStationInformationClass,
    [in, out, unique, size_is(WinStationInformationLength)]
    PCHAR pWinStationInformation,
    [in, range(0, 0x8000)] DWORD WinStationInformationLength
    );
    '''
    opnum = 6
class RpcWinStationSetInformationResponse(NDRCALL):
    structure = (
        ('Buffer', UNKNOWNDATA),
    )

# 3.7.4.1.8 RpcWinStationSendMessage (Opnum 7)
class RpcWinStationSendMessage(NDRCALL):
    opnum = 7
    structure = (
        ('hServer', SERVER_HANDLE),
        ('LogonId', DWORD),
        ('pTitle', TS_WCHAR),
        ('TitleLength', '<L=len(pTitle["Data"])'),
        ('pMessage', TS_WCHAR),
        ('MessageLength', '<L=len(pMessage["Data"])'),
        ('Style', DWORD),
        ('Timeout', DWORD),
        ('DoNotWait', BOOLEAN),
    )    
class RpcWinStationSendMessageResponse(NDRCALL):
    structure = (
        ('pResult', pResult_ENUM),
        ('pResponse', DWORD),
        ('ErrorCode', BOOLEAN),
    )
    
# 3.7.4.1.9 RpcLogonIdFromWinStationName (Opnum 8)
class RpcLogonIdFromWinStationName(NDRCALL):
    opnum = 8
    structure = (
        ('hServer', SERVER_HANDLE),
        ('pWinStationName', TS_WCHAR),
        ('NameSize', '<L=len(pWinStationName["Data"])'),
    )

class RpcLogonIdFromWinStationNameResponse(NDRCALL):
    structure = (
        ('pResult', pResult_ENUM),
        ('pLogonId', DWORD),
        ('ErrorCode', BOOLEAN),
    )

# 3.7.4.1.10 RpcWinStationNameFromLogonId (Opnum 9)
class RpcWinStationNameFromLogonId(NDRCALL):
    opnum = 9
    structure = (
        ('hServer', SERVER_HANDLE),
        ('LoginId', DWORD),
        ('pWinStationName', TS_WCHAR),
        ('NameSize', '<L=%d' % (WINSTATIONNAME_LENGTH+1)),
    )

class RpcWinStationNameFromLogonIdResponse(NDRCALL):
    structure = (
        ('pResult', pResult_ENUM),
        ('pWinStationName', TS_WCHAR_STRIPPED),
        ('ErrorCode', BOOLEAN),
    )

# 3.7.4.1.11 RpcWinStationConnect (Opnum 10)
class RpcWinStationConnect(NDRCALL):
    opnum = 10
    structure = (
        ('hServer', SERVER_HANDLE),
        ('ClientLogonId', DWORD),
        ('ConnectLogonId', DWORD),
        ('TargetLogonId', DWORD),
        ('pPassword', TS_WCHAR),
        ('PasswordSize', '<L=len(pPassword["Data"])'),
        ('Wait', BOOLEAN),
    )

class RpcWinStationConnectResponse(NDRCALL):
    structure = (
        ('pResult', pResult_ENUM),
        ('ErrorCode', BOOLEAN),
    )
#OLD 3.6.4.1.12 RpcWinStationVirtualOpen (Opnum 11)
# Does not work remotely
class RpcWinStationVirtualOpen(NDRCALL):
    opnum = 11
    structure = (
        ('hServer', SERVER_HANDLE),
        ('LogonId', DWORD),
        ('Pid', DWORD),
        ('pVirtualName', TS_CHAR),
        ('NameSize', '<L=len(pVirtualName["Data"])'),
    ) 
class RpcWinStationVirtualOpenResponse(NDRCALL):
    structure = (
        ('pResult', pResult_ENUM),
        ('pHandle', ULONG),
        ('ErrorCode', BOOLEAN),
    )    
#OLD 3.6.4.1.13 RpcWinStationBeepOpen (Opnum 12)
# Does not work remotely
class RpcWinStationBeepOpen(NDRCALL):
    opnum = 12
    structure = (
        ('hServer', SERVER_HANDLE),
        ('LogonId', DWORD),
        ('Pid', DWORD),
    ) 
class RpcWinStationBeepOpenResponse(NDRCALL):
    structure = (
        ('pResult', pResult_ENUM),
        ('pHandle', ULONG),
        ('ErrorCode', BOOLEAN),
    ) 
# 3.7.4.1.12 RpcWinStationDisconnect (Opnum 13)
class RpcWinStationDisconnect(NDRCALL):
    opnum = 13
    structure = (
        ('hServer', SERVER_HANDLE),
        ('LoginId', DWORD),
        ('bWait', BOOLEAN),
    )

class RpcWinStationDisconnectResponse(NDRCALL):
    structure = (
        ('pResult', pResult_ENUM),
        ('ErrorCode', BOOLEAN),
    )
# 3.7.4.1.13 RpcWinStationReset (Opnum 14)
class RpcWinStationReset(NDRCALL):
    opnum = 14
    structure = (
        ('hServer', SERVER_HANDLE),
        ('LogonId', DWORD),
        ('bWait', BOOLEAN),
    )

class RpcWinStationResetResponse(NDRCALL):
    structure = (
        ('pResult', pResult_ENUM),
        ('ErrorCode', BOOLEAN),
    ) 
# 3.7.4.1.14 RpcWinStationShutdownSystem (Opnum 15)
class RpcWinStationShutdownSystem(NDRCALL):
    opnum = 15
    structure = (
        ('hServer', SERVER_HANDLE),
        ('ClientLogonId', DWORD),
        ('ShutdownFlags', DWORD),
    )

class RpcWinStationShutdownSystemResponse(NDRCALL):
    structure = (
        ('pResult', pResult_ENUM),
        ('ErrorCode', BOOLEAN),
    ) 
# 3.7.4.1.15 RpcWinStationWaitSystemEvent (Opnum 16)
class RpcWinStationWaitSystemEvent(NDRCALL):
    opnum = 16
    structure = (
        ('hServer', SERVER_HANDLE),
        ('EventMask', DWORD),
    )

class RpcWinStationWaitSystemEventResponse(NDRCALL):
    structure = (
        ('pResult', pResult_ENUM),
        ('pEventFlags', DWORD),
        ('ErrorCode', BOOLEAN),
    ) 
# 3.7.4.1.16 RpcWinStationShadow (Opnum 17)
# Does not work :(
class RpcWinStationShadow(NDRCALL):
    opnum = 17
    structure = (
        ('hServer', SERVER_HANDLE),
        ('LogonId', DWORD),
        ('pTargetServerName', TS_LPWCHAR),
        ('NameSize', '<L=len(pTargetServerName["Data"])'),
        ('TargetLogonId', DWORD),
        ('HotKeyVk', BYTE),
        ('HotkeyModifiers', USHORT),
    )

class RpcWinStationShadowResponse(NDRCALL):
    structure = (
        ('pResult', pResult_ENUM),
        ('ErrorCode', BOOLEAN),
    )
#OLD 3.6.4.1.19 RpcWinStationShadowTargetSetup (Opnum 18)
class RpcWinStationShadowTargetSetup(NDRCALL):
    opnum = 18
    structure = (
        ('hServer', SERVER_HANDLE),
        ('LogonId', DWORD),
    )

class RpcWinStationShadowTargetSetupResponse(NDRCALL):
    structure = (
        ('pResult', pResult_ENUM),
        ('ErrorCode', BOOLEAN),
    )
#OLD 3.6.4.1.20 RpcWinStationShadowTarget (Opnum 19)
# Not tested
class RpcWinStationShadowTarget(NDRCALL):
    opnum = 19
    '''
    BOOLEAN RpcWinStationShadowTarget(
        [in] SERVER_HANDLE hServer,
        [out] DWORD* pResult,
        [in] DWORD LogonId,
        [in, size_is(ConfigSize)] PBYTE pConfig,
        [in, range(0, 0x8000)] DWORD ConfigSize,
        [in, size_is(AddressSize)] PBYTE pAddress,
        [in, range(0, 0x1000 )] DWORD AddressSize,
        [in, size_is(ModuleDataSize)] PBYTE pModuleData,
        [in, range(0, 0x1000 )] DWORD ModuleDataSize,
        [in, size_is(ThinwireDataSize)]
        PBYTE pThinwireData,
        [in] DWORD ThinwireDataSize,
        [in, size_is(ClientNameSize)] PBYTE pClientName,
        [in, range(0, 1024 )] DWORD ClientNameSize
    );
    '''
    structure = (
        ('hServer', SERVER_HANDLE),
        ('LogonId', DWORD),
        ('pConfig', PBYTE),
        ('ConfigSize', DWORD),
        ('pAddress', PBYTE),
        ('AddressSize', DWORD),
        ('pModuleData', PBYTE),
        ('ModuleDataSize', DWORD),
        ('pThinwireData', PBYTE),
        ('ThinwireDataSize', DWORD),
        ('pClientName', STR),
        ('ClientNameSize', DWORD),
    )

class RpcWinStationShadowTargetResponse(NDRCALL):
    structure = (
        ('pResult', pResult_ENUM),
        ('ErrorCode', BOOLEAN),
    )

#OLD 3.6.4.1.21 RpcWinStationSetPoolCount (Opnum 26)
# Not tested
class RpcWinStationSetPoolCount(NDRCALL):
    opnum = 26
    structure = (
        ('hServer', SERVER_HANDLE),
        ('pLicense', TS_CHAR),
        ('LicenseSize', '<L=len(pLicense["Data"])'),
    )

class RpcWinStationSetPoolCountResponse(NDRCALL):
    structure = (
        ('pResult', pResult_ENUM),
        ('ErrorCode', BOOLEAN),
    )
#OLD 3.6.4.1.22 RpcWinStationQueryUpdateRequired (Opnum 27)
# Not tested
class RpcWinStationQueryUpdateRequired(NDRCALL):
    opnum = 27
    structure = (
        ('hServer', SERVER_HANDLE),
    )

class RpcWinStationQueryUpdateRequiredResponse(NDRCALL):
    structure = (
        ('pResult', pResult_ENUM),
        ('pUpdateFlag', DWORD),
        ('ErrorCode', BOOLEAN),
    )
#OLD 3.6.4.1.23 RpcWinStationCallback (Opnum 28)
# Not tested 
class RpcWinStationCallback(NDRCALL):
    opnum = 28
    '''
    BOOLEAN RpcWinStationCallback(
        [in] SERVER_HANDLE hServer,
        [out] DWORD* pResult,
        [in] DWORD LogonId,
        [in, size_is(PhoneNumberSize)]
        PWCHAR pPhoneNumber,
        [in, range(0, 0x1000 )] DWORD PhoneNumberSize
    );
    '''
    structure = (
        ('hServer', SERVER_HANDLE),
        ('LogonId', DWORD),
        ('pPhoneNumber', TS_WCHAR),
        ('PhoneNumberSize', '<L=len(pPhoneNumber["Data"])'),
    )

class RpcWinStationCallbackResponse(NDRCALL):
    structure = (
        ('pResult', pResult_ENUM),
        ('ErrorCode', BOOLEAN),
    )
    
# 3.7.4.1.17 RpcWinStationBreakPoint (Opnum 29)
class RpcWinStationBreakPoint(NDRCALL):
    opnum = 29
    structure = (
        ('hServer', SERVER_HANDLE),
        ('LogonId', DWORD),
        ('KernelFlag', BOOLEAN),
    )

class RpcWinStationBreakPointResponse(NDRCALL):
    structure = (
        ('pResult', pResult_ENUM),
        ('ErrorCode', BOOLEAN),
    )
# 3.7.4.1.18 RpcWinStationReadRegistry (Opnum 30)
# Does not work
class RpcWinStationReadRegistry(NDRCALL):
    opnum = 30
    structure = (
        ('hServer', SERVER_HANDLE),
    )

class RpcWinStationReadRegistryResponse(NDRCALL):
    structure = (
        ('pResult', pResult_ENUM),
        ('ErrorCode', BOOLEAN),
    )
#OLD 3.6.4.1.26 RpcWinStationWaitForConnect (Opnum 31)
# Does not work
class RpcWinStationWaitForConnect(NDRCALL):
    opnum = 31
    structure = (
        ('hServer', SERVER_HANDLE),
        ('ClientLogonId', DWORD),
        ('ClientProcessId', DWORD),
    )

class RpcWinStationWaitForConnectResponse(NDRCALL): 
    structure = (
        ('pResult', pResult_ENUM),
        ('ErrorCode', BOOLEAN),
    )
#OLD 3.6.4.1.27 RpcWinStationNotifyLogon (Opnum 32)
# Unknown
class RpcWinStationNotifyLogon(NDRCALL):
    opnum = 32
    structure = (
        ('hServer', SERVER_HANDLE),
        ('ClientLogonId', DWORD),
        ('ClientProcessId', DWORD),
        ('fUserIsAdmin', BOOLEAN),
        ('UserToken', DWORD),
        ('pDomain', TS_WCHAR),
        ('DomainSize', '<L=len(pDomain["Data"])'),
        ('pUserName', TS_WCHAR),
        ('UserNameSize', '<L=len(pUserName["Data"])'),
        ('pPassword', TS_WCHAR),
        ('PasswordSize', '<L=len(pPassword["Data"])'),
        ('Seed', UCHAR),
        ('pUserConfig', TS_CHAR),
        ('ConfigSize', '<L=len(pUserConfig["Data"])'),
        ('pfIsRedirected', DWORD),
    )

class RpcWinStationNotifyLogonResponse(NDRCALL): 
    structure = (
        ('pResult', pResult_ENUM),
        ('pfIsRedirected', BOOLEAN),
        ('ErrorCode', BOOLEAN),
    )

#OLD 3.6.4.1.28 RpcWinStationNotifyLogoff (Opnum 33)
# Unknown
class RpcWinStationNotifyLogoff(NDRCALL):
    opnum = 33
    structure = (
        ('hServer', SERVER_HANDLE),
        ('ClientLogonId', DWORD),
        ('ClientProcessId', DWORD),
    )

class RpcWinStationNotifyLogoffResponse(NDRCALL): 
    structure = (
        ('pResult', pResult_ENUM),
        ('ErrorCode', BOOLEAN),
    )
# 3.7.4.1.19 OldRpcWinStationEnumerateProcesses (Opnum 34)
# Does not work
class OldRpcWinStationEnumerateProcesses(NDRCALL):
    opnum = 34
    structure = (
        ('hServer', SERVER_HANDLE),
        ('ByteCount', DWORD),
    )

class OldRpcWinStationEnumerateProcessesResponse(NDRCALL):
    structure = (
        ('pResult', pResult_ENUM),
        ('pProcessBuffer', TS_CHAR),
        ('ErrorCode', BOOLEAN),
    )
#OLD 3.6.4.1.29 RpcWinStationAnnoyancePopup (Opnum 35)
# Does not work
class RpcWinStationAnnoyancePopup(NDRCALL):
    opnum = 35
    structure = (
        ('hServer', SERVER_HANDLE),
        ('LogonIdld', DWORD),
    )

class RpcWinStationAnnoyancePopupResponse(NDRCALL):
    structure = (
        ('pResult', pResult_ENUM),
        ('ErrorCode', BOOLEAN),
        ('buff', UNKNOWNDATA),
    )

# 3.7.4.1.20 RpcWinStationEnumerateProcesses (Opnum 36)
# Does not work
class RpcWinStationEnumerateProcesses(NDRCALL):
    opnum = 36
    structure = (
        ('hServer', SERVER_HANDLE),
        ('ByteCount', DWORD),
    )

class RpcWinStationEnumerateProcessesResponse(NDRCALL):
    structure = (
        ('pResult', pResult_ENUM),
        ('pProcessBuffer', TS_CHAR),
        ('ErrorCode', BOOLEAN),
    )
# 3.7.4.1.21 RpcWinStationTerminateProcess (Opnum 37)
class RpcWinStationTerminateProcess(NDRCALL):
    opnum = 37
    structure = (
        ('hServer', SERVER_HANDLE),
        ('ProcessId', DWORD),
        ('ExitCode', DWORD),
    )

class RpcWinStationTerminateProcessResponse(NDRCALL):
    structure = (
        ('pResult', pResult_ENUM),
        ('ErrorCode', BOOLEAN),
    )
#OLD 3.6.4.1.32 RpcWinStationNtsdDebug (Opnum 42)
# Unknown
class RpcWinStationNtsdDebug(NDRCALL):
    opnum = 42
    structure = (
        ('hServer', SERVER_HANDLE),
        ('LogonId', DWORD),
        ('ProcessId', LONG),
        ('DbgProcessId', ULONG),
        ('DbgThreadId', ULONG),
        ('AttachCompletionRoutine', LPDWORD),
    )

class RpcWinStationNtsdDebugResponse(NDRCALL):
    structure = (
        ('pResult', pResult_ENUM),
        ('ErrorCode', BOOLEAN),
    )
# 3.7.4.1.22 RpcWinStationGetAllProcesses (Opnum 43)
class RpcWinStationGetAllProcesses(NDRCALL):
    opnum = 43
    structure = (
        ('hServer', SERVER_HANDLE),
        ('Level', ULONG),
        ('pNumberOfProcesses', BOUNDED_ULONG),
    )

class RpcWinStationGetAllProcessesResponse(NDRCALL):
    structure = (
        ('pResult', pResult_ENUM),
        ('pNumberOfProcesses', BOUNDED_ULONG),
        ('buffer',':'),
    )
# 3.7.4.1.23 RpcWinStationGetProcessSid (Opnum 44)
class RpcWinStationGetProcessSid(NDRCALL):
    opnum = 44
    structure = (
        ('hServer', SERVER_HANDLE),
        ('dwUniqueProcessId', DWORD),
        ('ProcessStartTime', LARGE_INTEGER),
        ('pProcessUserSid', TS_PBYTE),
        ('dwSidSize', '<L=len(pProcessUserSid["Data"])'),
        ('pdwSizeNeeded', DWORD),
    )

class RpcWinStationGetProcessSidResponse(NDRCALL):
    structure = (
        ('pResult', pResult_ENUM),
        ('pProcessUserSid', TS_PBYTE),
        ('pdwSizeNeeded', DWORD),
        ('ErrorCode', BOOLEAN),
    )
#NOT_IMPLEMENTED 3.7.4.1.24 RpcWinStationGetTermSrvCountersValue (Opnum 45)
class RpcWinStationGetTermSrvCountersValue(NDRCALL):
    '''
    BOOLEAN RpcWinStationGetTermSrvCountersValue(
        [in] SERVER_HANDLE hServer,
        [out] DWORD* pResult,
        [in, range(0, 0x1000)] DWORD dwEntries,
        [in, out, size_is(dwEntries)] PTS_COUNTER pCounter
    );
    '''
    opnum = 45
    structure = (
        ('hServer', SERVER_HANDLE),
        ('dwEntries', DWORD),
        ('pCounter', PTS_COUNTER),
    )

class RpcWinStationGetTermSrvCountersValueResponse(NDRCALL):
    structure = (
        ('pResult', pResult_ENUM),
        ('pCounter', PTS_COUNTER),
        ('ErrorCode', BOOLEAN),
    )
# 3.7.4.1.25 RpcWinStationReInitializeSecurity (Opnum 46)
# Does not work
class RpcWinStationReInitializeSecurity(NDRCALL):
    opnum = 46
    structure = (
        ('hServer', SERVER_HANDLE),
    )

class RpcWinStationReInitializeSecurityResponse(NDRCALL):
    structure = (
        ('pResult', pResult_ENUM),
        ('ErrorCode', BOOLEAN),
    )
#OLD 3.6.4.1.37 RpcWinStationBroadcastSystemMessage (Opnum 47)
'''
LONG RpcWinStationBroadcastSystemMessage(
 [in] SERVER_HANDLE hServer,
 [in] ULONG sessionID,
 [in] ULONG timeOut,
 [in] DWORD dwFlags,
 [in, out, ptr] DWORD* lpdwRecipients,
 [in] ULONG uiMessage,
 [in] UINT_PTR wParam,
 [in] LONG_PTR lParam,
 [in, size_is(bufferSize)] PBYTE pBuffer,
 [in, range(0, 0x8000 )] ULONG bufferSize,
 [in] BOOLEAN fBufferHasValidData,
 [out] LONG* pResponse
);
'''

#OLD 3.6.4.1.38 RpcWinStationSendWindowMessage (Opnum 48)
'''
LONG RpcWinStationSendWindowMessage(
 [in] SERVER_HANDLE hServer,
 [in] ULONG sessionID,
 [in] ULONG timeOut,
 [in] ULONG hWnd,
 [in] ULONG Msg,
 [in] UINT_PTR wParam,
 [in] LONG_PTR lParam,
 [in, size_is(bufferSize)] PBYTE pBuffer,
 [in, range(0, 0x8000 )] ULONG bufferSize,
 [in] BOOLEAN fBufferHasValidData,
 [out] LONG* pResponse
);
'''
#OLD 3.6.4.1.39 RpcWinStationNotifyNewSession (Opnum 49)
'''
BOOLEAN RpcWinStationNotifyNewSession(
 [in] SERVER_HANDLE hServer,
 [out] DWORD* pResult,
 [in] DWORD ClientLogonId
);
'''

# 3.7.4.1.26 RpcWinStationGetLanAdapterName (Opnum 53)
# Does not work
class RpcWinStationGetLanAdapterName(NDRCALL):
    '''
    BOOLEAN RpcWinStationGetLanAdapterName(
        [in] SERVER_HANDLE hServer,
        [out] DWORD* pResult,
        [in, range(0, 0x1000)] DWORD PdNameSize,
        [in, size_is(PdNameSize)] PWCHAR pPdName,
        [in, range(0, 1024)] ULONG LanAdapter,
        [out] ULONG* pLength,
        [out, size_is(,*pLength)] PWCHAR* ppLanAdapter
    );
    '''
    opnum = 53
    structure = (
        ('hServer', SERVER_HANDLE),
        ('PdNameSize', '<L=len(pPdName["Data"])'),
        ('pPdName', TS_WCHAR),
        ('LanAdapter', ULONG),
    )

class RpcWinStationGetLanAdapterNameResponse(NDRCALL):
    structure = (
        ('pResult', pResult_ENUM),
        ('ppLanAdapter', TS_WCHAR),
        ('ErrorCode', BOOLEAN),
    )
#OLD 3.6.4.1.41 RpcWinStationUpdateUserConfig (Opnum 54)
'''
BOOLEAN RpcWinStationUpdateUserConfig(
 [in] SERVER_HANDLE hServer,
 [in] DWORD ClientLogonId,
 [in] DWORD ClientProcessId,
 [in] DWORD UserToken,
 [out] DWORD* pResult
);
'''
#OLD 3.6.4.1.42 RpcWinStationQueryLogonCredentials (Opnum 55)
# Does not work
class RpcWinStationQueryLogonCredentials(NDRCALL):
    '''
    BOOLEAN RpcWinStationQueryLogonCredentials(
        [in] SERVER_HANDLE hServer,
        [in] ULONG LogonId,
        [out, size_is(,*pcbCredentials)]
        PCHAR* ppCredentials,
        [in, out] ULONG* pcbCredentials
    );
    '''
    opnum = 55
    structure = (
        ('hServer', SERVER_HANDLE),
        ('LogonId', ULONG),
        ('pcbCredentials', ULONG),
    )

class RpcWinStationQueryLogonCredentialsResponse(NDRCALL):
    structure = (
        ('pResult', UNKNOWNDATA),
    )

#OLD 3.6.4.1.43 RpcWinStationRegisterConsoleNotification (Opnum 56)
'''
BOOLEAN RpcWinStationRegisterConsoleNotification(
 [in] SERVER_HANDLE hServer,
 [out] DWORD* pResult,
 [in] ULONG SessionId,
 [in] ULONG_PTR hWnd,
 [in] DWORD dwFlags,
 [in] DWORD dwMask
);
'''

#OLD 3.6.4.1.44 RpcWinStationUnRegisterConsoleNotification (Opnum 57)
'''
BOOLEAN RpcWinStationUnRegisterConsoleNotification(
 [in] SERVER_HANDLE hServer,
 [out] DWORD* pResult,
 [in] ULONG SessionId,
 [in] ULONG hWnd
);
'''

# 3.7.4.1.27 RpcWinStationUpdateSettings (Opnum 58)
# Does not work
class RpcWinStationUpdateSettings(NDRCALL):
    '''
    BOOLEAN RpcWinStationUnRegisterConsoleNotification(
        [in] SERVER_HANDLE hServer,
        [out] DWORD* pResult,
        [in] ULONG SessionId,
        [in] ULONG hWnd
    );
    '''
    opnum = 58
    structure = (
        ('hServer', SERVER_HANDLE),
        ('SettingsClass', DWORD),
        ('SettingsParameters', DWORD),
    )

class RpcWinStationUpdateSettingsResponse(NDRCALL):
    structure = (
        ('pResult', UNKNOWNDATA),
    )
# 3.7.4.1.28 RpcWinStationShadowStop (Opnum 59)
class RpcWinStationShadowStop(NDRCALL):
    opnum = 59
    structure = (
        ('hServer', SERVER_HANDLE),
        ('LogonId', DWORD),
        ('bWait', BOOLEAN),
    )

class RpcWinStationShadowStopResponse(NDRCALL):
    structure = (
        ('pResult', pResult_ENUM),
        ('ErrorCode', BOOLEAN),
    )

# 3.7.4.1.29 RpcWinStationCloseServerEx (Opnum 60)
class RpcWinStationCloseServerEx(NDRCALL):
    opnum = 60
    structure = (
        ('hServer', SERVER_HANDLE),
    )

class RpcWinStationCloseServerExResponse(NDRCALL):
    structure = (
        ('phServer', SERVER_HANDLE),
        ('pResult', pResult_ENUM),
        ('ErrorCode', BOOLEAN),
    )
# 3.7.4.1.30 RpcWinStationIsHelpAssistantSession (Opnum 61)
# Does not work
class RpcWinStationIsHelpAssistantSession(NDRCALL):
    opnum = 61
    structure = (
        ('hServer', SERVER_HANDLE),
        ('SessionId', ULONG),
    )

class RpcWinStationIsHelpAssistantSessionResponse(NDRCALL):
    structure = (
        ('pResult', pResult_ENUM),
        ('ErrorCode', BOOLEAN),
    )
# 3.7.4.1.31 RpcWinStationGetMachinePolicy (Opnum 62)
'''
BOOLEAN RpcWinStationGetMachinePolicy(
 [in] SERVER_HANDLE hServer,
 [in, out, size_is(bufferSize)] PBYTE pPolicy,
 [in, range(0, 0x8000 )] ULONG bufferSize
);
'''
# 3.7.4.1.32 RpcWinStationCheckLoopBack (Opnum 65)
'''
BOOLEAN RpcWinStationCheckLoopBack(
 [in] SERVER_HANDLE hServer,
 [out] DWORD* pResult,
 [in] DWORD ClientLogonId,
 [in] DWORD TargetLogonId,
 [in, size_is(NameSize)] PWCHAR pTargetServerName,
 [in, range(0, 1024)] DWORD NameSize
);
'''
# 3.7.4.1.33 RpcConnectCallback (Opnum 66)
class RpcConnectCallback(NDRCALL):
    '''
    BOOLEAN RpcConnectCallback(
        [in] SERVER_HANDLE hServer,
        [out] DWORD* pResult,
        [in] DWORD TimeOut,
        [in] ULONG AddressType,
        [in, size_is(AddressSize)] PBYTE pAddress,
        [in, range(0, 0x1000 )] ULONG AddressSize
    );
    '''
    opnum = 61
    structure = (
        ('hServer', SERVER_HANDLE),
        ('TimeOut', DWORD),
        ('AddressType', ULONG),
        ('pAddress', TS_PBYTE),
        ('AddressSize', '<L=len(pAddress["Data"])'),
    )

class RpcConnectCallbackResponse(NDRCALL):
    structure = (
        ('pResult', pResult_ENUM),
        ('ErrorCode', BOOLEAN),
        ('out', UNKNOWNDATA),
    )
#OLD 3.6.4.1.52 RpcRemoteAssistancePrepareSystemRestore (Opnum 69)
'''
BOOLEAN RpcRemoteAssistancePrepareSystemRestore(
 [in] SERVER_HANDLE hServer,
 [out] DWORD* pResult
);
'''
# 3.7.4.1.34 RpcWinStationGetAllProcesses_NT6 (Opnum 70)
'''
BOOLEAN RpcWinStationGetAllProcesses_NT6(
 [in] SERVER_HANDLE hServer,
 [out] DWORD* pResult,
 [in] ULONG Level,
 [in, out] BOUNDED_ULONG* pNumberOfProcesses,
 [out, size_is(,*pNumberOfProcesses)]
 PTS_ALL_PROCESSES_INFO_NT6* ppTsAllProcessesInfo
);
'''

#OLD 3.6.4.1.54 RpcWinStationRegisterNotificationEvent (Opnum 71)
'''
BOOLEAN RpcWinStationRegisterNotificationEvent(
 [in] SERVER_HANDLE hServer,
 [out] DWORD* pResult,
 [out] REGISTRATION_HANDLE* pNotificationId,
 [in] ULONG_PTR EventHandle,
 [in] DWORD TargetSessionId,
 [in] DWORD dwMask,
 [in] DWORD dwProcessId
);
'''
#OLD 3.6.4.1.55 RpcWinStationUnRegisterNotificationEvent (Opnum 72)
'''
BOOLEAN RpcWinStationUnRegisterNotificationEvent(
 [in] SERVER_HANDLE hServer,
 [out] DWORD* pResult,
[in, out] REGISTRATION_HANDLE* NotificationId
);
'''

#OLD 3.6.4.1.56 RpcWinStationAutoReconnect (Opnum 73)
'''
BOOLEAN RpcWinStationAutoReconnect(
 [in] SERVER_HANDLE hServer,
 [out] DWORD* pResult,
 [in] DWORD LogonId,
 [in] DWORD flags
);
'''
#OLD 3.6.4.1.57 RpcWinStationCheckAccess (Opnum 74)
'''
BOOLEAN RpcWinStationCheckAccess(
 [in] SERVER_HANDLE hServer,
 [out] DWORD* pResult,
 [in] DWORD ClientLogonId,
 [in] DWORD UserToken,
 [in] ULONG LogonId,
 [in] ULONG AccessMask
);
'''

# 3.7.4.1.35 RpcWinStationOpenSessionDirectory (Opnum 75)
# Does not work
class RpcWinStationOpenSessionDirectory(NDRCALL):
    opnum = 75
    structure = (
        ('hServer', SERVER_HANDLE),
        ('pszServerName', WSTR),
    )

class RpcWinStationOpenSessionDirectoryResponse(NDRCALL):
    structure = (
        ('pResult', pResult_ENUM),
        ('ErrorCode', BOOLEAN),
    )


################################################################################
# Helper Functions
################################################################################

# 3.3.4.1 TermSrvSession; \pipe\LSM_API_service; 484809d6-4239-471b-b5bc-61df8c23ac48
# 3.3.4.1.1 RpcOpenSession (Opnum 0)
def hRpcOpenSession(dce, SessionId):
    request = RpcOpenSession()
    request['SessionId'] = SessionId
    return dce.request(request)['phSession']

# 3.3.4.1.2 RpcCloseSession (Opnum 1)
def hRpcCloseSession(dce, phSession):
    request = RpcCloseSession()
    request['phSession'] = phSession
    return dce.request(request)

# 3.3.4.1.3 RpcConnect (Opnum 2)
def hRpcConnect(dce, hSession, TargetSessionId, Password = None):
    if Password is None:
        Password = ''
    request = RpcConnect()
    request['hSession'] = hSession
    request['TargetSessionId'] = TargetSessionId
    request['szPassword'] = Password + '\0'
    try:
        return dce.request(request)
    except DCERPCSessionError as e:
        if e.error_code == 0x1: # Strange, but this error_code is returned on success
            resp = RpcConnectResponse()
            resp['ErrorCode'] = 0
            return resp
        raise e

# 3.3.4.1.4 RpcDisconnect (Opnum 3)
def hRpcDisconnect(dce, hSession):
    request = RpcDisconnect()
    request['hSession'] = hSession
    return dce.request(request)

# 3.3.4.1.5 RpcLogoff (Opnum 4)
def hRpcLogoff(dce, hSession):
    request = RpcLogoff()
    request['hSession'] = hSession
    try:
        return dce.request(request)
    except DCERPCSessionError as e:
        if e.error_code == 0x10000000: # Strange, but this error_code is returned on success
            resp = RpcLogoffResponse()
            resp['ErrorCode'] = 0
            return resp
        raise e
        
    return dce.request(request)

# 3.3.4.1.6 RpcGetUserName (Opnum 5)
def hRpcGetUserName(dce, hSession):
    request = RpcGetUserName()
    request['hSession'] = hSession
    return dce.request(request)

# 3.3.4.1.7 RpcGetTerminalName (Opnum 6)
def hRpcGetTerminalName(dce, hSession):
    request = RpcGetTerminalName()
    request['hSession'] = hSession
    return dce.request(request)

# 3.3.4.1.8 RpcGetState (Opnum 7)
def hRpcGetState(dce, hSession):
    request = RpcGetState()
    request['hSession'] = hSession
    return dce.request(request)

# 3.3.4.1.9 RpcIsSessionDesktopLocked (Opnum 8)
def hRpcIsSessionDesktopLocked(dce, hSession):
    request = RpcIsSessionDesktopLocked()
    request['hSession'] = hSession
    return dce.request(request)

# 3.3.4.1.10 RpcShowMessageBox (Opnum 9)
def hRpcShowMessageBox(dce, hSession, Title, Message, Style = 0, Timeout = 0, DoNotWait = True):
    Title = Title if Title is not None else ' '
    Message = Message if Message is not None else ''

    request = RpcShowMessageBox()
    request['hSession'] = hSession
    request['szTitle'] = Title + '\0'
    request['szMessage'] = Message + '\0'
    request['ulStyle'] = Style
    request['ulTimeout'] = Timeout
    request['bDoNotWait'] = DoNotWait
    return dce.request(request)

# 3.3.4.1.11 RpcGetTimes (Opnum 10)
def hRpcGetTimes(dce, hSession):
    request = RpcGetTimes()
    request['hSession'] = hSession
    return dce.request(request)

# 3.3.4.1.12 RpcGetSessionCounters (Opnum 11)
def hRpcGetSessionCounters(dce, Entries):
    request = RpcGetSessionCounters()
    request['uEntries'] = Entries
    return dce.request(request)

# 3.3.4.1.13 RpcGetSessionInformation (Opnum 12)
def hRpcGetSessionInformation(dce, SessionId):
    request = RpcGetSessionInformation()
    request['SessionId'] = SessionId
    return dce.request(request)

# 3.3.4.1.14 RpcGetLoggedOnCount (Opnum 15)
def hRpcGetLoggedOnCount(dce):
    request = RpcGetLoggedOnCount()
    return dce.request(request)

# 3.3.4.1.15 RpcGetSessionType (Opnum 16)
def hRpcGetSessionType(dce, SessionId):
    request = RpcGetSessionType()
    request['SessionId'] = SessionId
    return dce.request(request)

# 3.3.4.1.16 RpcGetSessionInformationEx (Opnum 17)
def hRpcGetSessionInformationEx(dce, SessionId):
    request = RpcGetSessionInformationEx()
    request['SessionId'] = SessionId
    request['Level'] = 1
    return dce.request(request)
    '''
    RpcGetSessionInformationExResponse 
    LSMSessionInfoExPtr:            
    tag:                             1 
    LSM_SessionInfo_Level1:         
        SessionState:                    State_Active 
        SessionFlags:                    WTS_SESSIONSTATE_UNLOCK 
        SessionName:                     'RDP-Tcp#0' 
        DomainName:                      'W11-WKS' 
        UserName:                        'john' 
        ConnectTime:                     datetime.datetime(2022, 5, 9, 2, 34, 48, 700543) 
        DisconnectTime:                  datetime.datetime(2022, 5, 9, 2, 34, 48, 547684) 
        LogonTime:                       datetime.datetime(2022, 5, 9, 2, 23, 31, 119361) 
        LastInputTime:                   datetime.datetime(1601, 1, 1, 2, 20, 54) 
        ProtocolDataSize:                1816 
        ProtocolData:                    
    '''

# 3.3.4.2 TermSrvNotification (LSM Notification); \PIPE\LSM_API_service; 11899a43-2b68-4a76-92e3-a3d6ad8c26ce
# 3.3.4.2.1 RpcWaitForSessionState (Opnum 0)
def hRpcWaitForSessionState(dce, SessionId, State, Timeout):
    # State from WINSTATIONSTATECLASS class
    request = RpcWaitForSessionState()
    request['SessionId'] = SessionId
    request['State'] = State
    request['Timeout'] = Timeout
    return dce.request(request)

# 3.3.4.2.2 RpcRegisterAsyncNotification (Opnum 1)
def hRpcRegisterAsyncNotification(dce, SessionId, Mask):
    request = RpcRegisterAsyncNotification()
    request['SessionId'] = SessionId
    request['Mask'] = Mask
    return dce.request(request)['phNotify']

# 3.3.4.2.3 RpcWaitAsyncNotification (Opnum 2)
def hRpcWaitAsyncNotification(dce, hNotify):
    request = RpcWaitAsyncNotification()
    request['hNotify'] = hNotify
    return dce.request(request)

# 3.3.4.2.4 RpcUnRegisterAsyncNotification (Opnum 3)
def hRpcUnRegisterAsyncNotification(dce, hNotify):
    request = RpcUnRegisterAsyncNotification()
    request['hNotify'] = hNotify
    return dce.request(request)

# 3.3.4.3 TermSrvEnumeration; 88143fd0-c28d-4b2b-8fef-8d882f6a9390; \pipe\LSM_API_service
# 3.3.4.3.1 RpcOpenEnum (Opnum 0)
def hRpcOpenEnum(dce):
    request = RpcOpenEnum()
    return dce.request(request)['phEnum']

# 3.3.4.3.2 RpcCloseEnum (Opnum 1)
def hRpcCloseEnum(dce, phEnum):
    request = RpcCloseEnum()
    request['phEnum'] = phEnum
    return dce.request(request)

#NOT_IMPLEMENTED 3.3.4.3.3 RpcFilterByState (Opnum 2)

#NOT_IMPLEMENTED 3.3.4.3.4 RpcFilterByCallersName (Opnum 3)

#NOT_IMPLEMENTED 3.3.4.3.5 RpcEnumAddFilter (Opnum 4)

# 3.3.4.3.6 RpcGetEnumResult (Opnum 5)
def hRpcGetEnumResult(dce, hEnum, Level = 1):
    request = RpcGetEnumResult()
    request['hEnum'] = hEnum
    request['Level'] = Level
    return dce.request(request)

#NOT_IMPLEMENTED 3.3.4.3.7 RpcFilterBySessionType (Opnum 6)

#NOT_IMPLEMENTED 3.3.4.3.8 RpcGetSessionIds (Opnum 8)

# 3.3.4.3.9 RpcGetEnumResultEx (Opnum 9)
def hRpcGetEnumResultEx(dce, hEnum, Level = 1):
    request = RpcGetEnumResultEx()
    request['hEnum'] = hEnum
    request['Level'] = Level
    return dce.request(request)

# 3.3.4.3.10 RpcGetAllSessions (Opnum 10)
def hRpcGetAllSessions(dce, Level = 1):
    request = RpcGetAllSessions()
    request['pLevel'] = Level
    return dce.request(request)

#NOT_IMPLEMENTED 3.3.4.3.11 RpcGetAllSessionsEx (Opnum 11)


# 3.5.4.1 RCMPublic bde95fdf-eee0-45de-9e12-e5a61cd0d4fe \pipe\TermSrv_API_service
# 3.5.4.1.1 RpcGetClientData (Opnum 0)
def hRpcGetClientData(dce, SessionId):
    request = RpcGetClientData()
    request['SessionId'] = SessionId
    try:
        return dce.request(request)
    except:
        return None

# 3.5.4.1.2 RpcGetConfigData (Opnum 1)
def hRpcGetConfigData(dce, SessionId):
    request = RpcGetConfigData()
    request['SessionId'] = SessionId
    return dce.request(request)

#NOT_IMPLEMENTED 3.5.4.1.3 RpcGetProtocolStatus (Opnum 2)

# 3.5.4.1.4 RpcGetLastInputTime (Opnum 3)
def hRpcGetLastInputTime(dce, SessionId):
    request = RpcGetLastInputTime()
    request['SessionId'] = SessionId
    return dce.request(request)

# 3.5.4.1.5 RpcGetRemoteAddress (Opnum 4)
def hRpcGetRemoteAddress(dce, SessionId):
    request = RpcGetRemoteAddress()
    request['SessionId'] = SessionId
    try:
        return dce.request(request)
    except:
        return None

# 3.5.4.1.6 RpcGetAllListeners (Opnum 8)
def hRpcGetAllListeners(dce):
    request = RpcGetAllListeners()
    request['Level'] = 1
    return dce.request(request)

#NOT_IMPLEMENTED 3.5.4.1.7 RpcGetSessionProtocolLastInputTime (Opnum 9)
#NOT_IMPLEMENTED 3.5.4.1.8 RpcGetUserCertificates (Opnum 10)
#NOT_IMPLEMENTED 3.5.4.1.9 RpcQuerySessionData (Opnum 11)

# 3.5.4.2 RCMListener 497d95a6-2d27-4bf5-9bbd-a6046957133c \pipe\TermSrv_API_service or \pipe\Ctx_WinStation_API_service
# 3.5.4.2.1 RpcOpenListener (Opnum 0)
def hRpcOpenListener(dce, ListenerName):
    request = RpcOpenListener()
    request['szListenerName'] = ListenerName + '\0'
    return dce.request(request)['phListener']

# 3.5.4.2.2 RpcCloseListener (Opnum 1)
def hRpcCloseListener(dce, phListener):
    request = RpcCloseListener()
    request['phListener'] = phListener
    return dce.request(request)
    
# 3.5.4.2.3 RpcStopListener (Opnum 2)
def hRpcStopListener(dce, phListener):
    request = RpcStopListener()
    request['phListener'] = phListener
    return dce.request(request)

# 3.5.4.2.4 RpcStartListener (Opnum 3)
def hRpcStartListener(dce, phListener):
    request = RpcStartListener()
    request['phListener'] = phListener
    return dce.request(request)

# 3.5.4.2.5 RpcIsListening (Opnum 4)
def hRpcIsListening(dce, phListener):
    request = RpcIsListening()
    request['phListener'] = phListener
    return dce.request(request)


# 3.7.4.1 LegacyApi 5ca4a760-ebb1-11cf-8611-00a0245420ed \pipe\Ctx_WinStation_API_service
#
# In legacy api, response error_codes are represented as 1 byte boolean at the end of the response
# so we have to ignore error checking by rpcrt module, by checkError=False
#
# 3.7.4.1.1 RpcWinStationOpenServer (Opnum 0)
def hRpcWinStationOpenServer(dce):
    request = RpcWinStationOpenServer()
    resp = dce.request(request, checkError=False)
    if resp['ErrorCode']:
        return resp['phServer']
    return None

# 3.7.4.1.2 RpcWinStationCloseServer (Opnum 1)
def hRpcWinStationCloseServer(dce, hServer):
    request = RpcWinStationCloseServer()
    request['hServer'] = hServer
    return dce.request(request, checkError=False)

#DOES_NOT_WORK 3.7.4.1.3 RpcIcaServerPing (Opnum 2)
def hRpcIcaServerPing(dce, hServer):
    request = RpcIcaServerPing()
    request['hServer'] = hServer
    return dce.request(request, checkError=False)


# 3.7.4.1.8 RpcWinStationSendMessage (Opnum 7)
def hRpcWinStationSendMessage(dce, hServer, LogonId, Title, Message, DoNotWait = True):
    request = RpcWinStationSendMessage()
    request['hServer'] = hServer
    request['LogonId'] = LogonId
    request['pTitle'] = ZEROPAD(Title,1024)
    request['pMessage'] = ZEROPAD(Message,1024)
    request['DoNotWait'] = DoNotWait
    return dce.request(request, checkError=False)

# 3.7.4.1.9 RpcLogonIdFromWinStationName (Opnum 8)
def hRpcLogonIdFromWinStationName(dce, hServer, WinStationName):
    request = RpcLogonIdFromWinStationName()
    request['hServer'] = hServer
    request['pWinStationName'] = ZEROPAD(WinStationName, WINSTATIONNAME_LENGTH + 1)
    return dce.request(request, checkError=False)

# 3.7.4.1.10 RpcWinStationNameFromLogonId (Opnum 9)
def hRpcWinStationNameFromLogonId(dce, hServer, LoginId):
    request = RpcWinStationNameFromLogonId()
    request['hServer'] = hServer
    request['LoginId'] = LoginId
    request['pWinStationName'] = ZEROPAD('', WINSTATIONNAME_LENGTH + 1)
    return dce.request(request, checkError=False)

# 3.7.4.1.11 RpcWinStationConnect (Opnum 10)
def hRpcWinStationConnect(dce, hServer, ClientLogonId, ConnectLogonId, TargetLogonId, Password, Wait = False):
    # Session #1 in disconnected state
    # You want to attach session #1 to your session and you know
    # the password of the logged in user in session #1
    # Your session ID: 3
    # Parameters:
    # ClientLogonId = 1
    # ConnectLogonId = d
    # TargetLogonId = 3
    request = RpcWinStationConnect()
    request['hServer'] = hServer
    request['ClientLogonId'] = ClientLogonId
    request['ConnectLogonId'] = ConnectLogonId
    request['TargetLogonId'] = TargetLogonId
    request['pPassword'] = Password + '\0'
    request['Wait'] = Wait
    return dce.request(request, checkError=False)

# 3.7.4.1.12 RpcWinStationDisconnect (Opnum 13)
def hRpcWinStationDisconnect(dce, hServer, LoginId, bWait = False):
    request = RpcWinStationDisconnect()
    request['hServer'] = hServer
    request['LoginId'] = LoginId
    request['bWait'] = bWait
    return dce.request(request, checkError=False)

# 3.7.4.1.13 RpcWinStationReset (Opnum 14)
def hRpcWinStationReset(dce, hServer, LogonId, bWait = False):
    request = RpcWinStationReset()
    request['hServer'] = hServer
    request['LogonId'] = LogonId
    request['bWait'] = bWait
    return dce.request(request, checkError=False)

# 3.7.4.1.14 RpcWinStationShutdownSystem (Opnum 15)
# ShutdownFlags == ENUM ShutdownFlags
def hRpcWinStationShutdownSystem(dce, hServer, ClientLogonId, ShutdownFlags):
    request = RpcWinStationShutdownSystem()
    request['hServer'] = hServer
    request['ClientLogonId'] = ClientLogonId
    request['ShutdownFlags'] = ShutdownFlags
    return dce.request(request, checkError=False)

# 3.7.4.1.15 RpcWinStationWaitSystemEvent (Opnum 16)
# EventMask == ENUM EventMask
def hRpcWinStationWaitSystemEvent(dce, hServer, EventMask):
    request = RpcWinStationWaitSystemEvent()
    request['hServer'] = hServer
    request['EventMask'] = EventMask
    return dce.request(request, checkError=False)


# 3.7.4.1.16 RpcWinStationShadow (Opnum 17)
def hRpcWinStationShadow(dce, hServer, LogonId, pTargetServerName, TargetLogonId, HotKeyVk, HotkeyModifiers):
    request = RpcWinStationShadow()
    request['hServer'] = hServer
    request['LogonId'] = LogonId
    request['pTargetServerName'] = pTargetServerName
    request['TargetLogonId'] = TargetLogonId
    request['HotKeyVk'] = HotKeyVk
    request['HotkeyModifiers'] = HotkeyModifiers
    return dce.request(request, checkError=False)

#OLD 3.6.4.1.19 RpcWinStationShadowTargetSetup (Opnum 18)
def hRpcWinStationShadowTargetSetup(dce, hServer, LogonId):
    request = RpcWinStationShadowTargetSetup()
    request['hServer'] = hServer
    request['LogonId'] = LogonId
    return dce.request(request, checkError=False)

# 3.7.4.1.17 RpcWinStationBreakPoint (Opnum 29)
def hRpcWinStationBreakPoint(dce, hServer, LogonId, KernelFlag):
    request = RpcWinStationBreakPoint()
    request['hServer'] = hServer
    request['LogonId'] = LogonId
    request['KernelFlag'] = KernelFlag
    return dce.request(request, checkError=False)

#DOES_NOT_WORK 3.7.4.1.18 RpcWinStationReadRegistry (Opnum 30)
def hRpcWinStationReadRegistry(dce, hServer):
    request = RpcWinStationReadRegistry()
    request['hServer'] = hServer
    return dce.request(request, checkError=False)

#DOES_NOT_WORK 3.7.4.1.19 OldRpcWinStationEnumerateProcesses (Opnum 34)
def hOldRpcWinStationEnumerateProcesses(dce, hServer, ByteCount):
    request = OldRpcWinStationEnumerateProcesses()
    request['hServer'] = hServer
    request['ByteCount'] = ByteCount
    return dce.request(request, checkError=False)

#DOES_NOT_WORK 3.7.4.1.20 RpcWinStationEnumerateProcesses (Opnum 36)
def hRpcWinStationEnumerateProcesses(dce, hServer, ByteCount):
    request = RpcWinStationEnumerateProcesses()
    request['hServer'] = hServer
    request['ByteCount'] = ByteCount
    return dce.request(request, checkError=False)


# 3.7.4.1.21 RpcWinStationTerminateProcess (Opnum 37)
def hRpcWinStationTerminateProcess(dce, hServer, ProcessId, ExitCode = 0):
    request = RpcWinStationTerminateProcess()
    request['hServer'] = hServer
    request['ProcessId'] = ProcessId
    request['ExitCode'] = ExitCode
    return dce.request(request, checkError=False)

# 3.7.4.1.22 RpcWinStationGetAllProcesses (Opnum 43)
def hRpcWinStationGetAllProcesses(dce, hServer):
    # i'm giving up constructing legitimate structures for this method
    # Going to parse raw response:
    # 1. Skip ndrpointers
    # 2. Create TS_SYS_PROCESS_INFORMATION structure one by one
    # Tested and seems to work well on WIN11, WIN10, WIN2012R2, WIN7
    request = RpcWinStationGetAllProcesses()
    request['hServer'] = hServer
    request['Level'] = 0
    request['pNumberOfProcesses'] = 0x8000
    resp = dce.request(request, checkError=False)
    data = resp.getData()
    bResult = bool(data[-1])
    if not bResult:
        raise DCERPCSessionError(error_code=resp['pResult'])
    data = data[:-1]
    procs = []
    if not resp['pNumberOfProcesses']:
        return procs
    offset = 0
    arrayOffset = 0
    while 1:
        offset = data.find(b'\x02\x00')
        if offset > 12:
            break
        data = data[offset+2:]
        arrayOffset = arrayOffset + offset + 2
    procInfo = ''
    while len(data)>1:
        if len(data[len(procInfo):]) < 16:
            break
        # I think there some alignment problems...
        # in the structure, second DWORD is thread count, i'm looking for the second DWORD
        # in order to align the data correctly
        # There is no proper errors handling!
        b,c,d,e = struct.unpack('<LLLL',data[len(procInfo):len(procInfo)+16])
        if b:
            data = data[len(procInfo)-4:]
        elif c:
            data = data[len(procInfo):]
        elif d:
            data = data[len(procInfo)+4:]
        elif e:
            data = data[len(procInfo)+8:]
            
        procInfo = TS_SYS_PROCESS_INFORMATION()
        procInfo.fromString(data)
        procs.append(procInfo)
    return procs

# 3.7.4.1.23 RpcWinStationGetProcessSid (Opnum 44)
def hRpcWinStationGetProcessSid(dce, hServer, dwUniqueProcessId, ProcessStartTime):
    request = RpcWinStationGetProcessSid()
    request['hServer'] = hServer
    request['dwUniqueProcessId'] = dwUniqueProcessId
    request['ProcessStartTime'] = ProcessStartTime
    request['pProcessUserSid'] = b'\0' * 28
    resp = dce.request(request, checkError=False)
    if resp['pResult'] == pResult_ENUM.ERROR_STATUS_BUFFER_TOO_SMALL:
        sizeNeeded = resp['pdwSizeNeeded']
        request['pProcessUserSid'] = b'\0' * sizeNeeded
        request['dwSidSize'] = sizeNeeded
        resp = dce.request(request, checkError=False)
    if resp['ErrorCode']:
        return format_sid(resp['pProcessUserSid'])

#NOT_IMPLEMENTED 3.7.4.1.24 RpcWinStationGetTermSrvCountersValue (Opnum 45)

# 3.7.4.1.25 RpcWinStationReInitializeSecurity (Opnum 46)
def hRpcWinStationReInitializeSecurity(dce, hServer):
    request = RpcWinStationReInitializeSecurity()
    request['hServer'] = hServer
    return dce.request(request, checkError=False)

#DOES_NOT_WORK 3.7.4.1.26 RpcWinStationGetLanAdapterName (Opnum 53)
def hRpcWinStationGetLanAdapterName(dce, hServer, pPdName, LanAdapter):
    request = RpcWinStationGetLanAdapterName()
    request['hServer'] = hServer
    request['pPdName'] = hServer
    request['LanAdapter'] = hServer
    return dce.request(request, checkError=False)

#DOES_NOT_WORK 3.7.4.1.27 RpcWinStationUpdateSettings (Opnum 58)
def hRpcWinStationUpdateSettings(dce, hServer, SettingsClass, SettingsParameters):
    request = RpcWinStationUpdateSettings()
    request['hServer'] = hServer
    request['SettingsClass'] = hServer
    request['SettingsParameters'] = hServer
    return dce.request(request, checkError=False)


# 3.7.4.1.28 RpcWinStationShadowStop (Opnum 59)
def hRpcWinStationShadowStop(dce, hServer, LogonId, bWait):
    request = RpcWinStationShadowStop()
    request['hServer'] = hServer
    request['LogonId'] = LogonId
    request['bWait'] = bWait
    return dce.request(request, checkError=False)

# 3.7.4.1.29 RpcWinStationCloseServerEx (Opnum 60)
def hRpcWinStationCloseServerEx(dce, hServer):
    request = RpcWinStationShadowStop()
    request['hServer'] = hServer
    return dce.request(request, checkError=False)

# 3.7.4.1.30 RpcWinStationIsHelpAssistantSession (Opnum 61)
def hRpcWinStationIsHelpAssistantSession(dce, hServer, SessionId):
    request = RpcWinStationShadowStop()
    request['hServer'] = hServer
    request['SessionId'] = SessionId
    return dce.request(request, checkError=False)

#NOT_IMPLEMENTED 3.7.4.1.31 RpcWinStationGetMachinePolicy (Opnum 62)

#NOT_IMPLEMENTED 3.7.4.1.32 RpcWinStationCheckLoopBack (Opnum 65)

#NOT_IMPLEMENTED 3.7.4.1.33 RpcConnectCallback (Opnum 66)

#NOT_IMPLEMENTED 3.7.4.1.34 RpcWinStationGetAllProcesses_NT6 (Opnum 70)

#DOES_NOT_WORK 3.7.4.1.35 RpcWinStationOpenSessionDirectory (Opnum 75)
def hRpcWinStationOpenSessionDirectory(dce, hServer, pszServerName):
    request = RpcWinStationShadowStop()
    request['hServer'] = hServer
    request['pszServerName'] = pszServerName
    return dce.request(request, checkError=False)


################################################################################
# Initialization Classes and Helper classes
################################################################################

class TSTSEndpoint:
    def __init__(self, smb, target_ip, stringbinding, endpoint, kerberos):
        self.__doKerberos = kerberos
        self._target_ip = target_ip
        self._stringbinding = stringbinding.format(target_ip)
        self._endpoint = endpoint
        self._smbconnection = smb
        self._bind()

        # Little hack to pass 'this' as 'dce' variable to a helper function
        self.request = self._dce.request
    def _bind(self):
        self._rpctransport = transport.DCERPCTransportFactory(self._stringbinding)
        self._rpctransport.set_smb_connection(self._smbconnection)
        self._dce = self._rpctransport.get_dce_rpc()
        if self.__doKerberos:
            self._dce.set_auth_type(RPC_C_AUTHN_GSS_NEGOTIATE)
        self._dce.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)

        self._dce.connect()
        self._dce.bind(self._endpoint)
        return self._dce
    def _disconnect(self):
        self._dce.disconnect()
    def __enter__(self):
        return self
    def __exit__(self, type, value, traceback):
        self._disconnect()

class TermSrvSession(TSTSEndpoint):
    def __init__(self, smb, target_ip, kerberos):
        super().__init__(smb, target_ip,
                            stringbinding = r'ncacn_np:{}[\pipe\LSM_API_service]',
                            endpoint = TermSrvSession_UUID,
                            kerberos = kerberos
        )
    hRpcOpenSession             = hRpcOpenSession
    hRpcCloseSession            = hRpcCloseSession
    hRpcConnect                 = hRpcConnect
    hRpcDisconnect              = hRpcDisconnect
    hRpcLogoff                  = hRpcLogoff
    hRpcGetUserName             = hRpcGetUserName
    hRpcGetTerminalName         = hRpcGetTerminalName
    hRpcGetState                = hRpcGetState
    hRpcIsSessionDesktopLocked  = hRpcIsSessionDesktopLocked
    hRpcShowMessageBox          = hRpcShowMessageBox
    hRpcGetTimes                = hRpcGetTimes
    hRpcGetSessionCounters      = hRpcGetSessionCounters
    hRpcGetSessionInformation   = hRpcGetSessionInformation
    hRpcGetLoggedOnCount        = hRpcGetLoggedOnCount
    hRpcGetSessionType          = hRpcGetSessionType
    hRpcGetSessionInformationEx = hRpcGetSessionInformationEx

class TermSrvNotification(TSTSEndpoint):
    def __init__(self, smb, target_ip, kerberos):
        super().__init__(smb, target_ip,
                            stringbinding = r'ncacn_np:{}[\pipe\LSM_API_service]',
                            endpoint = TermSrvNotification_UUID,
                            kerberos = kerberos
        )
    hRpcWaitForSessionState         = hRpcWaitForSessionState
    hRpcRegisterAsyncNotification   = hRpcRegisterAsyncNotification
    hRpcWaitAsyncNotification       = hRpcWaitAsyncNotification
    hRpcUnRegisterAsyncNotification = hRpcUnRegisterAsyncNotification

class TermSrvEnumeration(TSTSEndpoint):
    def __init__(self, smb, target_ip, kerberos):
        super().__init__(smb, target_ip,
                            stringbinding = r'ncacn_np:{}[\pipe\LSM_API_service]',
                            endpoint      = TermSrvEnumeration_UUID,
                            kerberos = kerberos
        )
    hRpcOpenEnum        = hRpcOpenEnum
    hRpcCloseEnum       = hRpcCloseEnum
    hRpcGetEnumResult   = hRpcGetEnumResult
    hRpcGetEnumResultEx = hRpcGetEnumResultEx
    hRpcGetAllSessions  = hRpcGetAllSessions

class RCMPublic(TSTSEndpoint):
    def __init__(self, smb, target_ip, kerberos):
        super().__init__(smb, target_ip,
                            stringbinding = r'ncacn_np:{}[\pipe\TermSrv_API_service]',
                            endpoint = RCMPublic_UUID,
                            kerberos = kerberos
        )
    hRpcGetClientData    = hRpcGetClientData
    hRpcGetConfigData    = hRpcGetConfigData
    hRpcGetLastInputTime = hRpcGetLastInputTime
    hRpcGetRemoteAddress = hRpcGetRemoteAddress
    hRpcGetAllListeners  = hRpcGetAllListeners


class RcmListener(TSTSEndpoint):
    def __init__(self, smb, target_ip, kerberos):
        super().__init__(smb, target_ip,
                            stringbinding = r'ncacn_np:{}[\pipe\TermSrv_API_service]',
                            endpoint = RcmListener_UUID,
                            kerberos = kerberos
        )
    hRpcOpenListener  = hRpcOpenListener
    hRpcCloseListener = hRpcCloseListener
    hRpcStopListener  = hRpcStopListener
    hRpcStartListener = hRpcStartListener
    hRpcIsListening   = hRpcIsListening

class LegacyAPI(TSTSEndpoint):
    def __init__(self, smb, target_ip, kerberos):
        super().__init__(smb, target_ip,
                            stringbinding = r'ncacn_np:{}[\pipe\Ctx_WinStation_API_service]',
                            endpoint = LegacyAPI_UUID,
                            kerberos = kerberos
        )
    hRpcWinStationOpenServer             = hRpcWinStationOpenServer
    hRpcWinStationCloseServer            = hRpcWinStationCloseServer
    hRpcIcaServerPing                    = hRpcIcaServerPing
    hRpcWinStationSendMessage            = hRpcWinStationSendMessage
    hRpcLogonIdFromWinStationName        = hRpcLogonIdFromWinStationName
    hRpcWinStationNameFromLogonId        = hRpcWinStationNameFromLogonId
    hRpcWinStationConnect                = hRpcWinStationConnect
    hRpcWinStationDisconnect             = hRpcWinStationDisconnect
    hRpcWinStationReset                  = hRpcWinStationReset
    hRpcWinStationShutdownSystem         = hRpcWinStationShutdownSystem
    hRpcWinStationWaitSystemEvent        = hRpcWinStationWaitSystemEvent
    hRpcWinStationShadow                 = hRpcWinStationShadow
    hRpcWinStationShadowTargetSetup      = hRpcWinStationShadowTargetSetup
    hRpcWinStationBreakPoint             = hRpcWinStationBreakPoint
    hRpcWinStationReadRegistry           = hRpcWinStationReadRegistry
    hOldRpcWinStationEnumerateProcesses  = hOldRpcWinStationEnumerateProcesses
    hRpcWinStationEnumerateProcesses     = hRpcWinStationEnumerateProcesses
    hRpcWinStationTerminateProcess       = hRpcWinStationTerminateProcess
    hRpcWinStationGetAllProcesses        = hRpcWinStationGetAllProcesses
    hRpcWinStationGetProcessSid          = hRpcWinStationGetProcessSid
    hRpcWinStationReInitializeSecurity   = hRpcWinStationReInitializeSecurity
    hRpcWinStationGetLanAdapterName      = hRpcWinStationGetLanAdapterName
    hRpcWinStationUpdateSettings         = hRpcWinStationUpdateSettings
    hRpcWinStationShadowStop             = hRpcWinStationShadowStop
    hRpcWinStationCloseServerEx          = hRpcWinStationCloseServerEx
    hRpcWinStationIsHelpAssistantSession = hRpcWinStationIsHelpAssistantSession
