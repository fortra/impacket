# Copyright (c) 2003-2016 CORE Security Technologies
#
# This software is provided under under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Author: Alberto Solino (@agsolino)
#
# Description:
#   [MS-RPCE]-C706 Interface implementation for the remote portmapper
#
#   Best way to learn how to use these calls is to grab the protocol standard
#   so you understand what the call does, and then read the test case located
#   at https://github.com/CoreSecurity/impacket/tree/master/impacket/testcases/SMB_RPC
#
#   Some calls have helper functions, which makes it even easier to use.
#   They are located at the end of this file. 
#   Helper functions start with "h"<name of the call>.
#   There are test cases for them too. 
#
import socket
from struct import unpack

from impacket.uuid import uuidtup_to_bin, bin_to_string
from impacket.dcerpc.v5 import transport
from impacket.dcerpc.v5.ndr import NDRCALL, NDRSTRUCT, NDRPOINTER, NDRUniConformantVaryingArray, NDRUniVaryingArray, \
    NDRUniConformantArray
from impacket.dcerpc.v5.dtypes import UUID, LPBYTE, PUUID, ULONG, USHORT
from impacket.structure import Structure
from impacket.dcerpc.v5.ndr import NULL
from impacket.dcerpc.v5.rpcrt import DCERPCException

MSRPC_UUID_PORTMAP = uuidtup_to_bin(('E1AF8308-5D1F-11C9-91A4-08002B14A0FA', '3.0'))

class DCERPCSessionError(DCERPCException):
    error_messages = {}
    def __init__(self, error_string=None, error_code=None, packet=None):
        DCERPCException.__init__(self, error_string, error_code, packet)
        self.error_code = packet['status']

    def __str__( self ):
        key = self.error_code
        if self.error_messages.has_key(key):
            error_msg_short = self.error_messages[key]
            return 'EPM SessionError: code: 0x%x - %s ' % (self.error_code, error_msg_short)
        else:
            return 'EPM SessionError: unknown error code: %s' % (str(self.error_code))

################################################################################
# CONSTANTS
################################################################################

KNOWN_UUIDS = {
"\xb0\x01\x52\x97\xca\x59\xd0\x11\xa8\xd5\x00\xa0\xc9\x0d\x80\x51\x01\x00": "rpcss.dll",
"\xf1\x8f\x37\xc9\xf7\x16\xd0\x11\xa0\xb2\x00\xaa\x00\x61\x42\x6a\x01\x00": "pstorsvc.dll",
"\xd4\xa7\x72\x0d\x48\x61\xd1\x11\xb4\xaa\x00\xc0\x4f\xb6\x6e\xa0\x01\x00": "cryptsvc.dll",
"\x40\x4e\x9f\x8d\x3d\xa0\xce\x11\x8f\x69\x08\x00\x3e\x30\x05\x1b\x01\x00": "services.exe",
"\xc5\x86\x5a\xda\xc2\x12\x43\x49\xab\x30\x7f\x74\xa8\x13\xd8\x53\x01\x00": "regsvc.dll",
"\x29\x07\x8a\xfb\x04\x2d\x58\x46\xbe\x93\x27\xb4\xad\x55\x3f\xac\x01\x00": "lsass.exe",
"\x04\xf7\xd9\x52\xc6\xd3\x48\x47\xad\x11\x25\x50\x20\x9e\x80\xaf\x00\x00": "IMEPADSM.DLL",
"\xce\xad\x21\xc4\xb2\xa0\x0d\x48\x84\x18\x98\x44\x95\xb3\x2d\x5f\x01\x00": "SLsvc.exe",
"\x14\xb5\xfb\xd3\x3b\x0e\xcb\x11\x8f\xad\x08\x00\x2b\x1d\x29\xc3\x01\x00": "locator.exe",
"\x6f\x40\x1c\xf6\x60\xbd\x94\x41\x95\x65\xbf\xed\xd5\x25\x6f\x70\x01\x00": "p2phost.exe",
"\x72\x33\x3d\xc1\x20\xcc\x49\x44\x9b\x23\x8c\xc8\x27\x1b\x38\x85\x01\x00": "rpcrt4.dll",
"\x70\xfe\x5a\xd9\xd5\xa6\x59\x42\x82\x2e\x2c\x84\xda\x1d\xdb\x0d\x01\x00": "wininit.exe",
"\x6a\x07\x2d\x55\x29\xcb\x44\x4e\x8b\x6a\xd1\x5e\x59\xe2\xc0\xaf\x01\x00": "iphlpsvc.dll",
"\x95\x4f\x25\xd4\xc3\x08\xcc\x4f\xb2\xa6\x0b\x65\x13\x77\xa2\x9d\x01\x00": "wwansvc.dll",
"\x43\x9a\x89\x11\x68\x2b\x76\x4a\x92\xe3\xa3\xd6\xad\x8c\x26\xce\x01\x00": "lsm.exe",
"\xb4\x33\x6f\x26\xc1\xc7\xd1\x4b\x8f\x52\xdd\xb8\xf2\x21\x4e\xa9\x01\x00": "wlansvc.dll",
"\x68\x9d\xcb\x2a\x34\xb4\x3e\x4b\xb9\x66\xe0\x6b\x4b\x3a\x84\xcb\x01\x00": "bthserv.dll",
"\xd0\x4c\x67\x57\x00\x52\xce\x11\xa8\x97\x08\x00\x2b\x2e\x9c\x6d\x01\x00": "llssrv.exe",
"\x52\x44\x7d\x64\x33\x9f\x18\x4a\xb2\xbe\xc5\xc0\xe9\x20\xe9\x4e\x01\x00": "pla.dll",
"\xc8\x9b\x3b\xde\xf7\xbe\x78\x45\xa0\xde\xf0\x89\x04\x84\x42\xdb\x01\x00": "audiodg.exe",
"\xd1\x51\xa9\xbf\x0e\x2f\xd3\x11\xbf\xd1\x00\xc0\x4f\xa3\x49\x0a\x01\x00": "aqueue.dll",
"\x84\x55\x66\x1e\xfe\x40\x50\x44\x8f\x6e\x80\x23\x62\x39\x96\x94\x01\x00": "lsm.exe",
"\x41\x76\x17\xaa\x9b\xfc\xbd\x41\x80\xff\xf9\x64\xa7\x01\x59\x6f\x01\x00": "tssdis.exe",
"\xe0\x0c\x6b\x90\x0b\xc7\x67\x10\xb3\x17\x00\xdd\x01\x06\x62\xda\x01\x00": "msdtcprx.dll",
"\x51\xb9\x6b\xfd\x30\xc8\x34\x47\xbf\x2c\x18\xba\x6e\xc7\xab\x49\x01\x00": "iscsiexe.dll",
"\x68\xff\x1d\x62\x39\x3c\x6c\x4c\xaa\xe3\xe6\x8e\x2c\x65\x03\xad\x01\x00": "wzcsvc.dll",
"\x56\xcc\x35\x94\x9c\x1d\x24\x49\xac\x7d\xb6\x0a\x2c\x35\x20\xe1\x01\x00": "sppsvc.exe",
"\xf0\xe4\x9c\x36\xdc\x0f\xd3\x11\xbd\xe8\x00\xc0\x4f\x8e\xee\x78\x01\x00": "profmap.dll",
"\x6a\x28\x19\x39\x0c\xb1\xd0\x11\x9b\xa8\x00\xc0\x4f\xd9\x2e\xf5\x00\x00": "lsasrv.dll",
"\x80\x2b\xd1\x76\x67\x34\xd3\x11\x91\xff\x00\x90\x27\x2f\x9e\xa3\x01\x00": "mqqm.dll",
"\x72\xfe\x0f\x8d\x52\xd2\xd0\x11\xbf\x8f\x00\xc0\x4f\xd9\x12\x6b\x01\x00": "cryptsvc.dll",
"\x86\xd4\xdc\x68\x9e\x66\xd1\x11\xab\x0c\x00\xc0\x4f\xc2\xdc\xd2\x01\x00": "ismserv.exe",
"\x83\xaf\xe1\x1f\x5d\xc9\x11\x91\xa4\x08\x00\x2b\x14\xa0\xfa\x03\x00\x00": "rpcss.dll",
"\x06\x91\x01\x24\x03\xa2\x42\x46\xb8\x8d\x82\xda\xe9\x15\x89\x29\x01\x00": "authui.dll",
"\x60\xa7\xa4\x5c\xb1\xeb\xcf\x11\x86\x11\x00\xa0\x24\x54\x20\xed\x01\x00": "termsrv.dll",
"\x4d\xdd\x73\x34\x88\x2e\x06\x40\x9c\xba\x22\x57\x09\x09\xdd\x10\x05\x01": "winhttp.dll",
"\xb2\xb8\x7d\xb9\x63\x4c\xcf\x11\xbf\xf6\x08\x00\x2b\xe2\x3f\x2f\x02\x00": "clussvc.exe",
"\x95\x1f\x51\x33\x84\x5b\xcc\x4d\xb6\xcc\x3f\x4b\x21\xda\x53\xe1\x01\x00": "ubpm.dll",
"\x78\xb2\xeb\x05\x14\xe1\xc1\x4e\xa5\xa3\x09\x61\x53\xf3\x00\xe4\x01\x01": "tsgqec.dll",
"\x24\xe4\xfb\x63\x29\x20\xd1\x11\x8d\xb8\x00\xaa\x00\x4a\xbd\x5e\x01\x00": "Sens.dll",
"\x36\xa0\x67\x07\x22\x0d\xaa\x48\xba\x69\xb6\x19\x48\x0f\x38\xcb\x01\x00": "pcasvc.dll",
"\x20\x32\x5f\x2f\x26\xc1\x76\x10\xb5\x49\x07\x4d\x07\x86\x19\xda\x01\x00": "netdde.exe",
"\x30\xa0\xb3\xfd\x5f\x06\xd1\x11\xbb\x9b\x00\xa0\x24\xea\x55\x25\x01\x00": "mqqm.dll",
"\x80\x7a\xdf\x77\x98\xf2\xd0\x11\x83\x58\x00\xa0\x24\xc4\x80\xa8\x01\x00": "mqdssrv.dll",
"\x03\x6d\x71\x98\xac\x89\xc7\x44\xbb\x8c\x28\x58\x24\xe5\x1c\x4a\x01\x00": "srvsvc.dll",
"\xc8\xad\x32\x4f\x52\x60\x04\x4a\x87\x01\x29\x3c\xcf\x20\x96\xf0\x01\x00": "sspisrv.dll",
"\x90\x38\xa9\x65\xb9\xfa\xa3\x43\xb2\xa5\x1e\x33\x0a\xc2\x8f\x11\x02\x00": "dnsrslvr.dll",
"\x32\xf5\x03\xc5\x3a\x44\x69\x4c\x83\x00\xcc\xd1\xfb\xdb\x38\x39\x01\x00": "MpSvc.dll",
"\x46\x9f\x3b\xc3\x88\x20\xbc\x4d\x97\xe3\x61\x25\xf1\x27\x66\x1c\x01\x00": "nlasvc.dll",
"\xa0\xb3\x02\xa0\xb7\xc9\xd1\x11\xae\x88\x00\x80\xc7\x5e\x4e\xc1\x01\x00": "wlnotify.dll",
"\xd0\xd1\x33\x88\x5f\x96\x16\x42\xb3\xe9\xfb\xe5\x8c\xad\x31\x00\x01\x00": "SCardSvr.dll",
"\x98\xd0\xff\x6b\x12\xa1\x10\x36\x98\x33\x46\xc3\xf8\x7e\x34\x5a\x01\x00": "wkssvc.dll",
"\x38\x8d\x04\x7e\x08\xac\xf1\x4f\x8e\x6b\xf3\x5d\xba\xb8\x8d\x4a\x01\x00": "mqqm.dll",
"\x35\x42\x51\xe3\x06\x4b\xd1\x11\xab\x04\x00\xc0\x4f\xc2\xdc\xd2\x04\x00": "ntdsai.dll",
"\xc8\x4f\x32\x4b\x70\x16\xd3\x01\x12\x78\x5a\x47\xbf\x6e\xe1\x88\x00\x00": "sfmsvc.exe",
"\xc5\x28\x47\x3c\xab\xf0\x8b\x44\xbd\xa1\x6c\xe0\x1e\xb0\xa6\xd6\x01\x00": "dhcpcsvc6.dll",
"\x36\x01\x00\x00\x00\x00\x00\x00\xc0\x00\x00\x00\x00\x00\x00\x46\x00\x00": "rpcss.dll",
"\x54\x79\x26\x3d\xb7\xee\xd1\x11\xb9\x4e\x00\xc0\x4f\xa3\x08\x0d\x01\x00": "lserver.dll",
"\xbf\x09\x11\x81\xe1\xa4\xd1\x11\xab\x54\x00\xa0\xc9\x1e\x9b\x45\x01\x00": "WINS.EXE",
"\xd0\xbb\xf5\x7a\x63\x60\xd1\x11\xae\x2a\x00\x80\xc7\x5e\x4e\xc1\x00\x00": "irmon.dll",
"\x99\x1e\xb8\x12\x07\xf2\x4c\x4a\x85\xd3\x77\xb4\x2f\x76\xfd\x14\x01\x00": "seclogon.dll",
"\x6c\x5e\x64\x00\x9f\xfc\x0c\x4a\x98\x96\xf0\x0b\x66\x29\x77\x98\x01\x00": "icardagt.exe",
"\x9f\x2f\x5b\xb1\x3c\x90\x71\x46\x8d\xc0\x77\x2c\x54\x21\x40\x68\x01\x00": "pwmig.dll",
"\xa6\x95\x7d\x49\x27\x2d\xf5\x4b\x9b\xbd\xa6\x04\x69\x57\x13\x3c\x01\x00": "termsrv.dll",
"\xcb\x92\xbe\x5c\xbe\xf4\xc9\x45\x9f\xc9\x33\xe7\x3e\x55\x7b\x20\x01\x00": "lsasrv.dll",
"\xa1\x0f\x51\x69\x99\x2f\xeb\x4e\xa4\xff\xaf\x25\x9f\x0f\x97\x49\x01\x00": "wecsvc.dll",
"\x70\x5d\xfb\x8c\xa4\x31\xcf\x11\xa7\xd8\x00\x80\x5f\x48\xa1\x35\x03\x00": "smtpsvc.dll",
"\x46\x0d\x85\x77\x1d\x85\xb6\x43\x93\x98\x29\x01\x61\xf0\xca\xe6\x01\x00": "SeVA.dll",
"\xc3\x26\xf2\x76\x14\xec\x25\x43\x8a\x99\x6a\x46\x34\x84\x18\xaf\x01\x00": "winlogon.exe",
"\x84\x65\x0a\x0b\x0f\x9e\xcf\x11\xa3\xcf\x00\x80\x5f\x68\xcb\x1b\x01\x00": "rpcss.dll",
"\x15\x55\xf2\x11\x79\xc8\x0a\x40\x98\x9e\xb0\x74\xd5\xf0\x92\xfe\x01\x00": "lsm.exe",
"\xc0\xe0\x4d\x89\x55\x0d\xd3\x11\xa3\x22\x00\xc0\x4f\xa3\x21\xa1\x01\x00": "wininit.exe",
"\x00\xac\x0a\xf5\xf3\xc7\x8e\x42\xa0\x22\xa6\xb7\x1b\xfb\x9d\x43\x01\x00": "cryptsvc.dll",
"\xa5\x44\xb0\x30\x25\xa2\xf0\x43\xb3\xa4\xe0\x60\xdf\x91\xf9\xc1\x01\x00": "certprop.dll",
"\x78\x57\x34\x12\x34\x12\xcd\xab\xef\x00\x01\x23\x45\x67\x89\xab\x00\x00": "lsasrv.dll",
"\x49\x69\xe9\x98\x59\xbc\xf1\x47\x92\xd1\x8c\x25\xb4\x6f\x85\xc7\x01\x00": "wlanext.exe",
"\xb8\x61\xe5\xff\x15\xbf\xcf\x11\x8c\x5e\x08\x00\x2b\xb4\x96\x49\x02\x00": "clussvc.exe",
"\xb4\x59\xcc\xf5\x64\x42\x1a\x10\x8c\x59\x08\x00\x2b\x2f\x84\x26\x01\x00": "ntfrs.exe",
"\xb4\x59\xcc\xf5\x64\x42\x1a\x10\x8c\x59\x08\x00\x2b\x2f\x84\x26\x01\x01": "ntfrs.exe",
"\xa4\xc2\xab\x50\x4d\x57\xb3\x40\x9d\x66\xee\x4f\xd5\xfb\xa0\x76\x05\x00": "dns.exe",
"\xb9\x99\x3f\x87\x4d\x1b\x10\x99\xb7\xaa\x00\x04\x00\x7f\x07\x01\x00\x00": "ssmsrp70.dll",
"\x01\xc3\x53\xb2\xa2\x78\x70\x42\xa9\x1f\x66\x0d\xee\x06\x9f\x4c\x01\x00": "rdpcore.dll",
"\x94\x68\x71\x22\x8e\xfd\x62\x44\x97\x83\x09\xe6\xd9\x53\x1f\x16\x01\x00": "ubpm.dll",
"\xf6\xb8\x35\xd3\x31\xcb\xd0\x11\xb0\xf9\x00\x60\x97\xba\x4e\x54\x01\x00": "polagent.dll",
"\x64\x1d\x82\x0c\xfc\xa3\xd1\x11\xbb\x7a\x00\x80\xc7\x5e\x4e\xc1\x01\x00": "irftp.exe",
"\xb8\x4a\x9f\x4d\x1c\x7d\xcf\x11\x86\x1e\x00\x20\xaf\x6e\x7c\x57\x00\x00": "rpcss.dll",
"\xa8\x95\xee\x81\x2e\x88\x15\x46\x88\x8a\x53\x34\x4c\xa1\x49\xe4\x01\x00": "vpnikeapi.dll",
"\xfb\xee\x0c\x13\x66\xe4\xd1\x11\xb7\x8b\x00\xc0\x4f\xa3\x28\x83\x02\x00": "ismip.dll",
"\x72\xee\xf3\xc6\x7e\xce\xd1\x11\xb7\x1e\x00\xc0\x4f\xc3\x11\x1a\x01\x00": "rpcss.dll",
"\x9a\xf9\x1e\x20\xa0\x7f\x4c\x44\x93\x99\x19\xba\x84\xf1\x2a\x1a\x01\x00": "appinfo.dll",
"\xc8\x4f\x32\x4b\x70\x16\xd3\x01\x12\x78\x5a\x47\xbf\x6e\xe1\x88\x03\x00": "srvsvc.dll",
"\x72\xe4\x9f\x6d\xf1\x30\x08\x47\x8f\xa8\x67\x83\x62\xb9\x61\x55\x01\x00": "wimserv.exe",
"\xd4\xd7\x44\x7c\xd5\x31\x4c\x42\xbd\x5e\x2b\x3e\x1f\x32\x3d\x22\x01\x00": "ntdsai.dll",
"\x55\x1a\x20\x6f\x4d\xa2\x5f\x49\xaa\xc9\x2f\x4f\xce\x34\xdf\x99\x01\x00": "IPHLPAPI.DLL",
"\x32\x35\x0f\x30\xcc\x38\xd0\x11\xa3\xf0\x00\x20\xaf\x6b\x0a\xdd\x01\x02": "trkwks.dll",
"\x32\x35\x0f\x30\xcc\x38\xd0\x11\xa3\xf0\x00\x20\xaf\x6b\x0a\xdd\x01\x00": "trkwks.dll",
"\x60\xf4\x82\x4f\x21\x0e\xcf\x11\x90\x9e\x00\x80\x5f\x48\xa1\x35\x04\x00": "nntpsvc.dll",
"\x7d\xce\x54\x5f\x79\x5b\x75\x41\x85\x84\xcb\x65\x31\x3a\x0e\x98\x01\x00": "appinfo.dll",
"\xdc\x3f\x27\x82\x2a\xe3\xc3\x18\x3f\x78\x82\x79\x29\xdc\x23\xea\x00\x00": "wevtsvc.dll",
"\x3a\xcf\xe0\x16\x04\xa6\xd0\x11\x96\xb1\x00\xa0\xc9\x1e\xce\x30\x01\x00": "ntdsbsrv.dll",
"\x98\xd0\xff\x6b\x12\xa1\x10\x36\x98\x33\x01\x28\x92\x02\x01\x62\x00\x00": "browser.dll",
"\xd6\x09\x48\x48\x39\x42\x1b\x47\xb5\xbc\x61\xdf\x8c\x23\xac\x48\x01\x00": "lsm.exe",
"\xe8\x04\xe6\x58\xdb\x9a\x2e\x4d\xa4\x64\x3b\x06\x83\xfb\x14\x80\x01\x00": "appinfo.dll",
"\x57\x72\xd4\xa2\xf7\x12\xeb\x4b\x89\x81\x0e\xbf\xa9\x35\xc4\x07\x01\x00": "p2psvc.dll",
"\x1e\xdd\x5b\x6b\x8c\x52\x2c\x42\xaf\x8c\xa4\x07\x9b\xe4\xfe\x48\x01\x00": "FwRemoteSvr.dll",
"\x75\x21\xc8\x51\x4e\x84\x50\x47\xb0\xd8\xec\x25\x55\x55\xbc\x06\x01\x00": "SLsvc.exe",
"\x78\x57\x34\x12\x34\x12\xcd\xab\xef\x00\x01\x23\x45\x67\x89\xac\x01\x00": "samsrv.dll",
"\xc0\x47\xdf\xb3\x5a\xa9\xcf\x11\xaa\x26\x00\xaa\x00\xc1\x48\xb9\x09\x00": "mspadmin.exe - Microsoft ISA Server",
"\x00\xac\x0a\xf5\xf3\xc7\x8e\x42\xa0\x22\xa6\xb7\x1b\xfb\x9d\x43\x01\x01": "cryptsvc.dll",
"\x65\x31\x0a\xea\x34\x48\xd2\x11\xa6\xf8\x00\xc0\x4f\xa3\x46\xcc\x04\x00": "FXSSVC.exe",
"\x33\xa2\x74\xd6\x29\x58\xdd\x49\x90\xf0\x60\xcf\x9c\xeb\x71\x29\x01\x00": "ipnathlp.dll",
"\xf7\xaf\xbe\xf6\x19\x1e\xbb\x4f\x9f\x8f\xb8\x9e\x20\x18\x33\x7c\x01\x00": "wevtsvc.dll",
"\x70\x0d\xec\xec\x03\xa6\xd0\x11\x96\xb1\x00\xa0\xc9\x1e\xce\x30\x02\x00": "ntdsbsrv.dll",
"\x7c\xda\x83\x4f\xe8\xd2\x11\x98\x07\x00\xc0\x4f\x8e\xc8\x50\x02\x00\x00": "sfc.dll",
"\x80\x92\xea\x46\xbf\x5b\x5e\x44\x83\x1d\x41\xd0\xf6\x0f\x50\x3a\x01\x00": "ifssvc.exe",
"\x81\xbb\x7a\x36\x44\x98\xf1\x35\xad\x32\x98\xf0\x38\x00\x10\x03\x02\x00": "services.exe",
"\x66\x9f\x9b\x62\x6c\x55\xd1\x11\x8d\xd2\x00\xaa\x00\x4a\xbd\x5e\x03\x00": "sens.dll",
"\x1c\x02\x0c\xa0\xe2\x2b\xd2\x11\xb6\x78\x00\x00\xf8\x7a\x8f\x8e\x01\x00": "ntfrs.exe",
"\x3e\xca\x86\xc3\x61\x90\x72\x4a\x82\x1e\x49\x8d\x83\xbe\x18\x8f\x01\x01": "audiosrv.dll",
"\x6d\xa5\x6e\xe7\x3f\x45\xcf\x11\xbf\xec\x08\x00\x2b\xe2\x3f\x2f\x02\x01": "resrcmon.exe",
"\xe1\xbf\x72\x4a\x94\x92\xda\x11\xa7\x2b\x08\x00\x20\x0c\x9a\x66\x01\x00": "rdpinit.exe",
"\x7c\x5f\xc4\xa2\x32\x7d\xad\x46\x96\xf5\xad\xaf\xb4\x86\xbe\x74\x01\x00": "services.exe",
"\x01\x6b\x77\x45\x56\x59\x85\x44\x9f\x80\xf4\x28\xf7\xd6\x01\x29\x02\x00": "dnsrslvr.dll",
"\x96\x7b\x9b\x6c\xa8\x45\xca\x4c\x9e\xb3\xe2\x1c\xcf\x8b\x5a\x89\x01\x00": "umpo.dll",
"\x15\x04\x42\x9d\xfb\xb8\x4a\x4f\x8c\x53\x45\x02\xea\xd3\x0c\xa9\x01\x00": "PlaySndSrv.dll",
"\x50\x38\xcd\x15\xca\x28\xce\x11\xa4\xe8\x00\xaa\x00\x61\x16\xcb\x01\x00": "PeerDistSvc.dll",
"\x20\xe5\x98\xa3\x9a\xd5\xdd\x4b\xaa\x7a\x3c\x1e\x03\x03\xa5\x11\x01\x00": "IKEEXT.DLL",
"\x08\x83\xaf\xe1\x1f\x5d\xc9\x11\x91\xa4\x08\x00\x2b\x14\xa0\xfa\x03\x00": "rpcss.dll",
"\x00\x7c\xda\x83\x4f\xe8\xd2\x11\x98\x07\x00\xc0\x4f\x8e\xc8\x50\x02\x00": "sfc_os.dll",
"\xf2\xdc\x51\x4a\x3a\x5c\xd2\x4d\x84\xdb\xc3\x80\x2e\xe7\xf9\xb7\x01\x00": "ntdsai.dll",
"\x82\x06\xf7\x1f\x51\x0a\xe8\x30\x07\x6d\x74\x0b\xe8\xce\xe9\x8b\x01\x00": "taskcomp.dll",
"\x00\xb9\x99\x3f\x87\x4d\x1b\x10\x99\xb7\xaa\x00\x04\x00\x7f\x07\x01\x00": "ssmsrpc.dll - Microsoft SQL Server",
"\x20\x17\x82\x5b\x3b\xf6\xd0\x11\xaa\xd2\x00\xc0\x4f\xc3\x24\xdb\x01\x00": "dhcpssvc.dll",
"\x22\xc4\xa1\x4d\x3d\x94\xd1\x11\xac\xae\x00\xc0\x4f\xc2\xaa\x3f\x01\x00": "trksvr.dll",
"\x74\xe9\xa5\x1a\x82\x62\x8d\x4e\x9c\x96\x40\x18\x6e\x89\xd2\x80\x01\x00": "scss.exe",
"\x94\x73\x92\x1a\x2e\x35\x53\x45\xae\x3f\x7c\xf4\xaa\xfc\xa6\x20\x01\x00": "wdssrv.dll",
"\x66\xf6\x8c\x04\x42\xab\xb4\x42\x89\x75\x13\x57\x01\x8d\xec\xb3\x01\x00": "ws2_32.dll",
"\x3a\xcf\xe0\x16\x04\xa6\xd0\x11\x96\xb1\x00\xa0\xc9\x1e\xce\x30\x02\x00": "ntdsbsrv.dll",
"\x02\x00\x00\x00\x01\x00\x00\x00\xc0\x00\x00\x00\x00\x00\x00\x69\x01\x00": "kdcsvc.dll",
"\xb0\x52\x8e\x37\xa9\xc0\xcf\x11\x82\x2d\x00\xaa\x00\x51\xe4\x0f\x01\x00": "taskcomp.dll",
"\xe0\x6d\x7a\x8c\x8d\x78\xd0\x11\x9e\xdf\x44\x45\x53\x54\x00\x00\x02\x00": "wiaservc.dll",
"\x05\x81\xa7\x3c\xa3\xa3\x68\x4a\xb4\x58\x1a\x60\x6b\xab\x8f\xd6\x01\x00": "mpnotify.exe",
"\x2e\xa0\x8a\xb5\x84\x28\x97\x4e\x81\x76\x4e\xe0\x6d\x79\x41\x84\x01\x00": "sysmain.dll",
"\x95\x4f\x25\xd4\xc3\x08\xcc\x4f\xb2\xa6\x0b\x65\x13\x77\xa2\x9c\x01\x00": "wwansvc.dll",
"\x6e\x2c\xf4\xc3\xcc\xd4\x5a\x4e\x93\x8b\x9c\x5e\x8a\x5d\x8c\x2e\x01\x00": "wlanmsm.dll",
"\x53\x0c\x19\xf3\x0c\x4e\x1a\x49\xaa\xd3\x2a\x7c\xeb\x7e\x25\xd4\x01\x00": "vpnikeapi.dll",
"\x26\xc0\xe1\xac\x3f\x8b\x11\x47\x89\x18\xf3\x45\xd1\x7f\x5b\xff\x01\x00": "lsasrv.dll",
"\xc0\xc4\x55\xae\xce\x64\xdd\x11\xad\x8b\x08\x00\x20\x0c\x9a\x66\x01\x00": "bdesvc.dll",
"\xc4\x0c\x3c\xe3\x82\x04\x1a\x10\xbc\x0c\x02\x60\x8c\x6b\xa2\x18\x01\x00": "locator.exe",
"\x0e\x3b\x6c\x50\xd1\x4b\x56\x4c\x88\xc0\x49\xa2\x0e\xd4\xb5\x39\x01\x00": "milcore.dll",
"\x3e\x8e\xb0\x2e\x9f\x63\xba\x4f\x97\xb1\x14\xf8\x78\x96\x10\x76\x01\x00": "gpsvc.dll",
"\x66\x9f\x9b\x62\x6c\x55\xd1\x11\x8d\xd2\x00\xaa\x00\x4a\xbd\x5e\x02\x00": "sens.dll",
"\xb5\x6d\xac\xc9\xb7\x82\x55\x4e\xae\x8a\xe4\x64\xed\x7b\x42\x77\x01\x00": "sysntfy.dll",
"\x98\x46\xbc\xa0\xd7\xb8\x30\x43\xa2\x8f\x77\x09\xe1\x8b\x61\x08\x04\x00": "Sens.dll",
"\x1e\xc9\x31\x3f\x45\x25\x7b\x4b\x93\x11\x95\x29\xe8\xbf\xfe\xf6\x01\x00": "p2psvc.dll",
"\x3e\xca\x86\xc3\x61\x90\x72\x4a\x82\x1e\x49\x8d\x83\xbe\x18\x8f\x02\x00": "audiosrv.dll",
"\x3e\xca\x86\xc3\x61\x90\x72\x4a\x82\x1e\x49\x8d\x83\xbe\x18\x8f\x02\x02": "audiosrv.dll",
"\xf8\x91\x7b\x5a\x00\xff\xd0\x11\xa9\xb2\x00\xc0\x4f\xb6\xe6\xfc\x01\x00": "msgsvc.dll",
"\x98\xd0\xff\x6b\x12\xa1\x10\x36\x98\x33\x46\xc3\xf8\x74\x53\x2d\x01\x00": "dhcpssvc.dll",
"\xb8\xd0\x48\xe2\x15\xbf\xcf\x11\x8c\x5e\x08\x00\x2b\xb4\x96\x49\x02\x00": "clussvc.exe",
"\x78\xad\xbc\x1c\x0b\xdf\x34\x49\xb5\x58\x87\x83\x9e\xa5\x01\xc9\x00\x00": "lsasrv.dll",
"\x87\x76\xcb\xc8\xd3\xe6\xd2\x11\xa9\x58\x00\xc0\x4f\x68\x2e\x16\x01\x00": "WebClnt.dll",
"\x88\xd4\x81\xc6\x50\xd8\xd0\x11\x8c\x52\x00\xc0\x4f\xd9\x0f\x7e\x01\x00": "lsasrv.dll",
"\x80\x35\x5b\x5b\xe0\xb0\xd1\x11\xb9\x2d\x00\x60\x08\x1e\x87\xf0\x01\x00": "mqqm.dll",
"\xf0\x09\x8f\xed\xb7\xce\x11\xbb\xd2\x00\x00\x1a\x18\x1c\xad\x00\x00\x00": "mprdim.dll",
"\xd8\x5d\xe6\x12\x7f\x88\xef\x41\x91\xbf\x8d\x81\x6c\x42\xc2\xe7\x01\x00": "winlogon.exe",
"\xf8\x91\x7b\x5a\x00\xff\xd0\x11\xa9\xb2\x00\xc0\x4f\xb6\x36\xfc\x01\x00": "msgsvc.dll",
"\x01\xd0\x8c\x33\x44\x22\xf1\x31\xaa\xaa\x90\x00\x38\x00\x10\x03\x01\x00": "regsvc.dll",
"\x03\xd7\xfd\x17\x27\x18\x34\x4e\x79\xd4\x24\xa5\x5c\x53\xbb\x37\x01\x00": "msgsvc.dll",
"\x1c\x95\x57\x33\xd1\xa1\xdb\x47\xa2\x78\xab\x94\x5d\x06\x3d\x03\x01\x00": "LBService.dll",
"\xab\xbe\x00\xc1\x3a\xd3\x4b\x4a\xbf\x23\xbb\xef\x46\x63\xd0\x17\x01\x00": "wcncsvc.dll",
"\xc4\xfc\x7b\x82\xb4\x38\xcd\x4a\x92\xe4\x21\xe1\x50\x6b\x85\xfb\x01\x00": "SLsvc.exe",
"\x00\xf0\x09\x8f\xed\xb7\xce\x11\xbb\xd2\x00\x00\x1a\x18\x1c\xad\x00\x00": "mprdim.dll",
"\x4b\xa0\x12\x72\x63\xb4\x2e\x40\x96\x49\x2b\xa4\x77\x39\x46\x76\x01\x00": "umrdp.dll",
"\x20\x65\x5f\x2f\x46\xca\x67\x10\xb3\x19\x00\xdd\x01\x06\x62\xda\x01\x00": "tapisrv.dll",
"\xa0\x9e\xc0\x69\x09\x4a\x1b\x10\xae\x4b\x08\x00\x2b\x34\x9a\x02\x00\x00": "ole32.dll",
"\xd0\x3f\x14\x88\x8d\xc2\x2b\x4b\x8f\xef\x8d\x88\x2f\x6a\x93\x90\x01\x00": "lsm.exe",
"\xe6\x73\x0c\xe6\xf9\x88\xcf\x11\x9a\xf1\x00\x20\xaf\x6e\x72\xf4\x02\x00": "rpcss.dll",
"\x6c\xfc\x79\xde\x6f\xdc\xc7\x43\xa4\x8e\x63\xbb\xc8\xd4\x00\x9d\x01\x00": "rdpclip.exe",
"\x41\x82\xb5\x68\x59\xc2\x03\x4f\xa2\xe5\xa2\x65\x1d\xcb\xc9\x30\x01\x00": "cryptsvc.dll",
"\x80\xa9\x88\x10\xe5\xea\xd0\x11\x8d\x9b\x00\xa0\x24\x53\xc3\x37\x01\x00": "mqqm.dll",
"\xcf\x0b\xa7\x7e\xaf\x48\x6a\x4f\x89\x68\x6a\x44\x07\x54\xd5\xfa\x01\x00": "nsisvc.dll",
"\xe0\xca\x02\xec\xe0\xb9\xd2\x11\xbe\x62\x00\x20\xaf\xed\xdf\x63\x01\x00": "mq1repl.dll",
"\xb3\x8b\x0b\x59\xf6\x4e\xa4\x4c\x83\xcf\xbe\x06\xc4\x07\x86\x74\x01\x00": "PSIService.exe",
"\xce\x9f\x75\x89\x25\x5a\x86\x40\x89\x67\xde\x12\xf3\x9a\x60\xb5\x01\x00": "tssdjet.dll",
"\x5d\x2c\x95\x25\x76\x79\xa1\x4a\xa3\xcb\xc3\x5f\x7a\xe7\x9d\x1b\x01\x00": "wlansvc.dll",
"\xc5\x41\x19\xdf\x89\xfe\x79\x4e\xbf\x10\x46\x36\x57\xac\xf4\x4d\x01\x00": "efssvc.dll",
"\xc1\xcd\x1a\x8f\x4d\x75\xeb\x43\x96\x29\xaa\x16\x20\x92\x8e\x65\x00\x00": "IMEPADSM.DLL",
"\xdf\x76\x49\x65\x98\x14\x56\x40\xa1\x5e\xcb\x4e\x87\x58\x4b\xd8\x01\x00": "emdmgmt.dll",
"\xe0\x42\xc7\x4f\x10\x4a\xcf\x11\x82\x73\x00\xaa\x00\x4a\xe6\x73\x03\x00": "dfssvc.exe",
"\xfa\xdb\x6e\x0b\x24\x4a\xc6\x4f\x8a\x23\x94\x2b\x1e\xca\x65\xd1\x01\x00": "spoolsv.exe",
"\xc8\xb7\xd4\x12\xd5\x77\xd1\x11\x8c\x24\x00\xc0\x4f\xa3\x08\x0d\x01\x00": "lserver.dll",
"\x44\xaf\x7d\x8c\xdc\xb6\xd1\x11\x9a\x4c\x00\x20\xaf\x6e\x7c\x57\x01\x00": "appmgmts.dll",
"\xae\x99\x86\x9b\x44\x0e\xb1\x47\x8e\x7f\x86\xa4\x61\xd7\xec\xdc\x00\x00": "rpcss.dll",
"\x84\x65\x0a\x0b\x0f\x9e\xcf\x11\xa3\xcf\x00\x80\x5f\x68\xcb\x1b\x01\x01": "rpcss.dll",
"\xa2\x9c\x14\x93\x3b\x97\xd1\x11\x8c\x39\x00\xc0\x4f\xb9\x84\xf9\x00\x00": "scecli.dll",
"\x7d\x25\x13\xfc\x67\x55\xea\x4d\x89\x8d\xc6\xf9\xc4\x84\x15\xa0\x01\x00": "mqqm.dll",
"\x82\x26\xb9\x2f\x99\x65\xdc\x42\xae\x13\xbd\x2c\xa8\x9b\xd1\x1c\x01\x00": "MPSSVC.dll",
"\x76\x22\x3a\x33\x00\x00\x00\x00\x0d\x00\x00\x80\x9c\x00\x00\x00\x03\x00": "rpcrt4.dll",
"\xf0\x0e\xd7\xd6\x3b\x0e\xcb\x11\xac\xc3\x08\x00\x2b\x1d\x29\xc4\x01\x00": "locator.exe",
"\xdd\x34\x91\x1a\x39\x7b\xba\x45\xad\x88\x44\xd0\x1c\xa4\x7f\x28\x01\x00": "mqqm.dll",
"\xfe\x95\x31\x9b\x03\xd6\xd1\x43\xa0\xd5\x90\x72\xd7\xcd\xe1\x22\x01\x00": "tssdjet.dll",
"\x55\x1a\x20\x6f\x4d\xa2\x5f\x49\xaa\xc9\x2f\x4f\xce\x34\xdf\x98\x01\x00": "iphlpsvc.dll",
"\x5f\x2e\x7e\x89\xf3\x93\x76\x43\x9c\x9c\xfd\x22\x77\x49\x5c\x27\x01\x00": "dfsrmig.exe",
"\x90\x2c\xfe\x98\x42\xa5\xd0\x11\xa4\xef\x00\xa0\xc9\x06\x29\x10\x01\x00": "advapi32.dll",
"\x0c\xc5\xad\x30\xbc\x5c\xce\x46\x9a\x0e\x91\x91\x47\x89\xe2\x3c\x01\x00": "nrpsrv.dll",
"\x1e\x24\x2f\x41\x2a\xc1\xce\x11\xab\xff\x00\x20\xaf\x6e\x7a\x17\x00\x02": "rpcss.dll",
"\xe6\x53\x3a\x9f\xb1\xcb\x54\x4e\x87\x8e\xaf\x9f\x82\x3a\xa3\xf1\x01\x00": "MpRtMon.dll",
"\xa8\xe5\xfc\x1d\x8a\xdd\x33\x4e\xaa\xce\xf6\x03\x92\x2f\xd9\xe7\x00\x01": "wpcsvc.dll",
"\xf0\x0e\xd7\xd6\x3b\x0e\xcb\x11\xac\xc3\x08\x00\x2b\x1d\x29\xc3\x01\x00": "locator.exe",
"\x46\xd7\xd0\xe3\xaf\xd2\xfd\x40\x8a\x7a\x0d\x70\x78\xbb\x70\x92\x01\x00": "qmgr.dll",
"\x5a\x23\xb5\xc6\x13\xe4\x1d\x48\x9a\xc8\x31\x68\x1b\x1f\xaa\xf5\x01\x01": "SCardSvr.dll",
"\x5a\x23\xb5\xc6\x13\xe4\x1d\x48\x9a\xc8\x31\x68\x1b\x1f\xaa\xf5\x01\x00": "SCardSvr.dll",
"\x69\x45\x81\x7d\xb3\x35\x50\x48\xbb\x32\x83\x03\x5f\xce\xbf\x6e\x01\x00": "ias.dll",
"\x41\xea\x25\x48\xe3\x51\x2a\x4c\x84\x06\x8f\x2d\x26\x98\x39\x5f\x01\x00": "userenv.dll",
"\xc4\xfe\xfc\x99\x60\x52\x1b\x10\xbb\xcb\x00\xaa\x00\x21\x34\x7a\x00\x00": "rpcss.dll",
"\xc5\x28\x47\x3c\xab\xf0\x8b\x44\xbd\xa1\x6c\xe0\x1e\xb0\xa6\xd5\x01\x00": "dhcpcsvc.dll",
"\xe0\x8e\x20\x41\x70\xe9\xd1\x11\x9b\x9e\x00\xe0\x2c\x06\x4c\x39\x01\x00": "mqqm.dll",
"\xbf\x7b\x40\xcb\x4f\xc1\xd9\x4c\x8f\x55\xcb\xb0\x81\x46\x59\x8c\x00\x00": "IMJPDCT.EXE",
"\x78\x56\x34\x12\x34\x12\xcd\xab\xef\x00\x01\x23\x45\x67\xcf\xfb\x01\x00": "netlogon.dll",
"\x30\x4c\xda\x83\x3a\xea\xcf\x11\x9c\xc1\x08\x00\x36\x01\xe5\x06\x01\x00": "nfsclnt.exe",
"\x1f\xa7\x37\x21\x5e\xbb\x29\x4e\x8e\x7e\x2e\x46\xa6\x68\x1d\xbf\x09\x00": "wspsrv.exe - Microsoft ISA Server",
"\x1e\x67\xe9\xc0\xc6\x33\x38\x44\x94\x64\x56\xb2\xe1\xb1\xc7\xb4\x01\x00": "wbiosrvc.dll",
"\x80\xbd\xa8\xaf\x8a\x7d\xc9\x11\xbe\xf4\x08\x00\x2b\x10\x29\x89\x01\x00": "rpcrt4.dll",
"\x8b\x3c\xf1\x6a\x44\x08\x83\x4c\x90\x64\x18\x92\xba\x82\x55\x27\x01\x00": "tssdis.exe",
"\x55\x51\xd8\xec\x3a\xcc\x10\x4f\xaa\xd5\x9a\x9a\x2b\xf2\xef\x0c\x01\x00": "termsrv.dll",
"\xe8\x98\x8b\xbb\xdd\x84\xe7\x45\x9f\x34\xc3\xfb\x61\x55\xee\xed\x01\x00": "vaultsvc.dll",
"\x86\xb1\x49\xd0\x4f\x81\xd1\x11\x9a\x3c\x00\xc0\x4f\xc9\xb2\x32\x01\x00": "ntfrs.exe",
"\x5d\x2c\x95\x25\x76\x79\xa1\x4a\xa3\xcb\xc3\x5f\x7a\xe7\x9d\x1b\x01\x01": "wlansvc.dll",
"\x7f\x0b\xfe\x64\xf5\x9e\x53\x45\xa7\xdb\x9a\x19\x75\x77\x75\x54\x01\x00": "rpcss.dll",
"\x86\xd4\xdc\x68\x9e\x66\xd1\x11\xab\x0c\x00\xc0\x4f\xc2\xdc\xd2\x02\x00": "ismserv.exe",
"\xc3\x26\xf2\x76\x14\xec\x25\x43\x8a\x99\x6a\x46\x34\x84\x18\xae\x01\x00": "winlogon.exe",
"\x23\x05\x7a\xfd\x70\xdc\xdd\x43\x9b\x2e\x9c\x5e\xd4\x82\x25\xb1\x01\x00": "appinfo.dll",
"\x40\xfd\x2c\x34\x6c\x3c\xce\x11\xa8\x93\x08\x00\x2b\x2e\x9c\x6d\x00\x00": "llssrv.exe",
"\x84\xd8\xb6\x8f\x88\x23\xd0\x11\x8c\x35\x00\xc0\x4f\xda\x27\x95\x04\x01": "w32time.dll",
"\x9b\x06\x33\xae\xa8\xa2\xee\x46\xa2\x35\xdd\xfd\x33\x9b\xe2\x81\x01\x00": "spoolsv.exe",
"\x26\xb5\x55\x1d\x37\xc1\xc5\x46\xab\x79\x63\x8f\x2a\x68\xe8\x69\x01\x00": "rpcss.dll",
"\xa0\xaa\x17\x6e\x47\x1a\xd1\x11\x98\xbd\x00\x00\xf8\x75\x29\x2e\x02\x00": "clussvc.exe",
"\xdf\x5f\xe9\xbd\xe0\xee\xde\x45\x9e\x12\xe5\xa6\x1c\xd0\xd4\xfe\x01\x00": "termsrv.dll",
"\xac\xbe\x00\xc1\x3a\xd3\x4b\x4a\xbf\x23\xbb\xef\x46\x63\xd0\x17\x01\x00": "wcncsvc.dll",
"\x78\x56\x34\x12\x34\x12\xcd\xab\xef\x00\x01\x23\x45\x67\x89\xab\x01\x00": "spoolsv.exe",
"\x06\x50\x7b\x8a\x13\xcc\xdb\x11\x97\x05\x00\x50\x56\xc0\x00\x08\x01\x00": "appidsvc.dll",
"\x20\x60\xae\x91\x3c\x9e\xcf\x11\x8d\x7c\x00\xaa\x00\xc0\x91\xbe\x00\x00": "certsrv.exe",
"\x16\xbb\x74\x81\x1b\x57\x38\x4c\x83\x86\x11\x02\xb4\x49\x04\x4a\x01\x00": "p2psvc.dll",
"\x36\x00\x61\x20\x22\xfa\xcf\x11\x98\x23\x00\xa0\xc9\x11\xe5\xdf\x01\x00": "rasmans.dll",
"\x70\x0d\xec\xec\x03\xa6\xd0\x11\x96\xb1\x00\xa0\xc9\x1e\xce\x30\x01\x00": "ntdsbsrv.dll",
"\x1c\xef\x74\x0a\xa4\x41\x06\x4e\x83\xae\xdc\x74\xfb\x1c\xdd\x53\x01\x00": "schedsvc.dll",
"\x25\x04\x49\xdd\x25\x53\x65\x45\xb7\x74\x7e\x27\xd6\xc0\x9c\x24\x01\x00": "BFE.DLL",
"\x7c\x5a\xcc\xf5\x64\x42\x1a\x10\x8c\x59\x08\x00\x2b\x2f\x84\x26\x15\x00": "ntdsa.dll",
"\xa0\x01\x00\x00\x00\x00\x00\x00\xc0\x00\x00\x00\x00\x00\x00\x46\x00\x00": "rpcss.dll",
"\x49\x59\xd3\x86\xc9\x83\x44\x40\xb4\x24\xdb\x36\x32\x31\xfd\x0c\x01\x00": "schedsvc.dll",
"\x35\x08\x22\x11\x26\x5b\x94\x4d\xae\x86\xc3\xe4\x75\xa8\x09\xde\x01\x00": "lsasrv.dll",
"\xa8\x66\x00\xc8\x79\x75\xfc\x44\xb9\xb2\x84\x66\x93\x07\x91\xb0\x01\x00": "umrdp.dll",
"\xab\x59\xec\xf1\xa9\x4c\x30\x4c\xb2\xd0\x54\xef\x1d\xb4\x41\xb7\x01\x00": "iertutil.dll",
"\xba\xaa\x67\x52\x49\x4f\x53\x46\x8e\x26\xd1\xe1\x1f\x3f\x2a\xd9\x01\x00": "termsrv.dll",
"\x60\x9e\xe7\xb9\x52\x3d\xce\x11\xaa\xa1\x00\x00\x69\x01\x29\x3f\x00\x00": "rpcss.dll",
"\x60\x9e\xe7\xb9\x52\x3d\xce\x11\xaa\xa1\x00\x00\x69\x01\x29\x3f\x00\x02": "rpcss.dll",
"\x38\x47\xaf\x3f\x21\x3a\x07\x43\xb4\x6c\xfd\xda\x9b\xb8\xc0\xd5\x01\x02": "audiosrv.dll",
"\x38\x47\xaf\x3f\x21\x3a\x07\x43\xb4\x6c\xfd\xda\x9b\xb8\xc0\xd5\x01\x01": "audiosrv.dll",
"\x20\x32\x5f\x2f\x26\xc1\x76\x10\xb5\x49\x07\x4d\x07\x86\x19\xda\x01\x02": "netdde.exe",
"\xbf\x11\x9d\x7f\xb9\x7f\x6b\x43\xa8\x12\xb2\xd5\x0c\x5d\x4c\x03\x01\x00": "MPSSVC.dll",
"\xbf\x52\x5a\xb2\xdd\xe5\x4a\x4f\xae\xa6\x8c\xa7\x27\x2a\x0e\x86\x01\x00": "keyiso.dll",
"\x04\x22\x11\x4b\x19\x0e\xd3\x11\xb4\x2b\x00\x00\xf8\x1f\xeb\x9f\x01\x00": "ssdpsrv.dll",
"\x97\xb2\xee\x04\xf4\xcb\x6b\x46\x8a\x2a\xbf\xd6\xa2\xf1\x0b\xba\x01\x00": "efssvc.dll",
"\x40\xb2\x9b\x20\x19\xb9\xd1\x11\xbb\xb6\x00\x80\xc7\x5e\x4e\xc1\x01\x00": "irmon.dll",
"\x96\x3f\xf0\x76\xfd\xcd\xfc\x44\xa2\x2c\x64\x95\x0a\x00\x12\x09\x01\x00": "spoolsv.exe",
"\x4a\xa5\xbb\x06\x05\xbe\xf9\x49\xb0\xa0\x30\xf7\x90\x26\x10\x23\x01\x00": "wscsvc.dll",
"\xa6\xb2\xdd\x1b\xc3\xc0\xbe\x41\x87\x03\xdd\xbd\xf4\xf0\xe8\x0a\x01\x00": "dot3svc.dll",
"\x82\x15\x41\xaa\xdf\x9b\xfb\x48\xb4\x2b\xfa\xa1\xee\xe3\x39\x49\x01\x00": "nlasvc.dll",
"\xfa\x9d\xd7\xd2\x00\x34\xd0\x11\xb4\x0b\x00\xaa\x00\x5f\xf5\x86\x01\x00": "dmadmin.exe",
"\x12\xfc\x99\x60\xff\x3e\xd0\x11\xab\xd0\x00\xc0\x4f\xd9\x1a\x4e\x03\x00": "FXSAPI.dll",
"\x1e\x24\x2f\x41\x2a\xc1\xce\x11\xab\xff\x00\x20\xaf\x6e\x7a\x17\x00\x00": "rpcss.dll",
"\xd5\x33\x9a\x2c\xdb\xf1\x2d\x47\x84\x64\x42\xb8\xb0\xc7\x6c\x38\x01\x00": "tbssvc.dll",
"\x30\x7c\xde\x3d\x5d\x16\xd1\x11\xab\x8f\x00\x80\x5f\x14\xdb\x40\x01\x00": "services.exe",
"\x86\xb1\x49\xd0\x4f\x81\xd1\x11\x9a\x3c\x00\xc0\x4f\xc9\xb2\x32\x01\x01": "ntfrs.exe",
"\x94\x8c\x95\x95\x24\xa4\x55\x40\xb6\x2b\xb7\xf4\xd5\xc4\x77\x70\x01\x00": "winlogon.exe",
"\xe3\x31\x67\x32\xc0\xc1\x69\x4a\xae\x20\x7d\x90\x44\xa4\xea\x5c\x01\x00": "profsvc.dll",
"\x18\x5a\xcc\xf5\x64\x42\x1a\x10\x8c\x59\x08\x00\x2b\x2f\x84\x26\x38\x00": "ntdsai.dll",
"\x0f\x6a\xe9\x4b\x52\x9f\x29\x47\xa5\x1d\xc7\x06\x10\xf1\x18\xb0\x01\x00": "wbiosrvc.dll",
"\x80\x42\xad\x82\x6b\x03\xcf\x11\x97\x2c\x00\xaa\x00\x68\x87\xb0\x02\x00": "infocomm.dll",
"\x87\x04\x26\x1f\x29\xba\x13\x4f\x92\x8a\xbb\xd2\x97\x61\xb0\x83\x01\x00": "termsrv.dll",
"\x70\x07\xf7\x18\x64\x8e\xcf\x11\x9a\xf1\x00\x20\xaf\x6e\x72\xf4\x00\x00": "ole32.dll",
"\xc0\xeb\x4f\xfa\x91\x45\xce\x11\x95\xe5\x00\xaa\x00\x51\xe5\x10\x04\x00": "autmgr32.exe",
"\x10\xca\x8c\x70\x69\x95\xd1\x11\xb2\xa5\x00\x60\x97\x7d\x81\x18\x01\x00": "mqdssrv.dll",
"\x28\x2c\xf5\x45\x9f\x7f\x1a\x10\xb5\x2b\x08\x00\x2b\x2e\xfa\xbe\x01\x00": "WINS.EXE",
"\x31\xa3\x59\x2f\x7d\xbf\xcb\x48\x9e\x5c\x7c\x09\x0d\x76\xe8\xb8\x01\x00": "termsrv.dll",
"\x61\x26\x45\x4a\x90\x82\x36\x4b\x8f\xbe\x7f\x40\x93\xa9\x49\x78\x01\x00": "spoolsv.exe",
}

KNOWN_PROTOCOLS = {
'52C80B95-C1AD-4240-8D89-72E9FA84025E':'[MC-CCFG]: Server Cluster:',
'FA7660F6-7B3F-4237-A8BF-ED0AD0DCBBD9':'[MC-IISA]: Internet Information Services (IIS) Application Host COM',
'450386DB-7409-4667-935E-384DBBEE2A9E':'[MC-IISA]: Internet Information Services (IIS) Application Host COM',
'832A32F7-B3EA-4B8C-B260-9A2923001184':'[MC-IISA]: Internet Information Services (IIS) Application Host COM',
'2D9915FB-9D42-4328-B782-1B46819FAB9E':'[MC-IISA]: Internet Information Services (IIS) Application Host COM',
'0DD8A158-EBE6-4008-A1D9-B7ECC8F1104B':'[MC-IISA]: Internet Information Services (IIS) Application Host COM',
'0716CAF8-7D05-4A46-8099-77594BE91394':'[MC-IISA]: Internet Information Services (IIS) Application Host COM',
'B80F3C42-60E0-4AE0-9007-F52852D3DBED':'[MC-IISA]: Internet Information Services (IIS) Application Host COM',
'0344CDDA-151E-4CBF-82DA-66AE61E97754':'[MC-IISA]: Internet Information Services (IIS) Application Host COM',
'8BED2C68-A5FB-4B28-8581-A0DC5267419F':'[MC-IISA]: Internet Information Services (IIS) Application Host COM',
'7883CA1C-1112-4447-84C3-52FBEB38069D':'[MC-IISA]: Internet Information Services (IIS) Application Host COM',
'09829352-87C2-418D-8D79-4133969A489D':'[MC-IISA]: Internet Information Services (IIS) Application Host COM',
'5B5A68E6-8B9F-45E1-8199-A95FFCCDFFFF':'[MC-IISA]: Internet Information Services (IIS) Application Host COM',
'9BE77978-73ED-4A9A-87FD-13F09FEC1B13':'[MC-IISA]: Internet Information Services (IIS) Application Host COM',
'ED35F7A1-5024-4E7B-A44D-07DDAF4B524D':'[MC-IISA]: Internet Information Services (IIS) Application Host COM',
'4DFA1DF3-8900-4BC7-BBB5-D1A458C52410':'[MC-IISA]: Internet Information Services (IIS) Application Host COM',
'370AF178-7758-4DAD-8146-7391F6E18585':'[MC-IISA]: Internet Information Services (IIS) Application Host COM',
'C8550BFF-5281-4B1E-AC34-99B6FA38464D':'[MC-IISA]: Internet Information Services (IIS) Application Host COM',
'08A90F5F-0702-48D6-B45F-02A9885A9768':'[MC-IISA]: Internet Information Services (IIS) Application Host COM',
'8F6D760F-F0CB-4D69-B5F6-848B33E9BDC6':'[MC-IISA]: Internet Information Services (IIS) Application Host COM',
'E7927575-5CC3-403B-822E-328A6B904BEE':'[MC-IISA]: Internet Information Services (IIS) Application Host COM',
'DE095DB1-5368-4D11-81F6-EFEF619B7BCF':'[MC-IISA]: Internet Information Services (IIS) Application Host COM',
'64FF8CCC-B287-4DAE-B08A-A72CBF45F453':'[MC-IISA]: Internet Information Services (IIS) Application Host COM',
'EAFE4895-A929-41EA-B14D-613E23F62B71':'[MC-IISA]: Internet Information Services (IIS) Application Host COM',
'EF13D885-642C-4709-99EC-B89561C6BC69':'[MC-IISA]: Internet Information Services (IIS) Application Host COM',
'0191775E-BCFF-445A-B4F4-3BDDA54E2816':'[MC-IISA]: Internet Information Services (IIS) Application Host COM',
'31A83EA0-C0E4-4A2C-8A01-353CC2A4C60A':'[MC-IISA]: Internet Information Services (IIS) Application Host COM',
'D6C7CD8F-BB8D-4F96-B591-D3A5F1320269':'[MC-IISA]: Internet Information Services (IIS) Application Host COM',
'ADA4E6FB-E025-401E-A5D0-C3134A281F07':'[MC-IISA]: Internet Information Services (IIS) Application Host COM',
'B7D381EE-8860-47A1-8AF4-1F33B2B1F325':'[MC-IISA]: Internet Information Services (IIS) Application Host COM',
'C5C04795-321C-4014-8FD6-D44658799393':'[MC-IISA]: Internet Information Services (IIS) Application Host COM',
'EBA96B22-2168-11D3-898C-00E02C074F6B':'[MC-MQAC]: Message Queuing (MSMQ):',
'12A30900-7300-11D2-B0E6-00E02C074F6B':'[MC-MQAC]: Message Queuing (MSMQ):',
'EBA96B24-2168-11D3-898C-00E02C074F6B':'[MC-MQAC]: Message Queuing (MSMQ):',
'2CE0C5B0-6E67-11D2-B0E6-00E02C074F6B':'[MC-MQAC]: Message Queuing (MSMQ):',
'EBA96B0E-2168-11D3-898C-00E02C074F6B':'[MC-MQAC]: Message Queuing (MSMQ):',
'B196B285-BAB4-101A-B69C-00AA00341D07':'[MC-MQAC]: Message Queuing (MSMQ):',
'39CE96FE-F4C5-4484-A143-4C2D5D324229':'[MC-MQAC]: Message Queuing (MSMQ):',
'D7D6E07F-DCCD-11D0-AA4B-0060970DEBAE':'[MC-MQAC]: Message Queuing (MSMQ):',
'EBA96B1A-2168-11D3-898C-00E02C074F6B':'[MC-MQAC]: Message Queuing (MSMQ):',
'EBA96B18-2168-11D3-898C-00E02C074F6B':'[MC-MQAC]: Message Queuing (MSMQ):',
'EBA96B23-2168-11D3-898C-00E02C074F6B':'[MC-MQAC]: Message Queuing (MSMQ):',
'EBA96B14-2168-11D3-898C-00E02C074F6B':'[MC-MQAC]: Message Queuing (MSMQ):',
'FD174A80-89CF-11D2-B0F2-00E02C074F6B':'[MC-MQAC]: Message Queuing (MSMQ):',
'F72B9031-2F0C-43E8-924E-E6052CDC493F':'[MC-MQAC]: Message Queuing (MSMQ):',
'D7D6E072-DCCD-11D0-AA4B-0060970DEBAE':'[MC-MQAC]: Message Queuing (MSMQ):',
'D7D6E075-DCCD-11D0-AA4B-0060970DEBAE':'[MC-MQAC]: Message Queuing (MSMQ):',
'0188401C-247A-4FED-99C6-BF14119D7055':'[MC-MQAC]: Message Queuing (MSMQ):',
'EBA96B15-2168-11D3-898C-00E02C074F6B':'[MC-MQAC]: Message Queuing (MSMQ):',
'D7D6E07C-DCCD-11D0-AA4B-0060970DEBAE':'[MC-MQAC]: Message Queuing (MSMQ):',
'BE5F0241-E489-4957-8CC4-A452FCF3E23E':'[MC-MQAC]: Message Queuing (MSMQ):',
'EBA96B1C-2168-11D3-898C-00E02C074F6B':'[MC-MQAC]: Message Queuing (MSMQ):',
'D7D6E077-DCCD-11D0-AA4B-0060970DEBAE':'[MC-MQAC]: Message Queuing (MSMQ):',
'D7D6E078-DCCD-11D0-AA4B-0060970DEBAE':'[MC-MQAC]: Message Queuing (MSMQ):',
'B196B284-BAB4-101A-B69C-00AA00341D07':'[MC-MQAC]: Message Queuing (MSMQ):',
'D7D6E073-DCCD-11D0-AA4B-0060970DEBAE':'[MC-MQAC]: Message Queuing (MSMQ):',
'D7D6E07D-DCCD-11D0-AA4B-0060970DEBAE':'[MC-MQAC]: Message Queuing (MSMQ):',
'EBA96B1B-2168-11D3-898C-00E02C074F6B':'[MC-MQAC]: Message Queuing (MSMQ):',
'D7D6E079-DCCD-11D0-AA4B-0060970DEBAE':'[MC-MQAC]: Message Queuing (MSMQ):',
'D7D6E084-DCCD-11D0-AA4B-0060970DEBAE':'[MC-MQAC]: Message Queuing (MSMQ):',
'EBA96B1F-2168-11D3-898C-00E02C074F6B':'[MC-MQAC]: Message Queuing (MSMQ):',
'33B6D07E-F27D-42FA-B2D7-BF82E11E9374':'[MC-MQAC]: Message Queuing (MSMQ):',
'D7D6E07A-DCCD-11D0-AA4B-0060970DEBAE':'[MC-MQAC]: Message Queuing (MSMQ):',
'0188AC2F-ECB3-4173-9779-635CA2039C72':'[MC-MQAC]: Message Queuing (MSMQ):',
'D7D6E085-DCCD-11D0-AA4B-0060970DEBAE':'[MC-MQAC]: Message Queuing (MSMQ):',
'EF0574E0-06D8-11D3-B100-00E02C074F6B':'[MC-MQAC]: Message Queuing (MSMQ):',
'D7D6E086-DCCD-11D0-AA4B-0060970DEBAE':'[MC-MQAC]: Message Queuing (MSMQ):',
'B196B286-BAB4-101A-B69C-00AA00341D07':'[MC-MQAC]: Message Queuing (MSMQ):',
'D9933BE0-A567-11D2-B0F3-00E02C074F6B':'[MC-MQAC]: Message Queuing (MSMQ):',
'D7AB3341-C9D3-11D1-BB47-0080C7C5A2C0':'[MC-MQAC]: Message Queuing (MSMQ):',
'D7D6E082-DCCD-11D0-AA4B-0060970DEBAE':'[MC-MQAC]: Message Queuing (MSMQ):',
'0FB15084-AF41-11CE-BD2B-204C4F4F5020':'[MC-MQAC]: Message Queuing (MSMQ):',
'D7D6E083-DCCD-11D0-AA4B-0060970DEBAE':'[MC-MQAC]: Message Queuing (MSMQ):',
'EBA96B13-2168-11D3-898C-00E02C074F6B':'[MC-MQAC]: Message Queuing (MSMQ):',
'EBA96B1D-2168-11D3-898C-00E02C074F6B':'[MC-MQAC]: Message Queuing (MSMQ):',
'EBA96B17-2168-11D3-898C-00E02C074F6B':'[MC-MQAC]: Message Queuing (MSMQ):',
'EBA96B20-2168-11D3-898C-00E02C074F6B':'[MC-MQAC]: Message Queuing (MSMQ):',
'D7D6E074-DCCD-11D0-AA4B-0060970DEBAE':'[MC-MQAC]: Message Queuing (MSMQ):',
'7FBE7759-5760-444D-B8A5-5E7AB9A84CCE':'[MC-MQAC]: Message Queuing (MSMQ):',
'B196B287-BAB4-101A-B69C-00AA00341D07':'[MC-MQAC]: Message Queuing (MSMQ):',
'EBA96B12-2168-11D3-898C-00E02C074F6B':'[MC-MQAC]: Message Queuing (MSMQ):',
'EBA96B1E-2168-11D3-898C-00E02C074F6B':'[MC-MQAC]: Message Queuing (MSMQ):',
'D7D6E07E-DCCD-11D0-AA4B-0060970DEBAE':'[MC-MQAC]: Message Queuing (MSMQ):',
'D7D6E081-DCCD-11D0-AA4B-0060970DEBAE':'[MC-MQAC]: Message Queuing (MSMQ):',
'D7D6E07B-DCCD-11D0-AA4B-0060970DEBAE':'[MC-MQAC]: Message Queuing (MSMQ):',
'64C478FB-F9B0-4695-8A7F-439AC94326D3':'[MC-MQAC]: Message Queuing (MSMQ):',
'EBA96B16-2168-11D3-898C-00E02C074F6B':'[MC-MQAC]: Message Queuing (MSMQ):',
'EBA96B19-2168-11D3-898C-00E02C074F6B':'[MC-MQAC]: Message Queuing (MSMQ):',
'EBA96B10-2168-11D3-898C-00E02C074F6B':'[MC-MQAC]: Message Queuing (MSMQ):',
'EBA96B21-2168-11D3-898C-00E02C074F6B':'[MC-MQAC]: Message Queuing (MSMQ):',
'D7D6E076-DCCD-11D0-AA4B-0060970DEBAE':'[MC-MQAC]: Message Queuing (MSMQ):',
'EBA96B0F-2168-11D3-898C-00E02C074F6B':'[MC-MQAC]: Message Queuing (MSMQ):',
'EBA96B11-2168-11D3-898C-00E02C074F6B':'[MC-MQAC]: Message Queuing (MSMQ):',
'D7D6E080-DCCD-11D0-AA4B-0060970DEBAE':'[MC-MQAC]: Message Queuing (MSMQ):',
'4639DB2A-BFC5-11D2-9318-00C04FBBBFB3':'[MS-ADTG]: Remote Data Services (RDS) Transport Protocol',
'0EAC4842-8763-11CF-A743-00AA00A3F00D':'[MS-ADTG]: Remote Data Services (RDS) Transport Protocol',
'070669EB-B52F-11D1-9270-00C04FBBBFB3':'[MS-ADTG]: Remote Data Services (RDS) Transport Protocol',
'3DDE7C30-165D-11D1-AB8F-00805F14DB40':'[MS-BKRP]: BackupKey Remote Protocol',
'E3D0D746-D2AF-40FD-8A7A-0D7078BB7092':'[MS-BPAU]: Background Intelligent Transfer Service (BITS) Peer-',
'6BFFD098-A112-3610-9833-012892020162':'[MS-BRWSA]: Common Internet File System (CIFS) Browser Auxiliary',
'AFC07E2E-311C-4435-808C-C483FFEEC7C9':'[MS-CAPR]: Central Access Policy Identifier (ID) Retrieval Protocol',
'B97DB8B2-4C63-11CF-BFF6-08002BE23F2F':'[MS-CMRP]: Failover Cluster:',
'97199110-DB2E-11D1-A251-0000F805CA53':'[MS-COM]: Component Object Model Plus (COM+) Protocol',
'0E3D6630-B46B-11D1-9D2D-006008B0E5CA':'[MS-COMA]: Component Object Model Plus (COM+) Remote',
'3F3B1B86-DBBE-11D1-9DA6-00805F85CFE3':'[MS-COMA]: Component Object Model Plus (COM+) Remote',
'7F43B400-1A0E-4D57-BBC9-6B0C65F7A889':'[MS-COMA]: Component Object Model Plus (COM+) Remote',
'456129E2-1078-11D2-B0F9-00805FC73204':'[MS-COMA]: Component Object Model Plus (COM+) Remote',
'8DB2180E-BD29-11D1-8B7E-00C04FD7A924':'[MS-COMA]: Component Object Model Plus (COM+) Remote',
'182C40FA-32E4-11D0-818B-00A0C9231C29':'[MS-COMA]: Component Object Model Plus (COM+) Remote',
'971668DC-C3FE-4EA1-9643-0C7230F494A1':'[MS-COMA]: Component Object Model Plus (COM+) Remote',
'98315903-7BE5-11D2-ADC1-00A02463D6E7':'[MS-COMA]: Component Object Model Plus (COM+) Remote',
'6C935649-30A6-4211-8687-C4C83E5FE1C7':'[MS-COMA]: Component Object Model Plus (COM+) Remote',
'F131EA3E-B7BE-480E-A60D-51CB2785779E':'[MS-COMA]: Component Object Model Plus (COM+) Remote',
'1F7B1697-ECB2-4CBB-8A0E-75C427F4A6F0':'[MS-COMA]: Component Object Model Plus (COM+) Remote',
'A8927A41-D3CE-11D1-8472-006008B0E5CA':'[MS-COMA]: Component Object Model Plus (COM+) Remote',
'CFADAC84-E12C-11D1-B34C-00C04F990D54':'[MS-COMA]: Component Object Model Plus (COM+) Remote',
'1D118904-94B3-4A64-9FA6-ED432666A7B9':'[MS-COMA]: Component Object Model Plus (COM+) Remote',
'47CDE9A1-0BF6-11D2-8016-00C04FB9988E':'[MS-COMA]: Component Object Model Plus (COM+) Remote',
'0E3D6631-B46B-11D1-9D2D-006008B0E5CA':'[MS-COMA]: Component Object Model Plus (COM+) Remote',
'C2BE6970-DF9E-11D1-8B87-00C04FD7A924':'[MS-COMA]: Component Object Model Plus (COM+) Remote',
'C726744E-5735-4F08-8286-C510EE638FB6':'[MS-COMA]: Component Object Model Plus (COM+) Remote',
'FBC1D17D-C498-43A0-81AF-423DDD530AF6':'[MS-COMEV]: Component Object Model Plus (COM+) Event System',
'F89AC270-D4EB-11D1-B682-00805FC79216':'[MS-COMEV]: Component Object Model Plus (COM+) Event System',
'FB2B72A1-7A68-11D1-88F9-0080C7D771BF':'[MS-COMEV]: Component Object Model Plus (COM+) Event System',
'4E14FB9F-2E22-11D1-9964-00C04FBBB345':'[MS-COMEV]: Component Object Model Plus (COM+) Event System',
'A0E8F27A-888C-11D1-B763-00C04FB926AF':'[MS-COMEV]: Component Object Model Plus (COM+) Event System',
'7FB7EA43-2D76-4EA8-8CD9-3DECC270295E':'[MS-COMEV]: Component Object Model Plus (COM+) Event System',
'99CC098F-A48A-4E9C-8E58-965C0AFC19D5':'[MS-COMEV]: Component Object Model Plus (COM+) Event System',
'FB2B72A0-7A68-11D1-88F9-0080C7D771BF':'[MS-COMEV]: Component Object Model Plus (COM+) Event System',
'4A6B0E16-2E38-11D1-9965-00C04FBBB345':'[MS-COMEV]: Component Object Model Plus (COM+) Event System',
'F4A07D63-2E25-11D1-9964-00C04FBBB345':'[MS-COMEV]: Component Object Model Plus (COM+) Event System',
'4A6B0E15-2E38-11D1-9965-00C04FBBB345':'[MS-COMEV]: Component Object Model Plus (COM+) Event System',
'B60040E0-BCF3-11D1-861D-0080C729264D':'[MS-COMT]: Component Object Model Plus (COM+) Tracker Service',
'23C9DD26-2355-4FE2-84DE-F779A238ADBD':'[MS-COMT]: Component Object Model Plus (COM+) Tracker Service',
'4E6CDCC9-FB25-4FD5-9CC5-C9F4B6559CEC':'[MS-COMT]: Component Object Model Plus (COM+) Tracker Service',
'D99E6E71-FC88-11D0-B498-00A0C90312F3':'[MS-CSRA]: Certificate Services Remote Administration Protocol',
'7FE0D935-DDA6-443F-85D0-1CFB58FE41DD':'[MS-CSRA]: Certificate Services Remote Administration Protocol',
'E1568352-586D-43E4-933F-8E6DC4DE317A':'[MS-CSVP]: Failover Cluster:',
'11942D87-A1DE-4E7F-83FB-A840D9C5928D':'[MS-CSVP]: Failover Cluster:',
'491260B5-05C9-40D9-B7F2-1F7BDAE0927F':'[MS-CSVP]: Failover Cluster:',
'C72B09DB-4D53-4F41-8DCC-2D752AB56F7C':'[MS-CSVP]: Failover Cluster:',
'E3C9B851-C442-432B-8FC6-A7FAAFC09D3B':'[MS-CSVP]: Failover Cluster:',
'4142DD5D-3472-4370-8641-DE7856431FB0':'[MS-CSVP]: Failover Cluster:',
'D6105110-8917-41A5-AA32-8E0AA2933DC9':'[MS-CSVP]: Failover Cluster:',
'A6D3E32B-9814-4409-8DE3-CFA673E6D3DE':'[MS-CSVP]: Failover Cluster:',
'04D55210-B6AC-4248-9E69-2A569D1D2AB6':'[MS-CSVP]: Failover Cluster:',
'2931C32C-F731-4C56-9FEB-3D5F1C5E72BF':'[MS-CSVP]: Failover Cluster:',
'12108A88-6858-4467-B92F-E6CF4568DFB6':'[MS-CSVP]: Failover Cluster:',
'85923CA7-1B6B-4E83-A2E4-F5BA3BFBB8A3':'[MS-CSVP]: Failover Cluster:',
'F1D6C29C-8FBE-4691-8724-F6D8DEAEAFC8':'[MS-CSVP]: Failover Cluster:',
'3CFEE98C-FB4B-44C6-BD98-A1DB14ABCA3F':'[MS-CSVP]: Failover Cluster:',
'88E7AC6D-C561-4F03-9A60-39DD768F867D':'[MS-CSVP]: Failover Cluster:',
'00000131-0000-0000-C000-000000000046':'[MS-DCOM]: Distributed Component Object Model (DCOM) Remote',
'4D9F4AB8-7D1C-11CF-861E-0020AF6E7C57':'[MS-DCOM]: Distributed Component Object Model (DCOM) Remote',
'00000143-0000-0000-C000-000000000046':'[MS-DCOM]: Distributed Component Object Model (DCOM) Remote',
'000001A0-0000-0000-C000-000000000046':'[MS-DCOM]: Distributed Component Object Model (DCOM) Remote',
'99FCFEC4-5260-101B-BBCB-00AA0021347A':'[MS-DCOM]: Distributed Component Object Model (DCOM) Remote',
'00000000-0000-0000-C000-000000000046':'[MS-DCOM]: Distributed Component Object Model (DCOM) Remote',
'4FC742E0-4A10-11CF-8273-00AA004AE673':'[MS-DFSNM]: Distributed File System (DFS):',
'9009D654-250B-4E0D-9AB0-ACB63134F69F':'[MS-DFSRH]: DFS Replication Helper Protocol',
'E65E8028-83E8-491B-9AF7-AAF6BD51A0CE':'[MS-DFSRH]: DFS Replication Helper Protocol',
'D3766938-9FB7-4392-AF2F-2CE8749DBBD0':'[MS-DFSRH]: DFS Replication Helper Protocol',
'4BB8AB1D-9EF9-4100-8EB6-DD4B4E418B72':'[MS-DFSRH]: DFS Replication Helper Protocol',
'CEB5D7B4-3964-4F71-AC17-4BF57A379D87':'[MS-DFSRH]: DFS Replication Helper Protocol',
'7A2323C7-9EBE-494A-A33C-3CC329A18E1D':'[MS-DFSRH]: DFS Replication Helper Protocol',
'20D15747-6C48-4254-A358-65039FD8C63C':'[MS-DFSRH]: DFS Replication Helper Protocol',
'C4B0C7D9-ABE0-4733-A1E1-9FDEDF260C7A':'[MS-DFSRH]: DFS Replication Helper Protocol',
'6BFFD098-A112-3610-9833-46C3F874532D':'[MS-DHCPM]: Microsoft Dynamic Host Configuration Protocol (DHCP)',
'5B821720-F63B-11D0-AAD2-00C04FC324DB':'[MS-DHCPM]: Microsoft Dynamic Host Configuration Protocol (DHCP)',
'4DA1C422-943D-11D1-ACAE-00C04FC2AA3F':'[MS-DLTM]: Distributed Link Tracking:',
'300F3532-38CC-11D0-A3F0-0020AF6B0ADD':'[MS-DLTW]: Distributed Link Tracking:',
'D2D79DF5-3400-11D0-B40B-00AA005FF586':'[MS-DMRP]: Disk Management Remote Protocol',
'DEB01010-3A37-4D26-99DF-E2BB6AE3AC61':'[MS-DMRP]: Disk Management Remote Protocol',
'3A410F21-553F-11D1-8E5E-00A0C92C9D5D':'[MS-DMRP]: Disk Management Remote Protocol',
'D2D79DF7-3400-11D0-B40B-00AA005FF586':'[MS-DMRP]: Disk Management Remote Protocol',
'4BDAFC52-FE6A-11D2-93F8-00105A11164A':'[MS-DMRP]: Disk Management Remote Protocol',
'135698D2-3A37-4D26-99DF-E2BB6AE3AC61':'[MS-DMRP]: Disk Management Remote Protocol',
'50ABC2A4-574D-40B3-9D66-EE4FD5FBA076':'[MS-DNSP]: Domain Name Service (DNS) Server Management',
'7C44D7D4-31D5-424C-BD5E-2B3E1F323D22':'[MS-DRSR]: Directory Replication Service (DRS) Remote Protocol',
'3919286A-B10C-11D0-9BA8-00C04FD92EF5':'[MS-DSSP]: Directory Services Setup Remote Protocol',
'14A8831C-BC82-11D2-8A64-0008C7457E5D':'[MS-EERR]: ExtendedError Remote Data Structure',
'C681D488-D850-11D0-8C52-00C04FD90F7E':'[MS-EFSR]: Encrypting File System Remote (EFSRPC) Protocol',
'82273FDC-E32A-18C3-3F78-827929DC23EA':'[MS-EVEN]: EventLog Remoting Protocol',
'6B5BDD1E-528C-422C-AF8C-A4079BE4FE48':'[MS-FASP]: Firewall and Advanced Security Protocol',
'6099FC12-3EFF-11D0-ABD0-00C04FD91A4E':'[MS-FAX]: Fax Server and Client Remote Protocol',
'EA0A3165-4834-11D2-A6F8-00C04FA346CC':'[MS-FAX]: Fax Server and Client Remote Protocol',
'897E2E5F-93F3-4376-9C9C-FD2277495C27':'[MS-FRS2]: Distributed File System Replication Protocol',
'377F739D-9647-4B8E-97D2-5FFCE6D759CD':'[MS-FSRM]: File Server Resource Manager Protocol',
'F411D4FD-14BE-4260-8C40-03B7C95E608A':'[MS-FSRM]: File Server Resource Manager Protocol',
'4C8F96C3-5D94-4F37-A4F4-F56AB463546F':'[MS-FSRM]: File Server Resource Manager Protocol',
'CFE36CBA-1949-4E74-A14F-F1D580CEAF13':'[MS-FSRM]: File Server Resource Manager Protocol',
'8276702F-2532-4839-89BF-4872609A2EA4':'[MS-FSRM]: File Server Resource Manager Protocol',
'4A73FEE4-4102-4FCC-9FFB-38614F9EE768':'[MS-FSRM]: File Server Resource Manager Protocol',
'F3637E80-5B22-4A2B-A637-BBB642B41CFC':'[MS-FSRM]: File Server Resource Manager Protocol',
'1568A795-3924-4118-B74B-68D8F0FA5DAF':'[MS-FSRM]: File Server Resource Manager Protocol',
'6F4DBFFF-6920-4821-A6C3-B7E94C1FD60C':'[MS-FSRM]: File Server Resource Manager Protocol',
'39322A2D-38EE-4D0D-8095-421A80849A82':'[MS-FSRM]: File Server Resource Manager Protocol',
'326AF66F-2AC0-4F68-BF8C-4759F054FA29':'[MS-FSRM]: File Server Resource Manager Protocol',
'27B899FE-6FFA-4481-A184-D3DAADE8A02B':'[MS-FSRM]: File Server Resource Manager Protocol',
'E1010359-3E5D-4ECD-9FE4-EF48622FDF30':'[MS-FSRM]: File Server Resource Manager Protocol',
'8DD04909-0E34-4D55-AFAA-89E1F1A1BBB9':'[MS-FSRM]: File Server Resource Manager Protocol',
'96DEB3B5-8B91-4A2A-9D93-80A35D8AA847':'[MS-FSRM]: File Server Resource Manager Protocol',
'D8CC81D9-46B8-4FA4-BFA5-4AA9DEC9B638':'[MS-FSRM]: File Server Resource Manager Protocol',
'EDE0150F-E9A3-419C-877C-01FE5D24C5D3':'[MS-FSRM]: File Server Resource Manager Protocol',
'15A81350-497D-4ABA-80E9-D4DBCC5521FE':'[MS-FSRM]: File Server Resource Manager Protocol',
'12937789-E247-4917-9C20-F3EE9C7EE783':'[MS-FSRM]: File Server Resource Manager Protocol',
'F76FBF3B-8DDD-4B42-B05A-CB1C3FF1FEE8':'[MS-FSRM]: File Server Resource Manager Protocol',
'CB0DF960-16F5-4495-9079-3F9360D831DF':'[MS-FSRM]: File Server Resource Manager Protocol',
'4846CB01-D430-494F-ABB4-B1054999FB09':'[MS-FSRM]: File Server Resource Manager Protocol',
'6CD6408A-AE60-463B-9EF1-E117534D69DC':'[MS-FSRM]: File Server Resource Manager Protocol',
'EE321ECB-D95E-48E9-907C-C7685A013235':'[MS-FSRM]: File Server Resource Manager Protocol',
'38E87280-715C-4C7D-A280-EA1651A19FEF':'[MS-FSRM]: File Server Resource Manager Protocol',
'BEE7CE02-DF77-4515-9389-78F01C5AFC1A':'[MS-FSRM]: File Server Resource Manager Protocol',
'9A2BF113-A329-44CC-809A-5C00FCE8DA40':'[MS-FSRM]: File Server Resource Manager Protocol',
'4173AC41-172D-4D52-963C-FDC7E415F717':'[MS-FSRM]: File Server Resource Manager Protocol',
'AD55F10B-5F11-4BE7-94EF-D9EE2E470DED':'[MS-FSRM]: File Server Resource Manager Protocol',
'BB36EA26-6318-4B8C-8592-F72DD602E7A5':'[MS-FSRM]: File Server Resource Manager Protocol',
'FF4FA04E-5A94-4BDA-A3A0-D5B4D3C52EBA':'[MS-FSRM]: File Server Resource Manager Protocol',
'22BCEF93-4A3F-4183-89F9-2F8B8A628AEE':'[MS-FSRM]: File Server Resource Manager Protocol',
'6879CAF9-6617-4484-8719-71C3D8645F94':'[MS-FSRM]: File Server Resource Manager Protocol',
'5F6325D3-CE88-4733-84C1-2D6AEFC5EA07':'[MS-FSRM]: File Server Resource Manager Protocol',
'8BB68C7D-19D8-4FFB-809E-BE4FC1734014':'[MS-FSRM]: File Server Resource Manager Protocol',
'A2EFAB31-295E-46BB-B976-E86D58B52E8B':'[MS-FSRM]: File Server Resource Manager Protocol',
'0770687E-9F36-4D6F-8778-599D188461C9':'[MS-FSRM]: File Server Resource Manager Protocol',
'AFC052C2-5315-45AB-841B-C6DB0E120148':'[MS-FSRM]: File Server Resource Manager Protocol',
'515C1277-2C81-440E-8FCF-367921ED4F59':'[MS-FSRM]: File Server Resource Manager Protocol',
'D2DC89DA-EE91-48A0-85D8-CC72A56F7D04':'[MS-FSRM]: File Server Resource Manager Protocol',
'47782152-D16C-4229-B4E1-0DDFE308B9F6':'[MS-FSRM]: File Server Resource Manager Protocol',
'205BEBF8-DD93-452A-95A6-32B566B35828':'[MS-FSRM]: File Server Resource Manager Protocol',
'1BB617B8-3886-49DC-AF82-A6C90FA35DDA':'[MS-FSRM]: File Server Resource Manager Protocol',
'42DC3511-61D5-48AE-B6DC-59FC00C0A8D6':'[MS-FSRM]: File Server Resource Manager Protocol',
'426677D5-018C-485C-8A51-20B86D00BDC4':'[MS-FSRM]: File Server Resource Manager Protocol',
'E946D148-BD67-4178-8E22-1C44925ED710':'[MS-FSRM]: File Server Resource Manager Protocol',
'D646567D-26AE-4CAA-9F84-4E0AAD207FCA':'[MS-FSRM]: File Server Resource Manager Protocol',
'F82E5729-6ABA-4740-BFC7-C7F58F75FB7B':'[MS-FSRM]: File Server Resource Manager Protocol',
'2DBE63C4-B340-48A0-A5B0-158E07FC567E':'[MS-FSRM]: File Server Resource Manager Protocol',
'A8E0653C-2744-4389-A61D-7373DF8B2292':'[MS-FSRVP]: File Server Remote VSS Protocol',
'B9785960-524F-11DF-8B6D-83DCDED72085':'[MS-GKDI]: Group Key Distribution Protocol',
'91AE6020-9E3C-11CF-8D7C-00AA00C091BE':'[MS-ICPR]: ICertPassage Remote Protocol',
'E8FB8620-588F-11D2-9D61-00C04F79C5FE':'[MS-IISS]: Internet Information Services (IIS) ServiceControl',
'F612954D-3B0B-4C56-9563-227B7BE624B4':'[MS-IMSA]: Internet Information Services (IIS) IMSAdminBaseW',
'8298D101-F992-43B7-8ECA-5052D885B995':'[MS-IMSA]: Internet Information Services (IIS) IMSAdminBaseW',
'29822AB8-F302-11D0-9953-00C04FD919C1':'[MS-IMSA]: Internet Information Services (IIS) IMSAdminBaseW',
'70B51430-B6CA-11D0-B9B9-00A0C922E750':'[MS-IMSA]: Internet Information Services (IIS) IMSAdminBaseW',
'29822AB7-F302-11D0-9953-00C04FD919C1':'[MS-IMSA]: Internet Information Services (IIS) IMSAdminBaseW',
'BD0C73BC-805B-4043-9C30-9A28D64DD7D2':'[MS-IMSA]: Internet Information Services (IIS) IMSAdminBaseW',
'7C4E1804-E342-483D-A43E-A850CFCC8D18':'[MS-IMSA]: Internet Information Services (IIS) IMSAdminBaseW',
'6619A740-8154-43BE-A186-0319578E02DB':'[MS-IOI]: IManagedObject Interface Protocol',
'8165B19E-8D3A-4D0B-80C8-97DE310DB583':'[MS-IOI]: IManagedObject Interface Protocol',
'C3FCC19E-A970-11D2-8B5A-00A0C9B7C9C4':'[MS-IOI]: IManagedObject Interface Protocol',
'82AD4280-036B-11CF-972C-00AA006887B0':'[MS-IRP]: Internet Information Services (IIS) Inetinfo Remote',
'4E65A71E-4EDE-4886-BE67-3C90A08D1F29':'[MS-ISTM]: iSCSI Software Target Management Protocol',
'866A78BC-A2FB-4AC4-94D5-DB3041B4ED75':'[MS-ISTM]: iSCSI Software Target Management Protocol',
'B0D1AC4B-F87A-49B2-938F-D439248575B2':'[MS-ISTM]: iSCSI Software Target Management Protocol',
'E141FD54-B79E-4938-A6BB-D523C3D49FF1':'[MS-ISTM]: iSCSI Software Target Management Protocol',
'40CC8569-6D23-4005-9958-E37F08AE192B':'[MS-ISTM]: iSCSI Software Target Management Protocol',
'1822A95E-1C2B-4D02-AB25-CC116DD9DBDE':'[MS-ISTM]: iSCSI Software Target Management Protocol',
'B4FA8E86-2517-4A88-BD67-75447219EEE4':'[MS-ISTM]: iSCSI Software Target Management Protocol',
'3C73848A-A679-40C5-B101-C963E67F9949':'[MS-ISTM]: iSCSI Software Target Management Protocol',
'66C9B082-7794-4948-839A-D8A5A616378F':'[MS-ISTM]: iSCSI Software Target Management Protocol',
'01454B97-C6A5-4685-BEA8-9779C88AB990':'[MS-ISTM]: iSCSI Software Target Management Protocol',
'D6BD6D63-E8CB-4905-AB34-8A278C93197A':'[MS-ISTM]: iSCSI Software Target Management Protocol',
'348A0821-69BB-4889-A101-6A9BDE6FA720':'[MS-ISTM]: iSCSI Software Target Management Protocol',
'703E6B03-7AD1-4DED-BA0D-E90496EBC5DE':'[MS-ISTM]: iSCSI Software Target Management Protocol',
'100DA538-3F4A-45AB-B852-709148152789':'[MS-ISTM]: iSCSI Software Target Management Protocol',
'592381E5-8D3C-42E9-B7DE-4E77A1F75AE4':'[MS-ISTM]: iSCSI Software Target Management Protocol',
'883343F1-CEED-4E3A-8C1B-F0DADFCE281E':'[MS-ISTM]: iSCSI Software Target Management Protocol',
'6AEA6B26-0680-411D-8877-A148DF3087D5':'[MS-ISTM]: iSCSI Software Target Management Protocol',
'D71B2CAE-33E8-4567-AE96-3CCF31620BE2':'[MS-ISTM]: iSCSI Software Target Management Protocol',
'8C58F6B3-4736-432A-891D-389DE3505C7C':'[MS-ISTM]: iSCSI Software Target Management Protocol',
'1995785D-2A1E-492F-8923-E621EACA39D9':'[MS-ISTM]: iSCSI Software Target Management Protocol',
'C10A76D8-1FE4-4C2F-B70D-665265215259':'[MS-ISTM]: iSCSI Software Target Management Protocol',
'8D7AE740-B9C5-49FC-A11E-89171907CB86':'[MS-ISTM]: iSCSI Software Target Management Protocol',
'8AD608A4-6C16-4405-8879-B27910A68995':'[MS-ISTM]: iSCSI Software Target Management Protocol',
'B0076FEC-A921-4034-A8BA-090BC6D03BDE':'[MS-ISTM]: iSCSI Software Target Management Protocol',
'640038F1-D626-40D8-B52B-09660601D045':'[MS-ISTM]: iSCSI Software Target Management Protocol',
'BB39E296-AD26-42C5-9890-5325333BB11E':'[MS-ISTM]: iSCSI Software Target Management Protocol',
'B06A64E3-814E-4FF9-AFAC-597AD32517C7':'[MS-ISTM]: iSCSI Software Target Management Protocol',
'A5ECFC73-0013-4A9E-951C-59BF9735FDDA':'[MS-ISTM]: iSCSI Software Target Management Protocol',
'1396DE6F-A794-4B11-B93F-6B69A5B47BAE':'[MS-ISTM]: iSCSI Software Target Management Protocol',
'DD6F0A28-248F-4DD3-AFE9-71AED8F685C4':'[MS-ISTM]: iSCSI Software Target Management Protocol',
'52BA97E7-9364-4134-B9CB-F8415213BDD8':'[MS-ISTM]: iSCSI Software Target Management Protocol',
'E2842C88-07C3-4EB0-B1A9-D3D95E76FEF2':'[MS-ISTM]: iSCSI Software Target Management Protocol',
'312CC019-D5CD-4CA7-8C10-9E0A661F147E':'[MS-ISTM]: iSCSI Software Target Management Protocol',
'345B026B-5802-4E38-AC75-795E08B0B83F':'[MS-ISTM]: iSCSI Software Target Management Protocol',
'442931D5-E522-4E64-A181-74E98A4E1748':'[MS-ISTM]: iSCSI Software Target Management Protocol',
'1B1C4D1C-ABC4-4D3A-8C22-547FBA3AA8A0':'[MS-ISTM]: iSCSI Software Target Management Protocol',
'56E65EA5-CDFF-4391-BA76-006E42C2D746':'[MS-ISTM]: iSCSI Software Target Management Protocol',
'E645744B-CAE5-4712-ACAF-13057F7195AF':'[MS-ISTM]: iSCSI Software Target Management Protocol',
'FE7F99F9-1DFB-4AFB-9D00-6A8DD0AABF2C':'[MS-ISTM]: iSCSI Software Target Management Protocol',
'81FE3594-2495-4C91-95BB-EB5785614EC7':'[MS-ISTM]: iSCSI Software Target Management Protocol',
'F093FE3D-8131-4B73-A742-EF54C20B337B':'[MS-ISTM]: iSCSI Software Target Management Protocol',
'28BC8D5E-CA4B-4F54-973C-ED9622D2B3AC':'[MS-ISTM]: iSCSI Software Target Management Protocol',
'12345778-1234-ABCD-EF00-0123456789AB':'[MS-LSAD]: Local Security Authority (Domain Policy) Remote Protocol',
'12345778-1234-ABCD-EF00-0123456789AB':'[MS-LSAT]: Local Security Authority (Translation Methods) Remote',
'708CCA10-9569-11D1-B2A5-0060977D8118':'[MS-MQDS]: Message Queuing (MSMQ):',
'77DF7A80-F298-11D0-8358-00A024C480A8':'[MS-MQDS]: Message Queuing (MSMQ):',
'76D12B80-3467-11D3-91FF-0090272F9EA3':'[MS-MQMP]: Message Queuing (MSMQ):',
'FDB3A030-065F-11D1-BB9B-00A024EA5525':'[MS-MQMP]: Message Queuing (MSMQ):',
'41208EE0-E970-11D1-9B9E-00E02C064C39':'[MS-MQMR]: Message Queuing (MSMQ):',
'1088A980-EAE5-11D0-8D9B-00A02453C337':'[MS-MQQP]: Message Queuing (MSMQ):',
'1A9134DD-7B39-45BA-AD88-44D01CA47F28':'[MS-MQRR]: Message Queuing (MSMQ):',
'17FDD703-1827-4E34-79D4-24A55C53BB37':'[MS-MSRP]: Messenger Service Remote Protocol',
'12345678-1234-ABCD-EF00-01234567CFFB':'[MS-NRPC]: Netlogon Remote Protocol',
'00020411-0000-0000-C000-000000000046':'[MS-OAUT]: OLE Automation Protocol',
'00020401-0000-0000-C000-000000000046':'[MS-OAUT]: OLE Automation Protocol',
'00020403-0000-0000-C000-000000000046':'[MS-OAUT]: OLE Automation Protocol',
'00020412-0000-0000-C000-000000000046':'[MS-OAUT]: OLE Automation Protocol',
'00020402-0000-0000-C000-000000000046':'[MS-OAUT]: OLE Automation Protocol',
'00020400-0000-0000-C000-000000000046':'[MS-OAUT]: OLE Automation Protocol',
'00020404-0000-0000-C000-000000000046':'[MS-OAUT]: OLE Automation Protocol',
'784B693D-95F3-420B-8126-365C098659F2':'[MS-OCSPA]: Microsoft OCSP Administration Protocol',
'AE33069B-A2A8-46EE-A235-DDFD339BE281':'[MS-PAN]: Print System Asynchronous Notification Protocol',
'0B6EDBFA-4A24-4FC6-8A23-942B1ECA65D1':'[MS-PAN]: Print System Asynchronous Notification Protocol',
'76F03F96-CDFD-44FC-A22C-64950A001209':'[MS-PAR]: Print System Asynchronous Remote Protocol',
'DA5A86C5-12C2-4943-AB30-7F74A813D853':'[MS-PCQ]: Performance Counter Query Protocol',
'03837510-098B-11D8-9414-505054503030':'[MS-PLA]: Performance Logs and Alerts Protocol',
'03837543-098B-11D8-9414-505054503030':'[MS-PLA]: Performance Logs and Alerts Protocol',
'03837533-098B-11D8-9414-505054503030':'[MS-PLA]: Performance Logs and Alerts Protocol',
'03837541-098B-11D8-9414-505054503030':'[MS-PLA]: Performance Logs and Alerts Protocol',
'03837544-098B-11D8-9414-505054503030':'[MS-PLA]: Performance Logs and Alerts Protocol',
'03837524-098B-11D8-9414-505054503030':'[MS-PLA]: Performance Logs and Alerts Protocol',
'0383753A-098B-11D8-9414-505054503030':'[MS-PLA]: Performance Logs and Alerts Protocol',
'03837534-098B-11D8-9414-505054503030':'[MS-PLA]: Performance Logs and Alerts Protocol',
'0383750B-098B-11D8-9414-505054503030':'[MS-PLA]: Performance Logs and Alerts Protocol',
'0383751A-098B-11D8-9414-505054503030':'[MS-PLA]: Performance Logs and Alerts Protocol',
'03837512-098B-11D8-9414-505054503030':'[MS-PLA]: Performance Logs and Alerts Protocol',
'0383753D-098B-11D8-9414-505054503030':'[MS-PLA]: Performance Logs and Alerts Protocol',
'03837506-098B-11D8-9414-505054503030':'[MS-PLA]: Performance Logs and Alerts Protocol',
'03837520-098B-11D8-9414-505054503030':'[MS-PLA]: Performance Logs and Alerts Protocol',
'038374FF-098B-11D8-9414-505054503030':'[MS-PLA]: Performance Logs and Alerts Protocol',
'03837514-098B-11D8-9414-505054503030':'[MS-PLA]: Performance Logs and Alerts Protocol',
'03837502-098B-11D8-9414-505054503030':'[MS-PLA]: Performance Logs and Alerts Protocol',
'03837516-098B-11D8-9414-505054503030':'[MS-PLA]: Performance Logs and Alerts Protocol',
'0B1C2170-5732-4E0E-8CD3-D9B16F3B84D7':'[MS-RAA]: Remote Authorization API Protocol',
'F120A684-B926-447F-9DF4-C966CB785648':'[MS-RAI]: Remote Assistance Initiation Protocol',
'833E4010-AFF7-4AC3-AAC2-9F24C1457BCE':'[MS-RAI]: Remote Assistance Initiation Protocol',
'833E4200-AFF7-4AC3-AAC2-9F24C1457BCE':'[MS-RAI]: Remote Assistance Initiation Protocol',
'3C3A70A7-A468-49B9-8ADA-28E11FCCAD5D':'[MS-RAI]: Remote Assistance Initiation Protocol',
'833E4100-AFF7-4AC3-AAC2-9F24C1457BCE':'[MS-RAI]: Remote Assistance Initiation Protocol',
'833E41AA-AFF7-4AC3-AAC2-9F24C1457BCE':'[MS-RAI]: Remote Assistance Initiation Protocol',
'C323BE28-E546-4C23-A81B-D6AD8D8FAC7B':'[MS-RAINPS]: Remote Administrative Interface:',
'83E05BD5-AEC1-4E58-AE50-E819C7296F67':'[MS-RAINPS]: Remote Administrative Interface:',
'45F52C28-7F9F-101A-B52B-08002B2EFABE':'[MS-RAIW]: Remote Administrative Interface:',
'811109BF-A4E1-11D1-AB54-00A0C91E9B45':'[MS-RAIW]: Remote Administrative Interface:',
'A35AF600-9CF4-11CD-A076-08002B2BD711':'[MS-RDPESC]: Remote Desktop Protocol:',
'12345678-1234-ABCD-EF00-0123456789AB':'[MS-RPRN]: Print System Remote Protocol',
'20610036-FA22-11CF-9823-00A0C911E5DF':'[MS-RRASM]: Routing and Remote Access Server (RRAS) Management',
'8F09F000-B7ED-11CE-BBD2-00001A181CAD':'[MS-RRASM]: Routing and Remote Access Server (RRAS) Management',
'338CD001-2244-31F1-AAAA-900038001003':'[MS-RRP]: Windows Remote Registry Protocol',
'3BBED8D9-2C9A-4B21-8936-ACB2F995BE6C':'[MS-RSMP]: Removable Storage Manager (RSM) Remote Protocol',
'8DA03F40-3419-11D1-8FB1-00A024CB6019':'[MS-RSMP]: Removable Storage Manager (RSM) Remote Protocol',
'D61A27C6-8F53-11D0-BFA0-00A024151983':'[MS-RSMP]: Removable Storage Manager (RSM) Remote Protocol',
'081E7188-C080-4FF3-9238-29F66D6CABFD':'[MS-RSMP]: Removable Storage Manager (RSM) Remote Protocol',
'895A2C86-270D-489D-A6C0-DC2A9B35280E':'[MS-RSMP]: Removable Storage Manager (RSM) Remote Protocol',
'D02E4BE0-3419-11D1-8FB1-00A024CB6019':'[MS-RSMP]: Removable Storage Manager (RSM) Remote Protocol',
'DB90832F-6910-4D46-9F5E-9FD6BFA73903':'[MS-RSMP]: Removable Storage Manager (RSM) Remote Protocol',
'4E934F30-341A-11D1-8FB1-00A024CB6019':'[MS-RSMP]: Removable Storage Manager (RSM) Remote Protocol',
'879C8BBE-41B0-11D1-BE11-00C04FB6BF70':'[MS-RSMP]: Removable Storage Manager (RSM) Remote Protocol',
'00000000-0000-0000-C000-000000000046':'[MS-RSMP]: Removable Storage Manager (RSM) Remote Protocol',
'69AB7050-3059-11D1-8FAF-00A024CB6019':'[MS-RSMP]: Removable Storage Manager (RSM) Remote Protocol',
'7D07F313-A53F-459A-BB12-012C15B1846E':'[MS-RSMP]: Removable Storage Manager (RSM) Remote Protocol',
'BB39332C-BFEE-4380-AD8A-BADC8AFF5BB6':'[MS-RSMP]: Removable Storage Manager (RSM) Remote Protocol',
'B057DC50-3059-11D1-8FAF-00A024CB6019':'[MS-RSMP]: Removable Storage Manager (RSM) Remote Protocol',
'338CD001-2244-31F1-AAAA-900038001003':'[MS-RSP]: Remote Shutdown Protocol',
'894DE0C0-0D55-11D3-A322-00C04FA321A1':'[MS-RSP]: Remote Shutdown Protocol',
'D95AFE70-A6D5-4259-822E-2C84DA1DDB0D':'[MS-RSP]: Remote Shutdown Protocol',
'12345778-1234-ABCD-EF00-0123456789AC':'[MS-SAMR]: Security Account Manager (SAM) Remote Protocol',
'01954E6B-9254-4E6E-808C-C9E05D007696':'[MS-SCMP]: Shadow Copy Management Protocol',
'FA7DF749-66E7-4986-A27F-E2F04AE53772':'[MS-SCMP]: Shadow Copy Management Protocol',
'214A0F28-B737-4026-B847-4F9E37D79529':'[MS-SCMP]: Shadow Copy Management Protocol',
'AE1C7110-2F60-11D3-8A39-00C04F72D8E3':'[MS-SCMP]: Shadow Copy Management Protocol',
'367ABB81-9844-35F1-AD32-98F038001003':'[MS-SCMR]: Service Control Manager Remote Protocol',
'4B324FC8-1670-01D3-1278-5A47BF6EE188':'[MS-SRVS]: Server Service Remote Protocol',
'CCD8C074-D0E5-4A40-92B4-D074FAA6BA28':'[MS-SWN]: Service Witness Protocol',
'00000000-0000-0000-C000-000000000046':'[MS-TPMVSC]: Trusted Platform Module (TPM) Virtual Smart Card',
'112B1DFF-D9DC-41F7-869F-D67FEE7CB591':'[MS-TPMVSC]: Trusted Platform Module (TPM) Virtual Smart Card',
'1A1BB35F-ABB8-451C-A1AE-33D98F1BEF4A':'[MS-TPMVSC]: Trusted Platform Module (TPM) Virtual Smart Card',
'2F5F6521-CA47-1068-B319-00DD010662DB':'[MS-TRP]: Telephony Remote Protocol',
'2F5F6520-CA46-1067-B319-00DD010662DA':'[MS-TRP]: Telephony Remote Protocol',
'1FF70682-0A51-30E8-076D-740BE8CEE98B':'[MS-TSCH]: Task Scheduler Service Remoting Protocol',
'378E52B0-C0A9-11CF-822D-00AA0051E40F':'[MS-TSCH]: Task Scheduler Service Remoting Protocol',
'86D35949-83C9-4044-B424-DB363231FD0C':'[MS-TSCH]: Task Scheduler Service Remoting Protocol',
'44E265DD-7DAF-42CD-8560-3CDB6E7A2729':'[MS-TSGU]: Terminal Services Gateway Server Protocol',
'034634FD-BA3F-11D1-856A-00A0C944138C':'[MS-TSRAP]: Telnet Server Remote Administration Protocol',
'497D95A6-2D27-4BF5-9BBD-A6046957133C':'[MS-TSTS]: Terminal Services Terminal Server Runtime Interface',
'11899A43-2B68-4A76-92E3-A3D6AD8C26CE':'[MS-TSTS]: Terminal Services Terminal Server Runtime Interface',
'5CA4A760-EBB1-11CF-8611-00A0245420ED':'[MS-TSTS]: Terminal Services Terminal Server Runtime Interface',
'BDE95FDF-EEE0-45DE-9E12-E5A61CD0D4FE':'[MS-TSTS]: Terminal Services Terminal Server Runtime Interface',
'484809D6-4239-471B-B5BC-61DF8C23AC48':'[MS-TSTS]: Terminal Services Terminal Server Runtime Interface',
'88143FD0-C28D-4B2B-8FEF-8D882F6A9390':'[MS-TSTS]: Terminal Services Terminal Server Runtime Interface',
'53B46B02-C73B-4A3E-8DEE-B16B80672FC0':'[MS-TSTS]: Terminal Services Terminal Server Runtime Interface',
'DDE02280-12B3-4E0B-937B-6747F6ACB286':'[MS-UAMG]: Update Agent Management Protocol',
'112EDA6B-95B3-476F-9D90-AEE82C6B8181':'[MS-UAMG]: Update Agent Management Protocol',
'144FE9B0-D23D-4A8B-8634-FB4457533B7A':'[MS-UAMG]: Update Agent Management Protocol',
'70CF5C82-8642-42BB-9DBC-0CFD263C6C4F':'[MS-UAMG]: Update Agent Management Protocol',
'49EBD502-4A96-41BD-9E3E-4C5057F4250C':'[MS-UAMG]: Update Agent Management Protocol',
'7C907864-346C-4AEB-8F3F-57DA289F969F':'[MS-UAMG]: Update Agent Management Protocol',
'46297823-9940-4C09-AED9-CD3EA6D05968':'[MS-UAMG]: Update Agent Management Protocol',
'4CBDCB2D-1589-4BEB-BD1C-3E582FF0ADD0':'[MS-UAMG]: Update Agent Management Protocol',
'8F45ABF1-F9AE-4B95-A933-F0F66E5056EA':'[MS-UAMG]: Update Agent Management Protocol',
'6A92B07A-D821-4682-B423-5C805022CC4D':'[MS-UAMG]: Update Agent Management Protocol',
'54A2CB2D-9A0C-48B6-8A50-9ABB69EE2D02':'[MS-UAMG]: Update Agent Management Protocol',
'0D521700-A372-4BEF-828B-3D00C10ADEBD':'[MS-UAMG]: Update Agent Management Protocol',
'C2BFB780-4539-4132-AB8C-0A8772013AB6':'[MS-UAMG]: Update Agent Management Protocol',
'1518B460-6518-4172-940F-C75883B24CEB':'[MS-UAMG]: Update Agent Management Protocol',
'81DDC1B8-9D35-47A6-B471-5B80F519223B':'[MS-UAMG]: Update Agent Management Protocol',
'BC5513C8-B3B8-4BF7-A4D4-361C0D8C88BA':'[MS-UAMG]: Update Agent Management Protocol',
'C1C2F21A-D2F4-4902-B5C6-8A081C19A890':'[MS-UAMG]: Update Agent Management Protocol',
'07F7438C-7709-4CA5-B518-91279288134E':'[MS-UAMG]: Update Agent Management Protocol',
'C97AD11B-F257-420B-9D9F-377F733F6F68':'[MS-UAMG]: Update Agent Management Protocol',
'3A56BFB8-576C-43F7-9335-FE4838FD7E37':'[MS-UAMG]: Update Agent Management Protocol',
'615C4269-7A48-43BD-96B7-BF6CA27D6C3E':'[MS-UAMG]: Update Agent Management Protocol',
'004C6A2B-0C19-4C69-9F5C-A269B2560DB9':'[MS-UAMG]: Update Agent Management Protocol',
'7366EA16-7A1A-4EA2-B042-973D3E9CD99B':'[MS-UAMG]: Update Agent Management Protocol',
'A376DD5E-09D4-427F-AF7C-FED5B6E1C1D6':'[MS-UAMG]: Update Agent Management Protocol',
'23857E3C-02BA-44A3-9423-B1C900805F37':'[MS-UAMG]: Update Agent Management Protocol',
'B383CD1A-5CE9-4504-9F63-764B1236F191':'[MS-UAMG]: Update Agent Management Protocol',
'76B3B17E-AED6-4DA5-85F0-83587F81ABE3':'[MS-UAMG]: Update Agent Management Protocol',
'0BB8531D-7E8D-424F-986C-A0B8F60A3E7B':'[MS-UAMG]: Update Agent Management Protocol',
'91CAF7B0-EB23-49ED-9937-C52D817F46F7':'[MS-UAMG]: Update Agent Management Protocol',
'673425BF-C082-4C7C-BDFD-569464B8E0CE':'[MS-UAMG]: Update Agent Management Protocol',
'EFF90582-2DDC-480F-A06D-60F3FBC362C3':'[MS-UAMG]: Update Agent Management Protocol',
'D9A59339-E245-4DBD-9686-4D5763E39624':'[MS-UAMG]: Update Agent Management Protocol',
'9B0353AA-0E52-44FF-B8B0-1F7FA0437F88':'[MS-UAMG]: Update Agent Management Protocol',
'503626A3-8E14-4729-9355-0FE664BD2321':'[MS-UAMG]: Update Agent Management Protocol',
'85713FA1-7796-4FA2-BE3B-E2D6124DD373':'[MS-UAMG]: Update Agent Management Protocol',
'816858A4-260D-4260-933A-2585F1ABC76B':'[MS-UAMG]: Update Agent Management Protocol',
'27E94B0D-5139-49A2-9A61-93522DC54652':'[MS-UAMG]: Update Agent Management Protocol',
'E7A4D634-7942-4DD9-A111-82228BA33901':'[MS-UAMG]: Update Agent Management Protocol',
'D40CFF62-E08C-4498-941A-01E25F0FD33C':'[MS-UAMG]: Update Agent Management Protocol',
'ED8BFE40-A60B-42EA-9652-817DFCFA23EC':'[MS-UAMG]: Update Agent Management Protocol',
'A7F04F3C-A290-435B-AADF-A116C3357A5C':'[MS-UAMG]: Update Agent Management Protocol',
'4A2F5C31-CFD9-410E-B7FB-29A653973A0F':'[MS-UAMG]: Update Agent Management Protocol',
'BE56A644-AF0E-4E0E-A311-C1D8E695CBFF':'[MS-UAMG]: Update Agent Management Protocol',
'918EFD1E-B5D8-4C90-8540-AEB9BDC56F9D':'[MS-UAMG]: Update Agent Management Protocol',
'04C6895D-EAF2-4034-97F3-311DE9BE413A':'[MS-UAMG]: Update Agent Management Protocol',
'15FC031C-0652-4306-B2C3-F558B8F837E2':'[MS-VDS]: Virtual Disk Service (VDS) Protocol',
'4DBCEE9A-6343-4651-B85F-5E75D74D983C':'[MS-VDS]: Virtual Disk Service (VDS) Protocol',
'1E062B84-E5E6-4B4B-8A25-67B81E8F13E8':'[MS-VDS]: Virtual Disk Service (VDS) Protocol',
'2ABD757F-2851-4997-9A13-47D2A885D6CA':'[MS-VDS]: Virtual Disk Service (VDS) Protocol',
'9CBE50CA-F2D2-4BF4-ACE1-96896B729625':'[MS-VDS]: Virtual Disk Service (VDS) Protocol',
'4DAA0135-E1D1-40F1-AAA5-3CC1E53221C3':'[MS-VDS]: Virtual Disk Service (VDS) Protocol',
'3858C0D5-0F35-4BF5-9714-69874963BC36':'[MS-VDS]: Virtual Disk Service (VDS) Protocol',
'40F73C8B-687D-4A13-8D96-3D7F2E683936':'[MS-VDS]: Virtual Disk Service (VDS) Protocol',
'8F4B2F5D-EC15-4357-992F-473EF10975B9':'[MS-VDS]: Virtual Disk Service (VDS) Protocol',
'FC5D23E8-A88B-41A5-8DE0-2D2F73C5A630':'[MS-VDS]: Virtual Disk Service (VDS) Protocol',
'B07FEDD4-1682-4440-9189-A39B55194DC5':'[MS-VDS]: Virtual Disk Service (VDS) Protocol',
'72AE6713-DCBB-4A03-B36B-371F6AC6B53D':'[MS-VDS]: Virtual Disk Service (VDS) Protocol',
'B6B22DA8-F903-4BE7-B492-C09D875AC9DA':'[MS-VDS]: Virtual Disk Service (VDS) Protocol',
'538684E0-BA3D-4BC0-ACA9-164AFF85C2A9':'[MS-VDS]: Virtual Disk Service (VDS) Protocol',
'75C8F324-F715-4FE3-A28E-F9011B61A4A1':'[MS-VDS]: Virtual Disk Service (VDS) Protocol',
'90681B1D-6A7F-48E8-9061-31B7AA125322':'[MS-VDS]: Virtual Disk Service (VDS) Protocol',
'9882F547-CFC3-420B-9750-00DFBEC50662':'[MS-VDS]: Virtual Disk Service (VDS) Protocol',
'83BFB87F-43FB-4903-BAA6-127F01029EEC':'[MS-VDS]: Virtual Disk Service (VDS) Protocol',
'EE2D5DED-6236-4169-931D-B9778CE03DC6':'[MS-VDS]: Virtual Disk Service (VDS) Protocol',
'9723F420-9355-42DE-AB66-E31BB15BEEAC':'[MS-VDS]: Virtual Disk Service (VDS) Protocol',
'4AFC3636-DB01-4052-80C3-03BBCB8D3C69':'[MS-VDS]: Virtual Disk Service (VDS) Protocol',
'D99BDAAE-B13A-4178-9FDB-E27F16B4603E':'[MS-VDS]: Virtual Disk Service (VDS) Protocol',
'D68168C9-82A2-4F85-B6E9-74707C49A58F':'[MS-VDS]: Virtual Disk Service (VDS) Protocol',
'13B50BFF-290A-47DD-8558-B7C58DB1A71A':'[MS-VDS]: Virtual Disk Service (VDS) Protocol',
'6E6F6B40-977C-4069-BDDD-AC710059F8C0':'[MS-VDS]: Virtual Disk Service (VDS) Protocol',
'9AA58360-CE33-4F92-B658-ED24B14425B8':'[MS-VDS]: Virtual Disk Service (VDS) Protocol',
'E0393303-90D4-4A97-AB71-E9B671EE2729':'[MS-VDS]: Virtual Disk Service (VDS) Protocol',
'07E5C822-F00C-47A1-8FCE-B244DA56FD06':'[MS-VDS]: Virtual Disk Service (VDS) Protocol',
'8326CD1D-CF59-4936-B786-5EFC08798E25':'[MS-VDS]: Virtual Disk Service (VDS) Protocol',
'1BE2275A-B315-4F70-9E44-879B3A2A53F2':'[MS-VDS]: Virtual Disk Service (VDS) Protocol',
'0316560B-5DB4-4ED9-BBB5-213436DDC0D9':'[MS-VDS]: Virtual Disk Service (VDS) Protocol',
'14FBE036-3ED7-4E10-90E9-A5FF991AFF01':'[MS-VDS]: Virtual Disk Service (VDS) Protocol',
'3B69D7F5-9D94-4648-91CA-79939BA263BF':'[MS-VDS]: Virtual Disk Service (VDS) Protocol',
'D5D23B6D-5A55-4492-9889-397A3C2D2DBC':'[MS-VDS]: Virtual Disk Service (VDS) Protocol',
'88306BB2-E71F-478C-86A2-79DA200A0F11':'[MS-VDS]: Virtual Disk Service (VDS) Protocol',
'118610B7-8D94-4030-B5B8-500889788E4E':'[MS-VDS]: Virtual Disk Service (VDS) Protocol',
'0AC13689-3134-47C6-A17C-4669216801BE':'[MS-VDS]: Virtual Disk Service (VDS) Protocol',
'0818A8EF-9BA9-40D8-A6F9-E22833CC771E':'[MS-VDS]: Virtual Disk Service (VDS) Protocol',
'6788FAF9-214E-4B85-BA59-266953616E09':'[MS-VDS]: Virtual Disk Service (VDS) Protocol',
'B481498C-8354-45F9-84A0-0BDD2832A91F':'[MS-VDS]: Virtual Disk Service (VDS) Protocol',
'10C5E575-7984-4E81-A56B-431F5F92AE42':'[MS-VDS]: Virtual Disk Service (VDS) Protocol',
'38A0A9AB-7CC8-4693-AC07-1F28BD03C3DA':'[MS-VDS]: Virtual Disk Service (VDS) Protocol',
'8FB6D884-2388-11D0-8C35-00C04FDA2795':'[MS-W32T]: W32Time Remote Protocol',
'5422FD3A-D4B8-4CEF-A12E-E87D4CA22E90':'[MS-WCCE]: Windows Client Certificate Enrollment Protocol',
'D99E6E70-FC88-11D0-B498-00A0C90312F3':'[MS-WCCE]: Windows Client Certificate Enrollment Protocol',
'1A927394-352E-4553-AE3F-7CF4AAFCA620':'[MS-WDSC]: Windows Deployment Services Control Protocol',
'6BFFD098-A112-3610-9833-46C3F87E345A':'[MS-WKST]: Workstation Service Remote Protocol',
'F1E9C5B2-F59B-11D2-B362-00105A1F8177':'[MS-WMI]: Windows Management Instrumentation Remote Protocol',
'423EC01E-2E35-11D2-B604-00104B703EFD':'[MS-WMI]: Windows Management Instrumentation Remote Protocol',
'9556DC99-828C-11CF-A37E-00AA003240C7':'[MS-WMI]: Windows Management Instrumentation Remote Protocol',
'F309AD18-D86A-11D0-A075-00C04FB68820':'[MS-WMI]: Windows Management Instrumentation Remote Protocol',
'9A653086-174F-11D2-B5F9-00104B703EFD':'[MS-WMI]: Windows Management Instrumentation Remote Protocol',
'D4781CD6-E5D3-44DF-AD94-930EFE48A887':'[MS-WMI]: Windows Management Instrumentation Remote Protocol',
'44ACA674-E8FC-11D0-A07C-00C04FB68820':'[MS-WMI]: Windows Management Instrumentation Remote Protocol',
'541679AB-2E5F-11D3-B34E-00104BCC4B4A':'[MS-WMI]: Windows Management Instrumentation Remote Protocol',
'027947E1-D731-11CE-A357-000000000001':'[MS-WMI]: Windows Management Instrumentation Remote Protocol',
'A359DEC5-E813-4834-8A2A-BA7F1D777D76':'[MS-WMI]: Windows Management Instrumentation Remote Protocol',
'C49E32C6-BC8B-11D2-85D4-00105A1F8304':'[MS-WMI]: Windows Management Instrumentation Remote Protocol',
'C49E32C7-BC8B-11D2-85D4-00105A1F8304':'[MS-WMI]: Windows Management Instrumentation Remote Protocol',
'2C9273E0-1DC3-11D3-B364-00105A1F8177':'[MS-WMI]: Windows Management Instrumentation Remote Protocol',
'7C857801-7381-11CF-884D-00AA004B2E24':'[MS-WMI]: Windows Management Instrumentation Remote Protocol',
'DC12A681-737F-11CF-884D-00AA004B2E24':'[MS-WMI]: Windows Management Instrumentation Remote Protocol',
'8BC3F05E-D86B-11D0-A075-00C04FB68820':'[MS-WMI]: Windows Management Instrumentation Remote Protocol',
'44ACA675-E8FC-11D0-A07C-00C04FB68820':'[MS-WMI]: Windows Management Instrumentation Remote Protocol',
'1C1C45EE-4395-11D2-B60B-00104B703EFD':'[MS-WMI]: Windows Management Instrumentation Remote Protocol',
'674B6698-EE92-11D0-AD71-00C04FD8FDFF':'[MS-WMI]: Windows Management Instrumentation Remote Protocol',
'FC910418-55CA-45EF-B264-83D4CE7D30E0':'[MS-WSRM]: Windows System Resource Manager (WSRM) Protocol',
'C5CEBEE2-9DF5-4CDD-A08C-C2471BC144B4':'[MS-WSRM]: Windows System Resource Manager (WSRM) Protocol',
'F31931A9-832D-481C-9503-887A0E6A79F0':'[MS-WSRM]: Windows System Resource Manager (WSRM) Protocol',
'21546AE8-4DA5-445E-987F-627FEA39C5E8':'[MS-WSRM]: Windows System Resource Manager (WSRM) Protocol',
'BC681469-9DD9-4BF4-9B3D-709F69EFE431':'[MS-WSRM]: Windows System Resource Manager (WSRM) Protocol',
'4F7CA01C-A9E5-45B6-B142-2332A1339C1D':'[MS-WSRM]: Windows System Resource Manager (WSRM) Protocol',
'2A3EB639-D134-422D-90D8-AAA1B5216202':'[MS-WSRM]: Windows System Resource Manager (WSRM) Protocol',
'59602EB6-57B0-4FD8-AA4B-EBF06971FE15':'[MS-WSRM]: Windows System Resource Manager (WSRM) Protocol',
'481E06CF-AB04-4498-8FFE-124A0A34296D':'[MS-WSRM]: Windows System Resource Manager (WSRM) Protocol',
'E8BCFFAC-B864-4574-B2E8-F1FB21DFDC18':'[MS-WSRM]: Windows System Resource Manager (WSRM) Protocol',
'943991A5-B3FE-41FA-9696-7F7B656EE34B':'[MS-WSRM]: Windows System Resource Manager (WSRM) Protocol',
'BBA9CB76-EB0C-462C-AA1B-5D8C34415701':'[MS-ADTS]: Active Directory Technical Specification',
'906B0CE0-C70B-1067-B317-00DD010662DA':'[MS-CMPO]: MSDTC Connection Manager:',
'E3514235-4B06-11D1-AB04-00C04FC2DCD2':'[MS-DRSR]: Directory Replication Service (DRS) Remote Protocol',
'F6BEAFF7-1E19-4FBB-9F8F-B89E2018337C':'[MS-EVEN6]: EventLog Remoting Protocol',
'D049B186-814F-11D1-9A3C-00C04FC9B232':'[MS-FRS1]: File Replication Service Protocol',
'F5CC59B4-4264-101A-8C59-08002B2F8426':'[MS-FRS1]: File Replication Service Protocol',
'5A7B91F8-FF00-11D0-A9B2-00C04FB6E6FC':'[MS-MSRP]: Messenger Service Remote Protocol',
'F5CC5A18-4264-101A-8C59-08002B2F8426':'[MS-NSPI]: Name Service Provider Interface (NSPI) Protocol',
'E33C0CC4-0482-101A-BC0C-02608C6BA218':'[MS-RPCL]: Remote Procedure Call Location Services Extensions',
} 

# Inquire Type
RPC_C_EP_ALL_ELTS     = 0x0
RPC_C_EP_MATCH_BY_IF  = 0x1
RPC_C_EP_MATH_BY_OBJ  = 0x2
RPC_C_EP_MATH_BY_BOTH = 0x1

# Vers Option
RPC_C_VERS_ALL        = 0x1
RPC_C_VERS_COMPATIBLE = 0x2
RPC_C_VERS_EXACT      = 0x3
RPC_C_VERS_MARJOR_ONLY= 0x4
RPC_C_VERS_UPTO       = 0x5

# Search 
RPC_NO_MORE_ELEMENTS  = 0x16c9a0d6 

# Floors constants
FLOOR_UUID_IDENTIFIER = 0x0d
# Protocol Identifiers
FLOOR_RPCV5_IDENTIFIER = 0x0b # DCERPC Connection Oriented v.5
FLOOR_MSNP_IDENTIFIER  = 0x0c # MS Named Pipes (LRPC)
# Pipe Identifier
FLOOR_NBNP_IDENTIFIER  = 0x0f # NetBIOS Named Pipe
# HostName Identifier
FLOOR_MSNB_IDENTIFIER  = 0x11 # MS NetBIOS HostName
# PortAddr Identifier
FLOOR_TCPPORT_IDENTIFIER = 0x07

################################################################################
# STRUCTURES
################################################################################

# Tower Floors: As states in C706:
# This appendix defines the rules for encoding an protocol_tower_t (abstract)
# into the twr_t.tower_octet_string and twr_p_t->tower_octet_string fields 
# (concrete). For historical reasons, this cannot be done using the standard NDR 
# encoding rules for marshalling and unmarshalling. A special encoding is 
# required.
# Note that the twr_t and twr_p_t are mashalled as standard IDL data types, 
# encoded in the standard transfer syntax (for example, NDR). As far as IDL and 
# NDR are concerned, tower_octet_string is simply an opaque conformant byte 
# array. This section only defines how to construct this opaque open array of 
# octets, which contains the actual protocol tower information.
# The tower_octet_string[ ] is a variable length array of octets that encodes 
# a single, complete protocol tower. It is encoded as follows:
# * Addresses increase, reading from left to right.
# * Each tower_octet_string begins with a 2-byte floor count, encoded 
#   little-endian, followed by the tower floors as follows:
# +-------------+---------+---------+---------+---------+---------+ 
# |  floorcount |  floor1 |  floor2 |  floor3 |   ...   |  floorn | 
# +-------------+---------+---------+---------+---------+---------+
# The number of tower floors is specific to the particular protocol tower, 
# also known as a protseq.
# * Eachtowerfloorcontainsthefollowing:
#   |<-   tower floor left hand side   ->|<-  tower floor right hand side  ->|
#   +------------+-----------------------+------------+----------------------+
#   |  LHS byte  |  protocol identifier  |  RHS byte  |  related or address  |
#   |   count    |        data           |   count    |        data          |
#   +------------+-----------------------+------------+----------------------+
# The LHS (Left Hand Side) of the floor contains protocol identifier information.
# Protocol identifier values and construction rules are defined in Appendix I.
# The RHS (Right Hand Side) of the floor contains related or addressing 
# information. The type and encoding for the currently defined protocol 
# identifiers are given in Appendix I.
# The floor count, LHS byte count and RHS byte count are all 2-bytes, 
# in little endian format.
#
# So.. we're gonna use Structure to solve this

# Standard Floor Assignments
class EPMFloor(Structure):
    structure = (
        ('LHSByteCount','<H=0'),
        ('_ProtocolData','_-ProtocolData','self["LHSByteCount"]'),
        ('ProtocolData',':'),
        ('RHSByteCount','<H=0'),
        ('_RelatedData','_-RelatedData','self["RHSByteCount"]'),
        ('RelatedData',':'),
    ) 

class EPMRPCInterface(EPMFloor):
    structure = (
        ('LHSByteCount','<H=19'),
        ('InterfaceIdent','B=0x0d'),
        ('InterfaceUUID','16s=""'),
        ('MajorVersion','<H=0'),
        ('RHSByteCount','<H=2'),
        ('MinorVersion','<H=0'),
    )
    def __init__(self, data = None):
        EPMFloor.__init__(self, data)

    def __str__(self):
        aUuid = bin_to_string(self["InterfaceUUID"])
        return "%s v%d.%d" % (aUuid,self["MajorVersion"],self["MinorVersion"])

    def __len__(self):
       return 25

class EPMRPCDataRepresentation(EPMFloor):
    structure = (
        ('LHSByteCount','<H=19'),
        ('DrepIdentifier','B=0x0d'),
        ('DataRepUuid','16s=""'),
        ('MajorVersion','<H=0'),
        ('RHSByteCount','<H=2'),
        ('MinorVersion','<H=0'),
    )
    def __init__(self, data = None):
        EPMFloor.__init__(self, data)

    def __str__(self):
        aUuid = bin_to_string(self["DataRepUuid"])
        return "%s v%d.%d" % (aUuid,self["MajorVersion"],self["MinorVersion"])

    def __len__(self):
       return 25

class EPMProtocolIdentifier(EPMFloor):
    structure = (
        ('LHSByteCount','<H=1'),
        ('ProtIdentifier','B=0'),
        ('RHSByteCount','<H=2'),
        ('MinorVersion','<H=0'),
    )
    def __init__(self, data = None):
        EPMFloor.__init__(self, data)

    def __len__(self):
       return 6

class EPMPipeName(EPMFloor):
    structure = (
        ('LHSByteCount','<H=1'),
        ('PipeIdentifier','B=15'),
        ('RHSByteCount','<H=len(PipeName)'),
        ('PipeName',':'),
    )

class EPMHostName(EPMFloor):
    structure = (
        ('LHSByteCount','<H=1'),
        ('HostNameIdentifier','B=17'),
        ('RHSByteCount','<H=len(HostName)'),
        ('HostName',':'),
    )

class EPMHostAddr(EPMFloor):
    structure = (
        ('LHSByteCount','<H=1'),
        ('HostAddressId','B=9'),
        ('RHSByteCount','<H=len(Ip4addr)'),
        ('Ip4addr','4s=""'),
    )

class EPMPortAddr(EPMFloor):
    structure = (
        ('LHSByteCount','<H=1'),
        ('PortIdentifier','B=7'),
        ('RHSByteCount','<H=2'),
        ('IpPort','>H=0'),
    )

EPMFloors = [ 
EPMRPCInterface,
EPMRPCDataRepresentation,
EPMFloor,
EPMFloor,
EPMFloor,
EPMFloor
]

class EPMTower(Structure):
    structure = (
        ('NumberOfFloors','<H'),
        ('Floors',':'),
    )
    def fromString(self,data):
        Structure.fromString(self,data)
        floors = self['Floors']
        fList = []
        for f in range(self['NumberOfFloors']):
            floor = EPMFloors[f](floors)
            floors = floors[len(floor):]
            fList.append(floor) 
        self['Floors'] = fList

    #def __len__(self):
    #   ll = 0
    #   for i in self['Floors']:
    #       ll += len(i) 
    #   ll += 10
    #   ll += (4-ll%4) & 3
    #   return ll

class RPC_IF_ID(NDRSTRUCT):
    structure = (
        ('Uuid', UUID ),
        ('VersMajor', USHORT),
        ('VersMinor', USHORT),
    )

class PRPC_IF_ID(NDRPOINTER):
    referent = (
        ('Data', RPC_IF_ID),
    )

class ept_lookup_handle_t(NDRSTRUCT):
    structure =  (
        ('context_handle_attributes',ULONG),
        ('context_handle_uuid',UUID),
    )
    def __init__(self, data = None,isNDR64 = False):
        NDRSTRUCT.__init__(self, data, isNDR64)
        self['context_handle_uuid'] = '\x00'*20

class twr_t(NDRSTRUCT):
    structure = (
        ('tower_length', ULONG),
        ('tower_octet_string', NDRUniConformantArray),
    )

class twr_p_t(NDRPOINTER):
    referent = (
        ('Data', twr_t),
    )

class octet_string_t(NDRSTRUCT):
    structure = (
        ('count', USHORT),
        ('value', LPBYTE),
    )

class prot_and_addr_t(NDRSTRUCT):
    structure = (
        ('protocol_id', octet_string_t),
        ('address', octet_string_t),
    )

class protocol_tower_t(NDRSTRUCT):
    structure = (
        ('count', USHORT),
        ('floors', prot_and_addr_t ),
    )

class ept_entry_t(NDRSTRUCT):
    structure = (
        ('object',UUID),
        ('tower',twr_p_t),
        ('annotation', NDRUniVaryingArray),
    )

class ept_entry_t_array(NDRUniConformantVaryingArray):
    item = ept_entry_t

class twr_p_t_array(NDRUniConformantVaryingArray):
    item = twr_p_t

error_status = ULONG

################################################################################
# RPC CALLS
################################################################################

class ept_lookup(NDRCALL):
    opnum = 2
    structure = (
        ('inquiry_type',ULONG),
        ('object',PUUID),
        ('Ifid',PRPC_IF_ID),
        ('vers_option',ULONG),
        ('entry_handle',ept_lookup_handle_t),
        ('max_ents',ULONG),
    )

class ept_lookupResponse(NDRCALL):
    structure = (
        ('entry_handle',ept_lookup_handle_t),
        ('num_ents',ULONG),
        ('entries',ept_entry_t_array),
        ('status',error_status),
    )

class ept_map(NDRCALL):
    opnum = 3
    structure = (
        ('obj',PUUID),
        ('map_tower',twr_p_t),
        ('entry_handle',ept_lookup_handle_t),
        ('max_towers',ULONG),
    )

class ept_mapResponse(NDRCALL):
    structure = (
        ('entry_handle',ept_lookup_handle_t),
        ('num_towers',ULONG),
        ('ITowers',twr_p_t_array),
        ('status',error_status),
    )


################################################################################
# HELPER FUNCTIONS
################################################################################

def hept_lookup(destHost, inquiry_type = RPC_C_EP_ALL_ELTS, objectUUID = NULL, ifId = NULL, vers_option = RPC_C_VERS_ALL,  entry_handle = ept_lookup_handle_t(), max_ents = 499, dce = None):
    if dce is None:
        stringBinding = r'ncacn_ip_tcp:%s[135]' % destHost
        rpctransport = transport.DCERPCTransportFactory(stringBinding)
        dce = rpctransport.get_dce_rpc()
        dce.connect()

    dce.bind(MSRPC_UUID_PORTMAP)
    request = ept_lookup()
    request['inquiry_type'] = inquiry_type
    request['object'] = objectUUID
    if ifId != NULL:
        request['Ifid']['Uuid'] = ifId[:16]
        request['Ifid']['VersMajor'] = ifId[16:][:2]
        request['Ifid']['VersMinor'] = ifId[18:]
    else:
        request['Ifid'] = ifId
    request['vers_option'] = vers_option
    request['entry_handle'] = entry_handle
    request['max_ents'] = max_ents
      
    resp = dce.request(request)

    entries = []
    for i in range(resp['num_ents']):
        tmpEntry = {}
        entry = resp['entries'][i]
        tmpEntry['object'] = entry['object'] 
        tmpEntry['annotation'] = ''.join(entry['annotation'])
        tmpEntry['tower'] = EPMTower(''.join(entry['tower']['tower_octet_string']))
        entries.append(tmpEntry)

    if dce is None:
        dce.disconnect()

    return entries

def hept_map(destHost, remoteIf, dataRepresentation = uuidtup_to_bin(('8a885d04-1ceb-11c9-9fe8-08002b104860', '2.0')), protocol = 'ncacn_np'):
    stringBinding = r'ncacn_ip_tcp:%s[135]' % destHost
    rpctransport = transport.DCERPCTransportFactory(stringBinding)
    dce = rpctransport.get_dce_rpc()
    dce.connect()
    dce.bind(MSRPC_UUID_PORTMAP)

    tower = EPMTower()
    interface = EPMRPCInterface()

    interface['InterfaceUUID'] = remoteIf[:16]
    interface['MajorVersion'] = unpack('<H', remoteIf[16:][:2])[0]
    interface['MinorVersion'] = unpack('<H', remoteIf[18:])[0]

    dataRep = EPMRPCDataRepresentation()
    dataRep['DataRepUuid'] = dataRepresentation[:16]
    dataRep['MajorVersion'] = unpack('<H', dataRepresentation[16:][:2])[0]
    dataRep['MinorVersion'] = unpack('<H', dataRepresentation[18:])[0]

    protId = EPMProtocolIdentifier()
    protId['ProtIdentifier'] = FLOOR_RPCV5_IDENTIFIER

    if protocol == 'ncacn_np':
        pipeName = EPMPipeName()
        pipeName['PipeName'] = '\x00'

        hostName = EPMHostName()
        hostName['HostName'] = '%s\x00' % destHost
        transportData = pipeName.getData() + hostName.getData()

    elif protocol == 'ncacn_ip_tcp':
        portAddr = EPMPortAddr()
        portAddr['IpPort'] = 0

        hostAddr = EPMHostAddr()
        import socket
        hostAddr['Ip4addr'] = socket.inet_aton('0.0.0.0')
        transportData = portAddr.getData() + hostAddr.getData()
    else:
        return None

    tower['NumberOfFloors'] = 5
    tower['Floors'] = interface.getData() + dataRep.getData() + protId.getData() + transportData

    request = ept_map()
    request['max_towers'] = 1
    request['map_tower']['tower_length'] = len(tower)
    request['map_tower']['tower_octet_string'] = str(tower)

    # Under Windows 2003 the Referent IDs cannot be random
    # they must have the following specific values
    # otherwise we get a rpc_x_bad_stub_data exception
    request.fields['obj'].fields['ReferentID'] = 1
    request.fields['map_tower'].fields['ReferentID'] = 2

    resp = dce.request(request)

    tower = EPMTower(''.join(resp['ITowers'][0]['Data']['tower_octet_string']))
    # Now let's parse the result and return an stringBinding
    result = None
    if protocol == 'ncacn_np':
        # Pipe Name should be the 4th floor
        pipeName = EPMPipeName(tower['Floors'][3].getData())
        result = 'ncacn_np:%s[%s]' % (destHost, pipeName['PipeName'][:-1])
    elif protocol == 'ncacn_ip_tcp':
        # Port Number should be the 4th floor
        portAddr = EPMPortAddr(tower['Floors'][3].getData())
        result = 'ncacn_ip_tcp:%s[%s]' % (destHost, portAddr['IpPort'])
        
    dce.disconnect()
    return result

def PrintStringBinding(floors, serverAddr = '0.0.0.0'):
    tmp_address = ''
    for floor in floors[3:]:
        if floor['ProtocolData'] == chr(0x07):
            tmp_address = 'ncacn_ip_tcp:%%s[%d]' % unpack('!H',floor['RelatedData'])
        elif floor['ProtocolData'] == chr(0x08):
            tmp_address = 'ncadg_ip_udp:%%s[%d]' % unpack('!H',floor['RelatedData'])
        elif floor['ProtocolData'] == chr(0x09):
            tmp_address2 = socket.inet_ntoa(floor['RelatedData'])
            # If the address were 0.0.0.0 it would have to be replaced by the remote host's IP.
            if tmp_address2 == '0.0.0.0':
                tmp_address2 = serverAddr
            if tmp_address <> '':
                return tmp_address % tmp_address2
            else:
                return 'IP: %s' % tmp_address2
        elif floor['ProtocolData'] == chr(0x0c):
            tmp_address = 'ncacn_spx:~%%s[%d]' % unpack('!H',floor['RelatedData'])
        elif floor['ProtocolData'] == chr(0x0d):
            n = len(floor['RelatedData'])
            tmp_address2 = ('%02X' * n) % unpack("%dB" % n, floor['RelatedData'])

            if tmp_address <> '':
                return tmp_address % tmp_address2
            else:
                return 'SPX: %s' % tmp_address2
        elif floor['ProtocolData'] == chr(0x0e):
            tmp_address = 'ncadg_ipx:~%%s[%d]' % unpack('!H',floor['RelatedData'])
        elif floor['ProtocolData'] == chr(0x0f):
            tmp_address = 'ncacn_np:%%s[%s]' % floor['RelatedData'][:len(floor['RelatedData'])-1]
        elif floor['ProtocolData'] == chr(0x10):
            return 'ncalrpc:[%s]' % floor['RelatedData'][:len(floor['RelatedData'])-1]
        elif floor['ProtocolData'] == chr(0x01) or floor['ProtocolData'] == chr(0x11):
            if tmp_address <> '':
                return tmp_address % floor['RelatedData'][:len(floor['RelatedData'])-1]
            else:
                return 'NetBIOS: %s' % floor['RelatedData'] 
        elif floor['ProtocolData'] == chr(0x1f):
            tmp_address = 'ncacn_http:%%s[%d]' % unpack('!H',floor['RelatedData'])
        else:
            return 'unknown_proto_0x%x:[0]' % ord(floor['ProtocolData'] )



