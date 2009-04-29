# Copyright (c) 2003-2006 CORE Security Technologies
#
# This software is provided under under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# $Id$
#

# -*- mode: python; tab-width: 4 -*-
# $Id$
#
# Copyright (C) 2001 Michael Teo <michaelteo@bigfoot.com>
# smb.py - SMB/CIFS library
#
# This software is provided 'as-is', without any express or implied warranty. 
# In no event will the author be held liable for any damages arising from the 
# use of this software.
#
# Permission is granted to anyone to use this software for any purpose, 
# including commercial applications, and to alter it and redistribute it 
# freely, subject to the following restrictions:
#
# 1. The origin of this software must not be misrepresented; you must not 
#    claim that you wrote the original software. If you use this software 
#    in a product, an acknowledgment in the product documentation would be
#    appreciated but is not required.
#
# 2. Altered source versions must be plainly marked as such, and must not be 
#    misrepresented as being the original software.
#
# 3. This notice cannot be removed or altered from any source distribution.
#
# Altered source done by Alberto Solino

# Todo:
# [ ] Try [SMB]transport fragmentation using Transact requests
# [ ] Try other methods of doing write (write_raw, transact2, write, write_and_unlock, write_and_close, write_mpx)
# [-] Try replacements for SMB_COM_NT_CREATE_ANDX  (CREATE, T_TRANSACT_CREATE, OPEN_ANDX works
# [x] Fix forceWriteAndx, which needs to send a RecvRequest, because recv() will not send it
# [x] Fix Recv() when using RecvAndx and the answer comes splet in several packets
# [ ] Try [SMB]transport fragmentation with overlaping segments
# [ ] Try [SMB]transport fragmentation with out of order segments
# [x] Do chained AndX requests

import os, sys, socket, string, re, select, errno
import nmb
import types
from random import randint
from struct import *

import ntlm
from dcerpc import samr
from structure import Structure

unicode_support = 0
unicode_convert = 1

try:
    from cStringIO import StringIO
except ImportError:
    from StringIO import StringIO

from binascii import a2b_hex

CVS_REVISION = '$Revision$'

# Shared Device Type
SHARED_DISK = 0x00
SHARED_PRINT_QUEUE = 0x01
SHARED_DEVICE = 0x02
SHARED_IPC = 0x03

# Extended attributes mask
ATTR_ARCHIVE = 0x020
ATTR_COMPRESSED = 0x800
ATTR_NORMAL = 0x080
ATTR_HIDDEN = 0x002
ATTR_READONLY = 0x001
ATTR_TEMPORARY = 0x100
ATTR_DIRECTORY = 0x010
ATTR_SYSTEM = 0x004

# Service Type
SERVICE_DISK = 'A:'
SERVICE_PRINTER = 'LPT1:'
SERVICE_IPC = 'IPC'
SERVICE_COMM = 'COMM'
SERVICE_ANY = '?????'

# Server Type (Can be used to mask with SMBMachine.get_type() or SMBDomain.get_type())
SV_TYPE_WORKSTATION = 0x00000001
SV_TYPE_SERVER      = 0x00000002
SV_TYPE_SQLSERVER   = 0x00000004
SV_TYPE_DOMAIN_CTRL = 0x00000008
SV_TYPE_DOMAIN_BAKCTRL = 0x00000010
SV_TYPE_TIME_SOURCE    = 0x00000020
SV_TYPE_AFP            = 0x00000040
SV_TYPE_NOVELL         = 0x00000080
SV_TYPE_DOMAIN_MEMBER = 0x00000100
SV_TYPE_PRINTQ_SERVER = 0x00000200
SV_TYPE_DIALIN_SERVER = 0x00000400
SV_TYPE_XENIX_SERVER  = 0x00000800
SV_TYPE_NT        = 0x00001000
SV_TYPE_WFW       = 0x00002000
SV_TYPE_SERVER_NT = 0x00004000
SV_TYPE_POTENTIAL_BROWSER = 0x00010000
SV_TYPE_BACKUP_BROWSER    = 0x00020000
SV_TYPE_MASTER_BROWSER    = 0x00040000
SV_TYPE_DOMAIN_MASTER     = 0x00080000
SV_TYPE_LOCAL_LIST_ONLY = 0x40000000
SV_TYPE_DOMAIN_ENUM     = 0x80000000

# Options values for SMB.stor_file and SMB.retr_file
SMB_O_CREAT = 0x10   # Create the file if file does not exists. Otherwise, operation fails.
SMB_O_EXCL = 0x00    # When used with SMB_O_CREAT, operation fails if file exists. Cannot be used with SMB_O_OPEN.
SMB_O_OPEN = 0x01    # Open the file if the file exists
SMB_O_TRUNC = 0x02   # Truncate the file if the file exists

# Share Access Mode
SMB_SHARE_COMPAT = 0x00
SMB_SHARE_DENY_EXCL = 0x10
SMB_SHARE_DENY_WRITE = 0x20
SMB_SHARE_DENY_READEXEC = 0x30
SMB_SHARE_DENY_NONE = 0x40
SMB_ACCESS_READ = 0x00
SMB_ACCESS_WRITE = 0x01
SMB_ACCESS_READWRITE = 0x02
SMB_ACCESS_EXEC = 0x03

TRANS_DISCONNECT_TID = 1
TRANS_NO_RESPONSE    = 2

#*********************************** TEMP BEGIN ********************************
def set_key_odd_parity(key):
    ""
    for i in range(len(key)):
        for k in range(7):
            bit = 0
            t = key[i] >> k
            bit = (t ^ bit) & 0x1
        key[i] = (key[i] & 0xFE) | bit

    return key

#*********************************** TEMP END ********************************

def strerror(errclass, errcode):
    if errclass == 0x01:
        return 'OS error', ERRDOS.get(errcode, 'Unknown error')
    elif errclass == 0x02:
        return 'Server error', ERRSRV.get(errcode, 'Unknown error')
    elif errclass == 0x03:
        return 'Hardware error', ERRHRD.get(errcode, 'Unknown error')
    # This is not a standard error class for SMB
    elif errclass == 0x80:
        return 'Browse error', ERRBROWSE.get(errcode, 'Unknown error')
    elif errclass == 0xff:
        return 'Bad command', 'Bad command. Please file bug report'
    else:
        return 'Unknown error', 'Unknown error'

    

# Raised when an error has occured during a session
class SessionError(Exception):
    # Error codes


    # SMB X/Open error codes for the ERRDOS error class
    ERRsuccess = 0
    ERRbadfunc = 1
    ERRbadfile = 2
    ERRbadpath = 3
    ERRnofids = 4
    ERRnoaccess = 5
    ERRbadfid = 6
    ERRbadmcb = 7
    ERRnomem = 8
    ERRbadmem = 9
    ERRbadenv = 10
    ERRbadaccess = 12
    ERRbaddata = 13
    ERRres = 14
    ERRbaddrive = 15
    ERRremcd = 16
    ERRdiffdevice = 17
    ERRnofiles = 18
    ERRgeneral = 31
    ERRbadshare = 32
    ERRlock = 33
    ERRunsup = 50
    ERRnetnamedel = 64
    ERRnosuchshare = 67
    ERRfilexists = 80
    ERRinvalidparam = 87
    ERRcannotopen = 110
    ERRinsufficientbuffer = 122
    ERRinvalidname = 123
    ERRunknownlevel = 124
    ERRnotlocked = 158
    ERRrename = 183
    ERRbadpipe = 230
    ERRpipebusy = 231
    ERRpipeclosing = 232
    ERRnotconnected = 233
    ERRmoredata = 234
    ERRnomoreitems = 259
    ERRbaddirectory = 267
    ERReasnotsupported = 282
    ERRlogonfailure = 1326
    ERRbuftoosmall = 2123
    ERRunknownipc = 2142
    ERRnosuchprintjob = 2151
    ERRinvgroup = 2455

    # here's a special one from observing NT
    ERRnoipc = 66

    # These errors seem to be only returned by the NT printer driver system
    ERRdriveralreadyinstalled = 1795
    ERRunknownprinterport = 1796
    ERRunknownprinterdriver = 1797
    ERRunknownprintprocessor = 1798
    ERRinvalidseparatorfile = 1799
    ERRinvalidjobpriority = 1800
    ERRinvalidprintername = 1801
    ERRprinteralreadyexists = 1802
    ERRinvalidprintercommand = 1803
    ERRinvaliddatatype = 1804
    ERRinvalidenvironment = 1805

    ERRunknownprintmonitor = 3000
    ERRprinterdriverinuse = 3001
    ERRspoolfilenotfound = 3002
    ERRnostartdoc = 3003
    ERRnoaddjob = 3004
    ERRprintprocessoralreadyinstalled = 3005
    ERRprintmonitoralreadyinstalled = 3006
    ERRinvalidprintmonitor = 3007
    ERRprintmonitorinuse = 3008
    ERRprinterhasjobsqueued = 3009

    # Error codes for the ERRSRV class

    ERRerror = 1
    ERRbadpw = 2
    ERRbadtype = 3
    ERRaccess = 4
    ERRinvnid = 5
    ERRinvnetname = 6
    ERRinvdevice = 7
    ERRqfull = 49
    ERRqtoobig = 50
    ERRinvpfid = 52
    ERRsmbcmd = 64
    ERRsrverror = 65
    ERRfilespecs = 67
    ERRbadlink = 68
    ERRbadpermits = 69
    ERRbadpid = 70
    ERRsetattrmode = 71
    ERRpaused = 81
    ERRmsgoff = 82
    ERRnoroom = 83
    ERRrmuns = 87
    ERRtimeout = 88
    ERRnoresource = 89
    ERRtoomanyuids = 90
    ERRbaduid = 91
    ERRuseMPX = 250
    ERRuseSTD = 251
    ERRcontMPX = 252
    ERRbadPW = None
    ERRnosupport = 0
    ERRunknownsmb = 22

    # Error codes for the ERRHRD class

    ERRnowrite = 19
    ERRbadunit = 20
    ERRnotready = 21
    ERRbadcmd = 22
    ERRdata = 23
    ERRbadreq = 24
    ERRseek = 25
    ERRbadmedia = 26
    ERRbadsector = 27
    ERRnopaper = 28
    ERRwrite = 29
    ERRread = 30
    ERRgeneral = 31
    ERRwrongdisk = 34
    ERRFCBunavail = 35
    ERRsharebufexc = 36
    ERRdiskfull = 39


    hard_msgs = {
      19: ("ERRnowrite", "Attempt to write on write-protected diskette."),
      20: ("ERRbadunit", "Unknown unit."),
      21: ("ERRnotready", "Drive not ready."),
      22: ("ERRbadcmd", "Unknown command."),
      23: ("ERRdata", "Data error (CRC)."),
      24: ("ERRbadreq", "Bad request structure length."),
      25 : ("ERRseek", "Seek error."),
      26: ("ERRbadmedia", "Unknown media type."),
      27: ("ERRbadsector", "Sector not found."),
      28: ("ERRnopaper", "Printer out of paper."),
      29: ("ERRwrite", "Write fault."),
      30: ("ERRread", "Read fault."),
      31: ("ERRgeneral", "General failure."),
      32: ("ERRbadshare", "An open conflicts with an existing open."),
      33: ("ERRlock", "A Lock request conflicted with an existing lock or specified an invalid mode, or an Unlock requested attempted to remove a lock held by another process."),
      34: ("ERRwrongdisk", "The wrong disk was found in a drive."),
      35: ("ERRFCBUnavail", "No FCBs are available to process request."),
      36: ("ERRsharebufexc", "A sharing buffer has been exceeded.")
      }
    dos_msgs = {
      ERRbadfunc: ("ERRbadfunc", "Invalid function."),
      ERRbadfile: ("ERRbadfile", "File not found."),
      ERRbadpath: ("ERRbadpath", "Directory invalid."),
      ERRnofids: ("ERRnofids", "No file descriptors available"),
      ERRnoaccess: ("ERRnoaccess", "Access denied."),
      ERRbadfid: ("ERRbadfid", "Invalid file handle."),
      ERRbadmcb: ("ERRbadmcb", "Memory control blocks destroyed."),
      ERRnomem: ("ERRnomem", "Insufficient server memory to perform the requested function."),
      ERRbadmem: ("ERRbadmem", "Invalid memory block address."),
      ERRbadenv: ("ERRbadenv", "Invalid environment."),
      11: ("ERRbadformat", "Invalid format."),
      ERRbadaccess: ("ERRbadaccess", "Invalid open mode."),
      ERRbaddata: ("ERRbaddata", "Invalid data."),
      ERRres: ("ERRres", "reserved."),
      ERRbaddrive: ("ERRbaddrive", "Invalid drive specified."),
      ERRremcd: ("ERRremcd", "A Delete Directory request attempted  to  remove  the  server's  current directory."),
      ERRdiffdevice: ("ERRdiffdevice", "Not same device."),
      ERRnofiles: ("ERRnofiles", "A File Search command can find no more files matching the specified criteria."),
      ERRbadshare: ("ERRbadshare", "The sharing mode specified for an Open conflicts with existing  FIDs  on the file."),
      ERRlock: ("ERRlock", "A Lock request conflicted with an existing lock or specified an  invalid mode,  or an Unlock requested attempted to remove a lock held by another process."),
      ERRunsup: ("ERRunsup",  "The operation is unsupported"),
      ERRnosuchshare: ("ERRnosuchshare",  "You specified an invalid share name"),
      ERRfilexists: ("ERRfilexists", "The file named in a Create Directory, Make  New  File  or  Link  request already exists."),
      ERRinvalidname: ("ERRinvalidname",  "Invalid name"),
      ERRbadpipe: ("ERRbadpipe", "Pipe invalid."),
      ERRpipebusy: ("ERRpipebusy", "All instances of the requested pipe are busy."),
      ERRpipeclosing: ("ERRpipeclosing", "Pipe close in progress."),
      ERRnotconnected: ("ERRnotconnected", "No process on other end of pipe."),
      ERRmoredata: ("ERRmoredata", "There is more data to be returned."),
      ERRinvgroup: ("ERRinvgroup", "Invalid workgroup (try the -W option)"),
      ERRlogonfailure: ("ERRlogonfailure", "Logon failure"),
      ERRdiskfull: ("ERRdiskfull", "Disk full"),
      ERRgeneral: ("ERRgeneral",  "General failure"),
      ERRunknownlevel: ("ERRunknownlevel",  "Unknown info level")
      }

    server_msgs = { 
      1: ("ERRerror", "Non-specific error code."),
      2: ("ERRbadpw", "Bad password - name/password pair in a Tree Connect or Session Setup are invalid."),
      3: ("ERRbadtype", "reserved."),
      4: ("ERRaccess", "The requester does not have  the  necessary  access  rights  within  the specified  context for the requested function. The context is defined by the TID or the UID."),
      5: ("ERRinvnid", "The tree ID (TID) specified in a command was invalid."),
      6: ("ERRinvnetname", "Invalid network name in tree connect."),
      7: ("ERRinvdevice", "Invalid device - printer request made to non-printer connection or  non-printer request made to printer connection."),
      49: ("ERRqfull", "Print queue full (files) -- returned by open print file."),
      50: ("ERRqtoobig", "Print queue full -- no space."),
      51: ("ERRqeof", "EOF on print queue dump."),
      52: ("ERRinvpfid", "Invalid print file FID."),
      64: ("ERRsmbcmd", "The server did not recognize the command received."),
      65: ("ERRsrverror","The server encountered an internal error, e.g., system file unavailable."),
      67: ("ERRfilespecs", "The file handle (FID) and pathname parameters contained an invalid  combination of values."),
      68: ("ERRreserved", "reserved."),
      69: ("ERRbadpermits", "The access permissions specified for a file or directory are not a valid combination.  The server cannot set the requested attribute."),
      70: ("ERRreserved", "reserved."),
      71: ("ERRsetattrmode", "The attribute mode in the Set File Attribute request is invalid."),
      81: ("ERRpaused", "Server is paused."),
      82: ("ERRmsgoff", "Not receiving messages."),
      83: ("ERRnoroom", "No room to buffer message."),
      87: ("ERRrmuns", "Too many remote user names."),
      88: ("ERRtimeout", "Operation timed out."),
      89: ("ERRnoresource", "No resources currently available for request."),
      90: ("ERRtoomanyuids", "Too many UIDs active on this session."),
      91: ("ERRbaduid", "The UID is not known as a valid ID on this session."),
      250: ("ERRusempx","Temp unable to support Raw, use MPX mode."),
      251: ("ERRusestd","Temp unable to support Raw, use standard read/write."),
      252: ("ERRcontmpx", "Continue in MPX mode."),
      253: ("ERRreserved", "reserved."),
      254: ("ERRreserved", "reserved."),
  0xFFFF: ("ERRnosupport", "Function not supported.")
  }    
    # Error clases

    ERRDOS = 0x1
    error_classes = { 0: ("SUCCESS", {}),
                      ERRDOS: ("ERRDOS", dos_msgs),
                      0x02: ("ERRSRV",server_msgs),
                      0x03: ("ERRHRD",hard_msgs),
                      0x04: ("ERRXOS", {} ),
                      0xE1: ("ERRRMX1", {} ),
                      0xE2: ("ERRRMX2", {} ),
                      0xE3: ("ERRRMX3", {} ),
                      0xFF: ("ERRCMD", {} ) }

    

    def __init__( self, str, error_class, error_code):
        self.args = str
        self.error_class = error_class
        self.error_code = error_code

    def get_error_class( self ):
        return self.error_class

    def get_error_code( self ):
        return self.error_code

    def __str__( self ):
        error_class = SessionError.error_classes.get( self.error_class, None )
        if not error_class:
            error_code_str = self.error_code
            error_class_str = self.error_class
        else:
            error_class_str = error_class[0]
            error_code = error_class[1].get( self.error_code, None )
            if not error_code:
                error_code_str = self.error_code
            else:
                error_code_str = '%s(%s)' % (error_code)

        return 'SessionError: %s, class: %s, code: %s' % (self.args, error_class_str, error_code_str)


# Raised when an supported feature is present/required in the protocol but is not
# currently supported by pysmb
class UnsupportedFeature(Exception): pass

# Contains information about a SMB shared device/service
class SharedDevice:

    def __init__(self, name, type, comment):
        self.__name = name
        self.__type = type
        self.__comment = comment

    def get_name(self):
        return self.__name

    def get_type(self):
        return self.__type

    def get_comment(self):
        return self.__comment

    def __repr__(self):
        return '<SharedDevice instance: name=' + self.__name + ', type=' + str(self.__type) + ', comment="' + self.__comment + '">'



# Contains information about the shared file/directory
class SharedFile:

    def __init__(self, ctime, atime, mtime, filesize, allocsize, attribs, shortname, longname):
        self.__ctime = ctime
        self.__atime = atime
        self.__mtime = mtime
        self.__filesize = filesize
        self.__allocsize = allocsize
        self.__attribs = attribs
        try:
            self.__shortname = shortname[:string.index(shortname, '\0')]
        except ValueError:
            self.__shortname = shortname
        try:
            self.__longname = longname[:string.index(longname, '\0')]
        except ValueError:
            self.__longname = longname

    def get_ctime(self):
        return self.__ctime

    def get_ctime_epoch(self):
        return self.__convert_smbtime(self.__ctime)

    def get_mtime(self):
        return self.__mtime

    def get_mtime_epoch(self):
        return self.__convert_smbtime(self.__mtime)

    def get_atime(self):
        return self.__atime

    def get_atime_epoch(self):
        return self.__convert_smbtime(self.__atime)

    def get_filesize(self):
        return self.__filesize

    def get_allocsize(self):
        return self.__allocsize

    def get_attributes(self):
        return self.__attribs

    def is_archive(self):
        return self.__attribs & ATTR_ARCHIVE

    def is_compressed(self):
        return self.__attribs & ATTR_COMPRESSED

    def is_normal(self):
        return self.__attribs & ATTR_NORMAL

    def is_hidden(self):
        return self.__attribs & ATTR_HIDDEN

    def is_readonly(self):
        return self.__attribs & ATTR_READONLY

    def is_temporary(self):
        return self.__attribs & ATTR_TEMPORARY

    def is_directory(self):
        return self.__attribs & ATTR_DIRECTORY

    def is_system(self):
        return self.__attribs & ATTR_SYSTEM

    def get_shortname(self):
        return self.__shortname

    def get_longname(self):
        return self.__longname

    def __repr__(self):
        return '<SharedFile instance: shortname="' + self.__shortname + '", longname="' + self.__longname + '", filesize=' + str(self.__filesize) + '>'

    def __convert_smbtime(self, t):
        x = t >> 32
        y = t & 0xffffffffL
        geo_cal_offset = 11644473600.0  # = 369.0 * 365.25 * 24 * 60 * 60 - (3.0 * 24 * 60 * 60 + 6.0 * 60 * 60)
        return ((x * 4.0 * (1 << 30) + (y & 0xfff00000L)) * 1.0e-7 - geo_cal_offset)


# Contain information about a SMB machine
class SMBMachine:

    def __init__(self, nbname, type, comment):
        self.__nbname = nbname
        self.__type = type
        self.__comment = comment

    def __repr__(self):
        return '<SMBMachine instance: nbname="' + self.__nbname + '", type=' + hex(self.__type) + ', comment="' + self.__comment + '">'



class SMBDomain:

    def __init__(self, nbgroup, type, master_browser):
        self.__nbgroup = nbgroup
        self.__type = type
        self.__master_browser = master_browser

    def __repr__(self):
        return '<SMBDomain instance: nbgroup="' + self.__nbgroup + '", type=' + hex(self.__type) + ', master browser="' + self.__master_browser + '">'
    
# Represents a SMB Packet
class NewSMBPacket(Structure):
    structure = (
        ('Signature', '"\xffSMB'),
        ('Command','B=0'),
        ('ErrorClass','B=0'),
        ('_reserved','B=0'),
        ('ErrorCode','<H=0'),
        ('Flags1','B=0'),
        ('Flags2','<H=0'),
        ('Padding','12s=""'),
        ('Tid','<H=0xffff'),
        ('Pid','<H=0'),
        ('Uid','<H=0'),
        ('Mid','<H=0'),
        ('Data','*:'),
    )

    def __init__(self, **kargs):
        Structure.__init__(self, **kargs)

        if not kargs.has_key('data'):
            self['Data'] = []

    def addCommand(self, command):
        if len(self['Data']) == 0:
            self['Command'] = command.command
        else:
            self['Data'][-1]['Parameters']['AndXCommand'] = command.command
            self['Data'][-1]['Parameters']['AndXOffset'] = len(self)
        self['Data'].append(command)
        
    def isMoreData(self):
        return (self['Command'] in [SMB.SMB_COM_TRANSACTION, SMB.SMB_COM_READ_ANDX, SMB.SMB_COM_READ_RAW] and
                self['ErrorClass'] == 1 and self['ErrorCode'] == SessionError.ERRmoredata)

    def isValidAnswer(self, cmd):
        # this was inside a loop reading more from the net (with recv_packet(None))
        if self['Command'] == cmd:
            if (self['ErrorClass'] == 0x00 and
                self['ErrorCode']  == 0x00):
                    return 1
            elif self.isMoreData():
                return 1
            raise SessionError, ("SMB Library Error", self['ErrorClass'], self['ErrorCode'])
        else:
            raise UnsupportedFeature, ("Unexpected answer from server: Got %d, Expected %d" % (self['Command'], cmd))

class SMBPacket:
    def __init__(self,data = ''):
        # The uid attribute will be set when the client calls the login() method
        self._command = 0x0
        self._error_class = 0x0
        self._error_code = 0x0
        self._flags = 0x0
        self._flags2 = 0x0
        self._pad = '\0' * 12
        self._tid = 0x0
        self._pid = 0x0
        self._uid = 0x0
        self._mid = 0x0
        self._wordcount = 0x0
        self._parameter_words = ''
        self._bytecount = 0x0
        self._buffer = ''
        if data != '':
            self._command = ord(data[4])
            self._error_class = ord(data[5])
            self._error_code = unpack('<H',data[7:9])[0]
            self._flags = ord(data[9])
            self._flags2 = unpack('<H',data[10:12])[0]
            self._tid = unpack('<H',data[24:26])[0]
            self._pid = unpack('<H',data[26:28])[0]
            self._uid = unpack('<H',data[28:30])[0]
            self._mid = unpack('<H',data[30:32])[0]
            self._wordcount = ord(data[32])
            self._parameter_words = data[33:33+self._wordcount*2]
            self._bytecount = ord(data[33+self._wordcount*2])
            self._buffer = data[35+self._wordcount*2:]
    def set_command(self,command):
        self._command = command
    def set_error_class(self, error_class):
        self._error_class = error_class
    def set_error_code(self,error_code):
        self._error_code = error_code
    def set_flags(self,flags):
        self._flags = flags
    def set_flags2(self, flags2):
        self._flags2 = flags2
    def set_pad(self, pad):
        self._pad = pad
    def set_tid(self,tid):
        self._tid = tid
    def set_pid(self,pid):
        self._pid = pid
    def set_uid(self,uid):
        self._uid = uid
    def set_mid(self,mid):
        self._mid = mid
    def set_parameter_words(self,param):
        self._parameter_words = param
        self._wordcount = len(param)/2
    def set_buffer(self,buffer):
        if type(buffer) is types.UnicodeType:
            raise Exception('SMBPacket: Invalid buffer. Received unicode')
        self._buffer = buffer
        self._bytecount = len(buffer)

    def get_command(self):
        return self._command
    def get_error_class(self):
        return self._error_class
    def get_error_code(self):
        return self._error_code
    def get_flags(self):
        return self._flags
    def get_flags2(self):
        return self._flags2
    def get_pad(self):
        return self._pad
    def get_tid(self):
        return self._tid
    def get_pid(self):
        return self._pid
    def get_uid(self):
        return self._uid
    def get_mid(self):
        return self._mid
    def get_parameter_words(self):
        return self._parameter_words
    def get_wordcount(self):
        return self._wordcount
    def get_bytecount(self):
        return self._bytecount
    def get_buffer(self):
        return self._buffer
    def rawData(self):
        data = pack('<4sBBBHBH12sHHHHB','\xffSMB',self._command,self._error_class,0,self._error_code,self._flags,
                    self._flags2,self._pad,self._tid, self._pid, self._uid, self._mid, self._wordcount) + self._parameter_words + pack('<H',self._bytecount) + self._buffer
        return data        

class TRANSHeader:
    def __init__(self,params = '', data = ''):
        self._total_param_count = 0
        self._total_data_count = 0
        self._max_param_count = 0
        self._max_data_count = 0
        self._max_setup_count = 0
        self._flags = 0
        self._timeout = 0
        self._param_count = 0
        self._param_offset = 0
        self._data_count = 0
        self._data_offset = 0
        self._setup_count = 0
        self._setup = 0
        self._name = ''
        self._pad = ''
        self._parameters = 0
        self._data = 0
        if data != '' and params != '':
            self._total_param_count, self._total_data_count, _, self._param_count, self._param_offset, self._param_displacement, self._data_count, self._data_offset, self._data_displacement, self._setup_count, _ = unpack ('<HHHHHHHHHBB', params)
            self._data = data[-self._data_count:]; # Remove -potential- prefix padding.
            
    def set_flags(self, flags):
        self._flags = flags
    def set_name(self,name):
        self._name = name
    def set_setup(self,setup):
        self._setup = setup
    def set_parameters(self,parameters):
        self._parameters = parameters
        self._total_param_count = len(parameters)
    def set_data(self, data):
        self._data = data
        self._total_data_count = len(data)
    def set_max_data_count(self, max):
        self._max_data_count = max
    def set_max_param_count(self, max):
        self._max_param_count = max
    def get_rawParameters(self):
        self._param_offset = 32+3+28+len(self._setup)+len(self._name)
        self._data_offset = self._param_offset + len(self._parameters)
        return pack('<HHHHBBHLHHHHHBB', self._total_param_count, self._total_data_count, self._max_param_count, self._max_data_count, self._max_setup_count,
                    0,self._flags, self._timeout, 0, self._total_param_count, self._param_offset , self._total_data_count, self._data_offset, len(self._setup) / 2,0 ) + self._setup
    def get_data(self):
        return self._data
    def rawData(self):
        return self._name +  self._parameters + self._data

class SMBCommand(Structure):
    structure = (
        ('WordCount', 'B=len(Parameters)/2'),
        ('_ParametersLength','_-Parameters','WordCount*2'),
        ('Parameters',':'),             # default set by constructor
        ('ByteCount','<H-Data'),
        ('Data',':'),                   # default set by constructor
    )

    def __init__(self, commandOrData = None, data = None, **kargs):
        if type(commandOrData) == type(0):
            self.command = commandOrData
        else:
            data = data or commandOrData

        Structure.__init__(self, data = data, **kargs)

        if data is None:
            self['Parameters'] = ''
            self['Data']       = ''

class AsciiOrUnicodeStructure(Structure):
    def __init__(self, flags = 0, **kargs):
        if flags & SMB.FLAGS2_UNICODE:
            self.structure = self.UnicodeStructure
        else:
            self.structure = self.AsciiStructure
        return Structure.__init__(self, **kargs)

class SMBCommand_Parameters(Structure):
    pass

class SMBAndXCommand_Parameters(Structure):
    commonHdr = (
        ('AndXCommand','B=0xff'),
        ('_reserved','B=0'),
        ('AndXOffset','<H=0'),
    )
    structure = (       # default structure, overriden by subclasses
        ('Data',':=""'),
    )

class SMBSessionSetupAndX_Parameters(SMBAndXCommand_Parameters):
    structure = (
        ('MaxBuffer','<H'),
        ('MaxMpxCount','<H'),
        ('VCNumber','<H'),
        ('SessionKey','<L'),
        ('AnsiPwdLength','<H'),
        ('UnicodePwdLength','<H'),
        ('_reserved','<L=0'),
        ('Capabilities','<L'),
    )

class SMBSessionSetupAndX_Data(AsciiOrUnicodeStructure):
    AsciiStructure = (
        ('AnsiPwdLength','_-AnsiPwd'),
        ('UnicodePwdLength','_-UnicodePwd'),
        ('AnsiPwd',':=""'),
        ('UnicodePwd',':=""'),
        ('Account','z=""'),
        ('PrimaryDomain','z=""'),
        ('NativeOS','z=""'),
        ('NativeLanMan','z=""'),
    )
    
    UnicodeStructure = (
        ('AnsiPwdLength','_-AnsiPwd'),
        ('UnicodePwdLength','_-UnicodePwd'),
        ('AnsiPwd',':=""'),
        ('UnicodePwd',':=""'),
        ('Account','w=""'),
        ('PrimaryDomain','w=""'),
        ('NativeOS','w=""'),
        ('NativeLanMan','w=""'),
    )

class SMBSessionSetupAndXResponse_Parameters(SMBAndXCommand_Parameters):
    structure = (
        ('Action','<H'),
    )

class SMBSessionSetupAndXResponse_Data(AsciiOrUnicodeStructure):
    AsciiStructure = (
        ('NativeOS','z=""'),
        ('NativeLanMan','z=""'),
        ('PrimaryDomain','z=""'),
    )

    UnicodeStructure = (
        ('NativeOS','w=""'),
        ('NativeLanMan','w=""'),
        ('PrimaryDomain','w=""'),
    )

class SMBTreeConnect_Parameters(SMBCommand_Parameters):
    structure = (
    )

class SMBTreeConnect_Data(SMBCommand_Parameters):
    structure = (
        ('PathFormat','"\x04'),
        ('Path','z'),
        ('PasswordFormat','"\x04'),
        ('Password','z'),
        ('ServiceFormat','"\x04'),
        ('Service','z'),
    )
class SMBTreeConnectAndX_Parameters(SMBAndXCommand_Parameters):
    structure = (
        ('Flags','<H=0'),
        ('PasswordLength','<H'),
    )

class SMBTreeConnectAndX_Data(SMBCommand_Parameters):
    structure = (
        ('_PasswordLength','_-Password'),
        ('Password',':'),
        ('Path','z'),
        ('Service','z'),
    )

class SMBNtCreateAndX_Parameters(SMBAndXCommand_Parameters):
    structure = (
        ('_reserved', 'B=0'),
        ('FileNameLength','<H'),
        ('CreateFlags','<L'),
        ('RootFid','<L=0'),
        ('AccessMask','<L'),
        ('AllocationSizeLo','<L=0'),
        ('AllocationSizeHi','<L=0'),
        ('FileAttributes','<L=0'),
        ('ShareAccess','<L=3'),
        ('Disposition','<L=1'),
        ('CreateOptions','<L'),
        ('Impersonation','<L=2'),
        ('SecurityFlags','B=3'),
    )

class SMBNtCreateAndXResponse_Parameters(SMBAndXCommand_Parameters):
    # XXX Is there a memory leak in the response for NTCreate (where the Data section would be) in Win 2000, Win XP, and Win 2003?
    structure = (
        ('OplockLevel', 'B=0'),
        ('Fid','<H'),
        ('CreateAction','<L'),
        ('CraetionTimeLo','<L=0'),
        ('CraetionTimeHi','<L=0'),
        ('AccessTimeLo','<L=0'),
        ('AccessTimeHi','<L=0'),
        ('LastWriteTimeLo','<L=0'),
        ('LastWriteTimeHi','<L=0'),
        ('ChangeTimeLo','<L=0'),
        ('ChangeTimeHi','<L=0'),
        ('FileAttributes','<L=0x80'),
        ('AllocationSizeLo','<L=0'),
        ('AllocationSizeHi','<L=0'),
        ('EndOfFileLo','<L=0'),
        ('EndOfFileHi','<L=0'),
        ('FileType','<H=0'),
        ('IPCState','<H=0'),
        ('IsDirectory','B'),
    )

class SMBNtCreateAndX_Data(Structure):
    structure = (
        ('FileName','z'),
    )

class SMBOpenAndX_Parameters(SMBAndXCommand_Parameters):
    structure = (
        ('Flags','<H=0'),
        ('DesiredAccess','<H=0'),
        ('SearchAttributes','<H=0'),
        ('FileAttributes','<H=0'),
        ('CreationTime','<L=0'),
        ('OpenMode','<H=1'),        # SMB_O_OPEN = 1
        ('AllocationSize','<L=0'),
        ('Reserved','8s=""'),
    )

class SMBOpenAndX_Data(SMBNtCreateAndX_Data):
    pass

class SMBOpenAndXResponse_Parameters(SMBAndXCommand_Parameters):
    structure = (
        ('Fid','<H=0'),
        ('FileAttributes','<H=0'),
        ('LastWriten','<L=0'),
        ('FileSize','<L=0'),
        ('GrantedAccess','<H=0'),
        ('FileType','<H=0'),
        ('IPCState','<H=0'),
        ('Action','<H=0'),
        ('ServerFid','<L=0'),
        ('_reserved','<H=0'),
    )

class SMBWrite_Parameters(SMBCommand_Parameters):
    structure = (
        ('Fid','<H'),
        ('Count','<H'),
        ('Offset','<L'),
        ('Remaining','<H'),
    )

class SMBWrite_Data(Structure):
    structure = (
        ('BufferFormat','<B=1'),
        ('DataLength','<H-Data'),
        ('Data',':'),
    )
    
class SMBWriteAndX_Parameters(SMBAndXCommand_Parameters):
    structure = (
        ('Fid','<H'),
        ('Offset','<L'),
        ('_reserved','<L=0xff'),
        ('WriteMode','<H=8'),
        ('Remaining','<H'),
        ('DataLength_Hi','<H=0'),
        ('DataLength','<H'),
        ('DataOffset','<H=0'),
        ('HighOffset','<L=0'),
    )
    
class SMBWriteRaw_Parameters(SMBCommand_Parameters):
    structure = (
        ('Fid','<H'),
        ('Count','<H'),
        ('_reserved','<H=0'),
        ('Offset','<L'),
        ('Timeout','<L=0'),
        ('WriteMode','<H=0'),
        ('_reserved2','<L=0'),
        ('DataLength','<H'),
        ('DataOffset','<H=0'),
    )
    
class SMBRead_Parameters(SMBCommand_Parameters):
    structure = (
        ('Fid','<H'),
        ('Count','<H'),
        ('Offset','<L'),
        ('Remaining','<H=Count'),
    )

class SMBReadResponse_Parameters(Structure):
    structure = (
        ('Count','<H=0'),
        ('_reserved','"\0\0\0\0\0\0\0\0'),
    )

class SMBReadResponse_Data(Structure):
    structure = (
        ('BufferFormat','<B'),
        ('DataLength','<H-Data'),
        ('Data',':'),
    )

class SMBReadRaw_Parameters(SMBCommand_Parameters):
    structure = (
        ('Fid','<H'),
        ('Offset','<L'),
        ('MaxCount','<H'),
        ('MinCount','<H=MaxCount'),
        ('Timeout','<L=0'),
        ('_reserved','<H=0'),
    )

class SMBReadAndX_Parameters(SMBAndXCommand_Parameters):
    structure = (
        ('Fid','<H'),
        ('Offset','<L'),
        ('MaxCount','<H'),
        ('MinCount','<H=MaxCount'),
        ('_reserved','<L=0xffffffff'),
        ('Remaining','<H=MaxCount'),
        ('HighOffset','<L=0'),
    )

class SMBReadAndXResponse_Parameters(SMBAndXCommand_Parameters):
    structure = (
        ('Remaining','<H=0'),
        ('DataMode','<H=0'),
        ('_reserved','<H=0'),
        ('DataCount','<H'),
        ('DataOffset','<H'),
        ('DataCount_Hi','<L'),
        ('_reserved2','"\0\0\0\0\0\0'),
    )
class SMBOpen_Parameters(SMBCommand_Parameters):
    structure = (
        ('DesiredAccess','<H=0'),
        ('SearchAttributes','<H=0'),
    )

class SMBOpen_Data(Structure):
    structure = (
        ('FileNameFormat','"\x04'),
        ('FileName','z'),
    )

class SMBOpenResponse_Parameters(SMBCommand_Parameters):
    structure = (
        ('Fid','<H=0'),
        ('FileAttributes','<H=0'),
        ('LastWriten','<L=0'),
        ('FileSize','<L=0'),
        ('GrantedAccess','<H=0'),
    )

class NTLMDialect(SMBPacket):
    def __init__(self,data=''):
        SMBPacket.__init__(self,data)
        self._selected_dialect = 0
        self._security_mode = 0
        self._max_mpx = 0
        self._max_vc = 0
        self._max_buffer = 0
        self._max_raw = 0
        self._session_key = 0
        self._lsw_capabilities = 0
        self._msw_capabilities = 0
        self._utc_high = 0
        self._utc_low = 0
        self._minutes_utc = 0
        self._encryption_key_len = 0
        self._encryption_key = ''
        self._server_domain = ''
        self._server_name = ''
        if data:
            self._selected_dialect, self._security_mode, self._max_mpx, self._max_vc = unpack('<HBHH',self.get_parameter_words()[:7])
            self._max_buffer,self._max_raw, self._session_key, self._lsw_capabilities, self._msw_capabilities = unpack('<lllHH', self.get_parameter_words()[7:16+7])
            self._utc_low, self._utc_high,self._minutes_utc, self._encryption_key_len = unpack('<LLhB',self.get_parameter_words()[23:34])
            if self._encryption_key_len > 0 and len(self.get_buffer()) >= self._encryption_key_len:
                self._encryption_key = self.get_buffer()[:self._encryption_key_len]
                buf = self.get_buffer() 
                # Look for the server domain offset
                self._server_name = '<Unknown>'
                self._server_domain = '<Unknown>'
                try:
                    if self._lsw_capabilities & 0x3: # is this unicode?
                         offset = self._encryption_key_len
                         if offset & 0x01:
                            offset += 1
                         end = offset
                         while ord(buf[end]) or ord(buf[end+1]):
                             end += 2
                         self._server_domain = unicode(buf[offset:end],'utf_16_le')
                         end += 2
                         offset = end
                         while ord(buf[end]) or ord(buf[end+1]):
                             end += 2
                         self._server_name = unicode(buf[offset:end],'utf_16_le')
                    else:
                         offset = self._encryption_key_len
                         idx1 = string.find(buf,'\0',offset)
                         if idx1 != -1:
                            self._server_domain = buf[offset:idx1]
                            idx2 = string.find(buf, '\0', idx1 + 1)
                            if idx2 != -1:
                               self._server_name = buf[idx1+1:idx2]
                except:
                    pass
            else:
                self._encryption_key = ''
 
    def get_selected_dialect(self):
        return self._selected_dialect
    def get_security_mode(self):
        return self._security_mode
    def get_max_mpx(self):
        return self._max_mpx
    def get_max_vc(self):
        return self._max_vc
    def get_max_buffer(self):
        return self._max_buffer
    def get_max_raw(self):
        return self._max_raw
    def get_session_key(self):
        return self._session_key
    def get_lsw_capabilities(self):
        return self._lsw_capabilities
    def get_msw_capabilities(self):
        return self._msw_capabilities
    def get_utc(self):
        return self._utc_high, self._utc_low
    def get_minutes_utc(self):
        return self._minutes_utc
    def get_encryption_key_len(self):
        return self._encryption_key_len
    def get_encryption_key(self):
        return self._encryption_key
    def get_server_domain(self):
        return self._server_domain
    def get_server_name(self):
        return self._server_name
    def is_auth_mode(self):
        return self._security_mode & SMB.SECURITY_AUTH_MASK
    def is_share_mode(self):
        return self._security_mode & SMB.SECURITY_SHARE_MASK
    def is_rawmode(self):
        return self._lsw_capabilities & SMB.CAP_RAW_MODE
                
                
class SMB:

    # SMB Command Codes
    SMB_COM_CREATE_DIRECTORY = 0x00
    SMB_COM_DELETE_DIRECTORY = 0x01
    SMB_COM_OPEN = 0x02
    SMB_COM_CREATE = 0x03
    SMB_COM_CLOSE = 0x04
    SMB_COM_FLUSH = 0x05
    SMB_COM_DELETE = 0x06
    SMB_COM_RENAME = 0x07
    SMB_COM_QUERY_INFORMATION = 0x08
    SMB_COM_SET_INFORMATION = 0x09
    SMB_COM_READ = 0x0A
    SMB_COM_WRITE = 0x0B
    SMB_COM_LOCK_BYTE_RANGE = 0x0C
    SMB_COM_UNLOCK_BYTE_RANGE = 0x0D
    SMB_COM_CREATE_TEMPORARY = 0x0E
    SMB_COM_CREATE_NEW = 0x0F
    SMB_COM_CHECK_DIRECTORY = 0x10
    SMB_COM_PROCESS_EXIT = 0x11
    SMB_COM_SEEK = 0x12
    SMB_COM_LOCK_AND_READ = 0x13
    SMB_COM_WRITE_AND_UNLOCK = 0x14
    SMB_COM_READ_RAW = 0x1A
    SMB_COM_READ_MPX = 0x1B
    SMB_COM_READ_MPX_SECONDARY = 0x1C
    SMB_COM_WRITE_RAW = 0x1D
    SMB_COM_WRITE_MPX = 0x1E
    SMB_COM_WRITE_MPX_SECONDARY = 0x1F
    SMB_COM_WRITE_COMPLETE = 0x20
    SMB_COM_QUERY_SERVER = 0x21
    SMB_COM_SET_INFORMATION2 = 0x22
    SMB_COM_QUERY_INFORMATION2 = 0x23
    SMB_COM_LOCKING_ANDX = 0x24
    SMB_COM_TRANSACTION = 0x25
    SMB_COM_TRANSACTION_SECONDARY = 0x26
    SMB_COM_IOCTL = 0x27
    SMB_COM_IOCTL_SECONDARY = 0x28
    SMB_COM_COPY = 0x29
    SMB_COM_MOVE = 0x2A
    SMB_COM_ECHO = 0x2B
    SMB_COM_WRITE_AND_CLOSE = 0x2C
    SMB_COM_OPEN_ANDX = 0x2D
    SMB_COM_READ_ANDX = 0x2E
    SMB_COM_WRITE_ANDX = 0x2F
    SMB_COM_NEW_FILE_SIZE = 0x30
    SMB_COM_CLOSE_AND_TREE_DISC = 0x31
    SMB_COM_TRANSACTION2 = 0x32
    SMB_COM_TRANSACTION2_SECONDARY = 0x33
    SMB_COM_FIND_CLOSE2 = 0x34
    SMB_COM_FIND_NOTIFY_CLOSE = 0x35
    # Used by Xenix/Unix 0x60 - 0x6E 
    SMB_COM_TREE_CONNECT = 0x70
    SMB_COM_TREE_DISCONNECT = 0x71
    SMB_COM_NEGOTIATE = 0x72
    SMB_COM_SESSION_SETUP_ANDX = 0x73
    SMB_COM_LOGOFF_ANDX = 0x74
    SMB_COM_TREE_CONNECT_ANDX = 0x75
    SMB_COM_QUERY_INFORMATION_DISK = 0x80
    SMB_COM_SEARCH = 0x81
    SMB_COM_FIND = 0x82
    SMB_COM_FIND_UNIQUE = 0x83
    SMB_COM_FIND_CLOSE = 0x84
    SMB_COM_NT_TRANSACT = 0xA0
    SMB_COM_NT_TRANSACT_SECONDARY = 0xA1
    SMB_COM_NT_CREATE_ANDX = 0xA2
    SMB_COM_NT_CANCEL = 0xA4
    SMB_COM_NT_RENAME = 0xA5
    SMB_COM_OPEN_PRINT_FILE = 0xC0
    SMB_COM_WRITE_PRINT_FILE = 0xC1
    SMB_COM_CLOSE_PRINT_FILE = 0xC2
    SMB_COM_GET_PRINT_QUEUE = 0xC3
    SMB_COM_READ_BULK = 0xD8
    SMB_COM_WRITE_BULK = 0xD9
    SMB_COM_WRITE_BULK_DATA = 0xDA

    # Security Share Mode (Used internally by SMB class)
    SECURITY_SHARE_MASK = 0x01
    SECURITY_SHARE_SHARE = 0x00
    SECURITY_SHARE_USER = 0x01
    
    # Security Auth Mode (Used internally by SMB class)
    SECURITY_AUTH_MASK = 0x02
    SECURITY_AUTH_ENCRYPTED = 0x02
    SECURITY_AUTH_PLAINTEXT = 0x00

    # Raw Mode Mask (Used internally by SMB class. Good for dialect up to and including LANMAN2.1)
    RAW_READ_MASK = 0x01
    RAW_WRITE_MASK = 0x02

    # Capabilities Mask (Used internally by SMB class. Good for dialect NT LM 0.12)
    CAP_RAW_MODE = 0x0001
    CAP_MPX_MODE = 0x0002
    CAP_UNICODE = 0x0004
    CAP_LARGE_FILES = 0x0008
    CAP_EXTENDED_SECURITY = 0x80000000

    # Flags1 Mask
    FLAGS1_PATHCASELESS = 0x08

    # Flags2 Mask
    FLAGS2_LONG_FILENAME = 0x0001
    FLAGS2_USE_NT_ERRORS = 0x4000
    FLAGS2_UNICODE = 0x8000

    def __init__(self, remote_name, remote_host, my_name = None, host_type = nmb.TYPE_SERVER, sess_port = nmb.NETBIOS_SESSION_PORT, timeout=None, UDP = 0):
        # The uid attribute will be set when the client calls the login() method
        self.__uid = 0
        self.__server_os = ''
        self.__server_lanman = ''
        self.__server_domain = ''
        self.__remote_name = string.upper(remote_name)
        self.__is_pathcaseless = 0
        self.__ntlm_dialect = 0
        self.__sess = None

        if timeout==None:
            self.__timeout = 30
        else:
            self.__timeout = timeout
        
        if not my_name:
            my_name = socket.gethostname()
            i = string.find(my_name, '.')
            if i > -1:
                my_name = my_name[:i]

        if UDP:
            self.__sess = nmb.NetBIOSUDPSession(my_name, remote_name, remote_host, host_type, sess_port, timeout)
        else:
            self.__sess = nmb.NetBIOSTCPSession(my_name, remote_name, remote_host, host_type, sess_port, timeout)

            # Initialize values __ntlm_dialect, __is_pathcaseless
            self.__neg_session()

            # If the following assertion fails, then mean that the encryption key is not sent when
            # encrypted authentication is required by the server.
            assert (self.__ntlm_dialect.is_auth_mode() == SMB.SECURITY_AUTH_PLAINTEXT) or (self.__ntlm_dialect.is_auth_mode() == SMB.SECURITY_AUTH_ENCRYPTED and self.__ntlm_dialect.get_encryption_key() and self.__ntlm_dialect.get_encryption_key_len() >= 8)

            # Call login() without any authentication information to setup a session if the remote server
            # is in share mode.
            if self.__ntlm_dialect.is_share_mode() == SMB.SECURITY_SHARE_SHARE:
                self.login('', '')

    def get_remote_name(self):
        return self.__remote_name
    
    def set_timeout(self, timeout):
        self.__timeout = timeout
        
    def __del__(self):
        if self.__sess:
            self.__sess.close()

    def __decode_smb(self, data):
        _, cmd, err_class, _, err_code, flags1, flags2, _, tid, pid, uid, mid, wcount = unpack('<4sBBBHBH12sHHHHB', data[:33])
        param_end = 33 + wcount * 2
        return cmd, err_class, err_code, flags1, flags2, tid, uid, mid, data[33:param_end], data[param_end + 2:]

    def recvSMB(self):
        r = self.__sess.recv_packet(self.__timeout)
        return NewSMBPacket(data = r.get_trailer())
    
    def recv_packet(self):
        r = self.__sess.recv_packet(self.__timeout)
        return SMBPacket(r.get_trailer())
    
    def __decode_trans(self, params, data):
        totparamcnt, totdatacnt, _, paramcnt, paramoffset, paramds, datacnt, dataoffset, datads, setupcnt = unpack('<HHHHHHHHHB', params[:19])
        if paramcnt + paramds < totparamcnt or datacnt + datads < totdatacnt:
            has_more = 1
        else:
            has_more = 0
        paramoffset = paramoffset - 55 - setupcnt * 2
        dataoffset = dataoffset - 55 - setupcnt * 2
        return has_more, params[20:20 + setupcnt * 2], data[paramoffset:paramoffset + paramcnt], data[dataoffset:dataoffset + datacnt]

    def sendSMB(self,smb):
        smb['Uid'] = self.__uid
        smb['Pid'] = os.getpid()
        self.__sess.send_packet(str(smb))

    def send_smb(self,s):
        s.set_uid(self.__uid)
        s.set_pid(os.getpid())
        self.__sess.send_packet(s.rawData())

    def __send_smb_packet(self, cmd, flags, flags2, tid, mid, params = '', data = ''):
        smb = NewSMBPacket()
        smb['Flags'] = flags
        smb['Flags2'] = flags2
        smb['Tid'] = tid
        smb['Mid'] = mid
        cmd = SMBCommand(cmd)
        smb.addCommand(cmd)

        cmd['Parameters'] = params
        cmd['Data'] = data
        self.sendSMB(smb)

    def isValidAnswer(self, s, cmd):
        while 1:
            if s.rawData():
                if s.get_command() == cmd:
                    if s.get_error_class() == 0x00 and s.get_error_code() == 0x00:
                        return 1
                    else:
                        raise SessionError, ( "SMB Library Error", s.get_error_class(), s.get_error_code())
                else:
                    break
#                    raise SessionError("Invalid command received. %x" % cmd)
#            s=self.recv_packet(None)   
        return 0
    
    def __neg_session(self):
        s = SMBPacket()
        s.set_command(SMB.SMB_COM_NEGOTIATE)
        s.set_buffer('\x02NT LM 0.12\x00')
        self.send_smb(s)

        while 1:
            s = self.recv_packet()
            if self.isValidAnswer(s,SMB.SMB_COM_NEGOTIATE):
                self.__ntlm_dialect = NTLMDialect(s.rawData())
                if self.__ntlm_dialect.get_selected_dialect() == 0xffff:
                    raise UnsupportedFeature,"Remote server does not know NT LM 0.12"

                #NL LM 0.12 dialect selected
                if self.__ntlm_dialect.get_lsw_capabilities() & SMB.CAP_EXTENDED_SECURITY:
                    raise UnsupportedFeature, "This version of pysmb does not support extended security validation. Please file a request for it."

                self.__is_pathcaseless = s.get_flags() & SMB.FLAGS1_PATHCASELESS

                return 1
            else:
                return 0


    def tree_connect(self, path, password = '', service = SERVICE_ANY):
        # return 0x800
        if password:
            # Password is only encrypted if the server passed us an "encryption" during protocol dialect
            if self.__ntlm_dialect.get_encryption_key():
                # this code is untested
                password = self.get_ntlmv1_response(ntlm.compute_lmhash(password))

        if not unicode_support:
            if unicode_convert:
                path = str(path)
            else:
                raise Except('SMB: Can\t conver path from unicode!')

        smb = NewSMBPacket()
        smb['Flags1']  = 8
        
        treeConnect = SMBCommand(SMB.SMB_COM_TREE_CONNECT)
        treeConnect['Parameters'] = SMBTreeConnect_Parameters()
        treeConnect['Data']       = SMBTreeConnect_Data()
        treeConnect['Data']['Path'] = path.upper()
        treeConnect['Data']['Password'] = password
        treeConnect['Data']['Service'] = service

        smb.addCommand(treeConnect)

        self.sendSMB(smb)

        while 1:
            smb = self.recvSMB()
            if smb.isValidAnswer(SMB.SMB_COM_TREE_CONNECT):
                # XXX Here we are ignoring the rest of the response
                return smb['Tid']
            return smb['Tid']

    def tree_connect_andx(self, path, password = None, service = SERVICE_ANY):
        if password:
            # Password is only encrypted if the server passed us an "encryption" during protocol dialect
            if self.__ntlm_dialect.get_encryption_key():
                # this code is untested
                password = self.get_ntlmv1_response(ntlm.compute_lmhash(password))
        else:
            password = '\x00'

        if not unicode_support:
            if unicode_convert:
                path = str(path)
            else:
                raise Except('SMB: Can\t convert path from unicode!')

        smb = NewSMBPacket()
        smb['Flags1']  = 8
        
        treeConnect = SMBCommand(SMB.SMB_COM_TREE_CONNECT_ANDX)
        treeConnect['Parameters'] = SMBTreeConnectAndX_Parameters()
        treeConnect['Data']       = SMBTreeConnectAndX_Data()
        treeConnect['Parameters']['PasswordLength'] = len(password)
        treeConnect['Data']['Password'] = password
        treeConnect['Data']['Path'] = path.upper()
        treeConnect['Data']['Service'] = service

        smb.addCommand(treeConnect)

        # filename = "\PIPE\epmapper"

        # ntCreate = SMBCommand(SMB.SMB_COM_NT_CREATE_ANDX)
        # ntCreate['Parameters'] = SMBNtCreateAndX_Parameters()
        # ntCreate['Data']       = SMBNtCreateAndX_Data()
        # ntCreate['Parameters']['FileNameLength'] = len(filename)
        # ntCreate['Parameters']['CreateFlags'] = 0
        # ntCreate['Parameters']['AccessMask'] = 0x3
        # ntCreate['Parameters']['CreateOptions'] = 0x0
        # ntCreate['Data']['FileName'] = filename

        # smb.addCommand(ntCreate)
        self.sendSMB(smb)

        while 1:
            smb = self.recvSMB()
            if smb.isValidAnswer(SMB.SMB_COM_TREE_CONNECT_ANDX):
                # XXX Here we are ignoring the rest of the response
                return smb['Tid']
            return smb['Tid']

    # backwars compatibility
    connect_tree = tree_connect_andx

    def get_server_name(self):
        return self.__ntlm_dialect.get_server_name()

    def get_session_key(self):
        return self.__ntlm_dialect.get_session_key()

    def get_server_time(self):
        high, low = self.__ntlm_dialect.get_utc()
        min = self.__ntlm_dialect.get_minutes_utc()
        return samr.display_time(high, low, min)

    def disconnect_tree(self, tid):
        smb = NewSMBPacket()
        smb['Tid']  = tid
        smb.addCommand(SMBCommand(SMB.SMB_COM_TREE_DISCONNECT))
        self.sendSMB(smb)

        smb = self.recvSMB()

    def open(self, tid, filename, open_mode, desired_access):
        smb = NewSMBPacket()
        smb['Flags']  = 8
        smb['Flags2'] = SMB.FLAGS2_LONG_FILENAME
        smb['Tid']    = tid

        openFile = SMBCommand(SMB.SMB_COM_OPEN)
        openFile['Parameters'] = SMBOpen_Parameters()
        openFile['Parameters']['DesiredAccess']    = desired_access
        openFile['Parameters']['OpenMode']         = open_mode
        openFile['Parameters']['SearchAttributes'] = ATTR_READONLY | ATTR_HIDDEN | ATTR_ARCHIVE
        openFile['Data']       = SMBOpen_Data()
        openFile['Data']['FileName'] = filename
        
        smb.addCommand(openFile)

        self.sendSMB(smb)
        
        smb = self.recvSMB()
        if smb.isValidAnswer(SMB.SMB_COM_OPEN):
            # XXX Here we are ignoring the rest of the response
            openFileResponse   = SMBCommand(smb['Data'][0])
            openFileParameters = SMBOpenResponse_Parameters(openFileResponse['Parameters'])

            return (
                openFileParameters['Fid'],
                openFileParameters['FileAttributes'],
                openFileParameters['LastWriten'],
                openFileParameters['FileSize'],
                openFileParameters['GrantedAccess'],
            )
        
    def open_andx(self, tid, filename, open_mode, desired_access):
        smb = NewSMBPacket()
        smb['Flags']  = 8
        smb['Flags2'] = SMB.FLAGS2_LONG_FILENAME
        smb['Tid']    = tid

        openFile = SMBCommand(SMB.SMB_COM_OPEN_ANDX)
        openFile['Parameters'] = SMBOpenAndX_Parameters()
        openFile['Parameters']['DesiredAccess']    = desired_access
        openFile['Parameters']['OpenMode']         = open_mode
        openFile['Parameters']['SearchAttributes'] = ATTR_READONLY | ATTR_HIDDEN | ATTR_ARCHIVE
        openFile['Data']       = SMBOpenAndX_Data()
        openFile['Data']['FileName'] = filename
        
        smb.addCommand(openFile)

        self.sendSMB(smb)
        
        smb = self.recvSMB()
        if smb.isValidAnswer(SMB.SMB_COM_OPEN_ANDX):
            # XXX Here we are ignoring the rest of the response
            openFileResponse   = SMBCommand(smb['Data'][0])
            openFileParameters = SMBOpenAndXResponse_Parameters(openFileResponse['Parameters'])

            return (
                openFileParameters['Fid'],
                openFileParameters['FileAttributes'],
                openFileParameters['LastWriten'],
                openFileParameters['FileSize'],
                openFileParameters['GrantedAccess'],
                openFileParameters['FileType'],
                openFileParameters['IPCState'],
                openFileParameters['Action'],
                openFileParameters['ServerFid'],
            )
        
    def close(self, tid, fid):
        s = SMBPacket()
        s.set_command(SMB.SMB_COM_CLOSE)
        s.set_tid(tid)
        s.set_parameter_words(pack('<HL', fid, 0))
        self.send_smb(s)
        s = self.recv_packet()

    def send_trans(self, tid, setup, name, param, data, noAnswer = 0):
        t = TRANSHeader()
        s = SMBPacket()
        s.set_tid(tid)
        s.set_command(SMB.SMB_COM_TRANSACTION)
        s.set_flags(self.__is_pathcaseless)
        s.set_flags2(SMB.FLAGS2_LONG_FILENAME)
        t.set_setup(setup)
        t.set_name(name)
        t.set_parameters(param)
        t.set_data(data)
        t.set_max_param_count(1024) # Saca esto y se muere remotamente
        t.set_max_data_count(65504) # Saca esto y se muere remotamente
        if noAnswer:
            t.set_flags(TRANS_NO_RESPONSE)
        s.set_parameter_words(t.get_rawParameters())
        s.set_buffer(t.rawData())
        self.send_smb(s)

    def __trans(self, tid, setup, name, param, data):
        data_len = len(data)
        name_len = len(name)
        param_len = len(param)
        setup_len = len(setup)

        assert setup_len & 0x01 == 0

        param_offset = name_len + setup_len + 63
        data_offset = param_offset + param_len
            
        self.__send_smb_packet(SMB.SMB_COM_TRANSACTION, self.__is_pathcaseless, SMB.FLAGS2_LONG_FILENAME, tid, 0, pack('<HHHHBBHLHHHHHBB', param_len, data_len, 1024, 65504, 0, 0, 0, 0, 0, param_len, param_offset, data_len, data_offset, setup_len / 2, 0) + setup, name + param + data)

    def trans2(self, tid, setup, name, param, data):
        data_len = len(data)
        name_len = len(name)
        param_len = len(param)
        setup_len = len(setup)

        assert setup_len & 0x01 == 0

        param_offset = name_len + setup_len + 63
        data_offset = param_offset + param_len
            
        self.__send_smb_packet(SMB.SMB_COM_TRANSACTION2, self.__is_pathcaseless, SMB.FLAGS2_LONG_FILENAME, tid, 0, pack('<HHHHBBHLHHHHHBB', param_len, data_len, 1024, self.__ntlm_dialect.get_max_buffer(), 0, 0, 0, 0, 0, param_len, param_offset, data_len, data_offset, setup_len / 2, 0) + setup, name  + param + data)

    def query_file_info(self, tid, fid):
        self.trans2(tid, '\x07\x00', '\x00', pack('<HH', fid, 0x107), '')

        while 1:
            s = self.recv_packet()
            if self.isValidAnswer(s,SMB.SMB_COM_TRANSACTION2):
                f1, f2 = unpack('<LL', s.get_buffer()[53:53+8])
                return (f2 & 0xffffffffL) << 32 | f1

    def __nonraw_retr_file(self, tid, fid, offset, datasize, callback):
        max_buf_size = self.__ntlm_dialect.get_max_buffer() & ~0x3ff  # Read in multiple KB blocks
        read_offset = offset
        while read_offset < datasize:
            data = self.read_andx(tid, fid, read_offset, max_buf_size)

            callback(data)
            read_offset += len(data)

    def __raw_retr_file(self, tid, fid, offset, datasize, callback):
        max_buf_size = self.__ntlm_dialect.get_max_buffer() & ~0x3ff  # Write in multiple KB blocks
        read_offset = offset
        while read_offset < datasize:
            data = self.read_raw(tid, fid, read_offset, 0xffff)
            if not data:
                # No data returned. Need to send SMB_COM_READ_ANDX to find out what is the error.
                data = self.read_andx(tid, fid, read_offset, max_buf_size)

            callback(data)
            read_offset += len(data)

    def __nonraw_stor_file(self, tid, fid, offset, datasize, callback):
        max_buf_size = self.__ntlm_dialect.get_max_buffer() & ~0x3ff  # Write in multiple KB blocks
        write_offset = offset
        while 1:
            data = callback(max_buf_size)
            if not data:
                break
            
            self.__send_smb_packet(SMB.SMB_COM_WRITE_ANDX, 0, 0, tid, 0, pack('<BBHHLLHHHHH', 0xff, 0, 0, fid, write_offset, 0, 0, 0, 0, len(data), 59), data)
            
            while 1:
                s = self.recv_packet()
                if self.isValidAnswer(s,SMB.SMB_COM_WRITE_ANDX):
                    offset = unpack('<H', s.get_parameter_words()[2:4])[0]
                    write_offset = write_offset + unpack('<H', s.get_parameter_words()[4:6])[0]
                    break

    def __raw_stor_file(self, tid, fid, offset, datasize, callback):
        write_offset = offset
        while 1:
            read_data = callback(65535)
            if not read_data:
                break
            read_len = len(read_data)
            self.__send_smb_packet(SMB.SMB_COM_WRITE_RAW, 0, 0, tid, 0, pack('<HHHLLHLHH', fid, read_len, 0, write_offset, 0, 0, 0, 0, 59), '')
            while 1:
                s = self.recv_packet()
                if self.isValidAnswer(s,SMB.SMB_COM_WRITE_RAW):
                    self.__sess.send_packet(read_data)
                    write_offset = write_offset + read_len
                    break

    def __browse_servers(self, server_flags, container_type, domain):
        tid = self.tree_connect_andx('\\\\' + self.__remote_name + '\\IPC$')

        buf = StringIO()
        try:
            if server_flags & 0x80000000:
                self.__trans(tid, '', '\\PIPE\\LANMAN\x00', '\x68\x00WrLehDz\x00' + 'B16BBDz\x00\x01\x00\xff\xff\x00\x00\x00\x80', '')
            else:
                self.__trans(tid, '', '\\PIPE\\LANMAN\x00', '\x68\x00WrLehDz\x00' + 'B16BBDz\x00\x01\x00\xff\xff' + pack('<l', server_flags)  + domain + '\x00', '')
                
            servers = [ ]
            entry_count = 0
            while 1:
                s = self.recv_packet()
                if self.isValidAnswer(s,SMB.SMB_COM_TRANSACTION):
                    has_more, _, transparam, transdata = self.__decode_trans(s.get_parameter_words(), s.get_buffer())
                    if not entry_count:
                        status, convert, entry_count, avail_entry = unpack('<HHHH', transparam[:8])
                        if status and status != 234:  # status 234 means have more data
                            raise SessionError, ( 'Browse domains failed. (ErrClass: %d and ErrCode: %d)' % ( 0x80, status ), 0x80, status )
                    buf.write(transdata)

                    if not has_more:
                        server_data = buf.getvalue()

                        for i in range(0, entry_count):
                            server, _, server_type, comment_offset = unpack('<16s2sll', server_data[i * 26:i * 26 + 26])
                            idx = string.find(server, '\0')
                            idx2 = string.find(server_data, '\0', comment_offset)
                            if idx < 0:
                                server = server[:idx]
                            servers.append(container_type(server, server_type, server_data[comment_offset:idx2]))
                        return servers
        finally:
            buf.close()
            self.disconnect_tree(tid)            

    def get_server_domain(self):
        return self.__server_domain

    def get_server_os(self):
        return self.__server_os

    def get_server_lanman(self):
        return self.__server_lanman

    def is_login_required(self):
        # Login is required if share mode is user. Otherwise only public services or services in share mode
        # are allowed.
        return self.__ntlm_dialect.is_share_mode() == SMB.SECURITY_SHARE_USER

    def get_ntlmv1_response(self, key):
        challenge = self.__ntlm_dialect.get_encryption_key()
        return ntlm.get_ntlmv1_response(key, challenge)

    def hmac_md5(self, key, data):
        import POW
        h = POW.Hmac(POW.MD5_DIGEST, key)
        h.update(data)
        result = h.mac()
        return result

    def get_ntlmv2_response(self, hash):
        """
        blob = RandomBytes( blobsize );
        data = concat( ServerChallenge, 8, blob, blobsize );
        hmac = hmac_md5( v2hash, 16, data, (8 + blobsize) );
        v2resp = concat( hmac, 16, blob, blobsize );
        """
        return ''

    def login(self, user, password, domain = '', lmhash = '', nthash = ''):
        if password != '' or (password == '' and lmhash == '' and nthash == ''):
            self.login_plaintext_password(user, password)
        elif lmhash != '' or nthash != '':
            self.login_pass_the_hash(user, lmhash, nthash, domain)

    def _login(self, user, pwd_ansi, pwd_unicode, domain = ''):
        smb = NewSMBPacket()
        smb['Flags1']  = 8
        
        sessionSetup = SMBCommand(SMB.SMB_COM_SESSION_SETUP_ANDX)
        sessionSetup['Parameters'] = SMBSessionSetupAndX_Parameters()
        sessionSetup['Data']       = SMBSessionSetupAndX_Data()

        sessionSetup['Parameters']['MaxBuffer']        = 65535
        sessionSetup['Parameters']['MaxMpxCount']      = 2
        sessionSetup['Parameters']['VCNumber']         = os.getpid()
        sessionSetup['Parameters']['SessionKey']       = self.__ntlm_dialect.get_session_key()
        sessionSetup['Parameters']['AnsiPwdLength']    = len(pwd_ansi)
        sessionSetup['Parameters']['UnicodePwdLength'] = len(pwd_unicode)
        sessionSetup['Parameters']['Capabilities']     = SMB.CAP_RAW_MODE

        sessionSetup['Data']['AnsiPwd']       = pwd_ansi
        sessionSetup['Data']['UnicodePwd']    = pwd_unicode
        sessionSetup['Data']['Account']       = str(user)
        sessionSetup['Data']['PrimaryDomain'] = str(domain)
        sessionSetup['Data']['NativeOS']      = str(os.name)
        sessionSetup['Data']['NativeLanMan']  = 'pysmb'

        smb.addCommand(sessionSetup)

        self.sendSMB(smb)

        smb = self.recvSMB()
        if smb.isValidAnswer(SMB.SMB_COM_SESSION_SETUP_ANDX):
            # We will need to use this uid field for all future requests/responses
            self.__uid = smb['Uid']
            sessionResponse   = SMBCommand(smb['Data'][0])
            sessionParameters = SMBSessionSetupAndXResponse_Parameters(sessionResponse['Parameters'])
            sessionData       = SMBSessionSetupAndXResponse_Data(flags = smb['Flags2'], data = sessionResponse['Data'])

            self.__server_os     = sessionData['NativeOS']
            self.__server_lanman = sessionData['NativeLanMan']
            self.__server_domain = sessionData['PrimaryDomain']

            return 1
        else: raise Exception('Error: Could not login successfully')

    def read(self, tid, fid, offset=0, max_size = None, wait_answer=1):
        if not max_size:
            max_size = self.__ntlm_dialect.get_max_buffer() # Read in multiple KB blocks
        
        # max_size is not working, because although it would, the server returns an error (More data avail)

        smb = NewSMBPacket()
        smb['Flags1'] = 0x18
        smb['Flags2'] = 0
        smb['Tid']    = tid

        read = SMBCommand(SMB.SMB_COM_READ)
        
        read['Parameters'] = SMBRead_Parameters()
        read['Parameters']['Fid'] = fid
        read['Parameters']['Offset'] = offset
        read['Parameters']['Count'] = max_size

        smb.addCommand(read)

        if wait_answer:
            answer = ''
            while 1:
                self.sendSMB(smb)
                ans = self.recvSMB()

                if ans.isValidAnswer(SMB.SMB_COM_READ):
                    readResponse   = SMBCommand(ans['Data'][0])
                    readParameters = SMBReadResponse_Parameters(readResponse['Parameters'])
                    readData       = SMBReadResponse_Data(readResponse['Data'])

                    return readData['Data']

        return None

    def read_andx(self, tid, fid, offset=0, max_size = None, wait_answer=1):
        if not max_size:
            max_size = self.__ntlm_dialect.get_max_buffer() # Read in multiple KB blocks
        
        # max_size is not working, because although it would, the server returns an error (More data avail)

        smb = NewSMBPacket()
        smb['Flags1'] = 0x18
        smb['Flags2'] = 0
        smb['Tid']    = tid

        readAndX = SMBCommand(SMB.SMB_COM_READ_ANDX)
        
        readAndX['Parameters'] = SMBReadAndX_Parameters()
        readAndX['Parameters']['Fid'] = fid
        readAndX['Parameters']['Offset'] = offset
        readAndX['Parameters']['MaxCount'] = max_size

        smb.addCommand(readAndX)

        if wait_answer:
            answer = ''
            while 1:
                self.sendSMB(smb)
                ans = self.recvSMB()

                if ans.isValidAnswer(SMB.SMB_COM_READ_ANDX):
                    # XXX Here we are only using a few fields from the response
                    readAndXResponse   = SMBCommand(ans['Data'][0])
                    readAndXParameters = SMBReadAndXResponse_Parameters(readAndXResponse['Parameters'])

                    offset = readAndXParameters['DataOffset']
                    count = readAndXParameters['DataCount']+0x10000*readAndXParameters['DataCount_Hi']
                    answer += str(ans)[offset:offset+count]
                    if not ans.isMoreData():
                        return answer
                    max_size = min(max_size, readAndXParameters['Remaining'])
                    readAndX['Parameters']['Offset'] += count                      # XXX Offset is not important (apparently)

        return None

    def read_raw(self, tid, fid, offset=0, max_size = None, wait_answer=1):
        if not max_size:
            max_size = self.__ntlm_dialect.get_max_buffer() # Read in multiple KB blocks
        
        # max_size is not working, because although it would, the server returns an error (More data avail)

        smb = NewSMBPacket()
        smb['Flags1'] = 0x18
        smb['Flags2'] = 0
        smb['Tid']    = tid

        readRaw = SMBCommand(SMB.SMB_COM_READ_RAW)
        
        readRaw['Parameters'] = SMBReadRaw_Parameters()
        readRaw['Parameters']['Fid'] = fid
        readRaw['Parameters']['Offset'] = offset
        readRaw['Parameters']['MaxCount'] = max_size

        smb.addCommand(readRaw)

        self.sendSMB(smb)
        if wait_answer:
            data = self.__sess.recv_packet(self.__timeout).get_trailer()
            if not data:
                # If there is no data it means there was an error
                data = self.read_andx(tid, fid, offset, max_size)
            return data

        return None

    def write(self,tid,fid,data, offset = 0, wait_answer=1):
        smb = NewSMBPacket()
        smb['Flags1'] = 0x18
        smb['Flags2'] = 0
        smb['Tid']    = tid

        write = SMBCommand(SMB.SMB_COM_WRITE)
        smb.addCommand(write)
        
        write['Parameters'] = SMBWrite_Parameters()
        write['Data'] = SMBWrite_Data()
        write['Parameters']['Fid'] = fid
        write['Parameters']['Count'] = len(data)
        write['Parameters']['Offset'] = offset
        write['Parameters']['Remaining'] = len(data)
        write['Data']['Data'] = data

        self.sendSMB(smb)
                
        if wait_answer:
            smb = self.recvSMB()
            if smb.isValidAnswer(SMB.SMB_COM_WRITE):
                return smb
        return None

    def write_andx(self,tid,fid,data, offset = 0, wait_answer=1):
        smb = NewSMBPacket()
        smb['Flags1'] = 0x18
        smb['Flags2'] = 0
        smb['Tid']    = tid

        writeAndX = SMBCommand(SMB.SMB_COM_WRITE_ANDX)
        smb.addCommand(writeAndX)
        
        writeAndX['Parameters'] = SMBWriteAndX_Parameters()
        writeAndX['Parameters']['Fid'] = fid
        writeAndX['Parameters']['Offset'] = offset
        writeAndX['Parameters']['WriteMode'] = 8
        writeAndX['Parameters']['Remaining'] = len(data)
        writeAndX['Parameters']['DataLength'] = len(data)
        writeAndX['Parameters']['DataOffset'] = len(smb)    # this length already includes the parameter
        writeAndX['Data'] = data

        self.sendSMB(smb)
                
        if wait_answer:
            smb = self.recvSMB()
            if smb.isValidAnswer(SMB.SMB_COM_WRITE_ANDX):
                return smb
        return None

    def write_raw(self,tid,fid,data, offset = 0, wait_answer=1):
        smb = NewSMBPacket()
        smb['Flags1'] = 0x18
        smb['Flags2'] = 0
        smb['Tid']    = tid

        writeRaw = SMBCommand(SMB.SMB_COM_WRITE_RAW)
        smb.addCommand(writeRaw)
        
        writeRaw['Parameters'] = SMBWriteRaw_Parameters()
        writeRaw['Parameters']['Fid'] = fid
        writeRaw['Parameters']['Offset'] = offset
        writeRaw['Parameters']['Count'] = len(data)
        writeRaw['Parameters']['DataLength'] = 0
        writeRaw['Parameters']['DataOffset'] = 0

        self.sendSMB(smb)
        self.__sess.send_packet(data)
                
        if wait_answer:
            smb = self.recvSMB()
            if smb.isValidAnswer(SMB.SMB_COM_WRITE_RAW):
                return smb
        return None

    def TransactNamedPipe(self, tid, fid, data = '', noAnswer = 0, waitAnswer = 1, offset = 0):
        self.send_trans(tid,pack('<HH', 0x26, fid),'\\PIPE\\\x00','',data, noAnswer = noAnswer)

        if noAnswer or not waitAnswer:
            return

        s = self.recv_packet()
        if self.isValidAnswer(s,SMB.SMB_COM_TRANSACTION):
            trans = TRANSHeader(s.get_parameter_words(), s.get_buffer())
            return trans.get_data()

        return None

        

    def nt_create_andx(self,tid,filename):
        smb = NewSMBPacket()
        smb['Flags1'] = 0x18
        smb['Flags2'] = SMB.FLAGS2_LONG_FILENAME
        smb['Tid']    = tid
        
        ntCreate = SMBCommand(SMB.SMB_COM_NT_CREATE_ANDX)
        ntCreate['Parameters'] = SMBNtCreateAndX_Parameters()
        ntCreate['Data']       = SMBNtCreateAndX_Data()
        ntCreate['Parameters']['FileNameLength'] = len(filename)
        ntCreate['Parameters']['CreateFlags'] = 0x16
        ntCreate['Parameters']['AccessMask'] = 0x2019f
        ntCreate['Parameters']['CreateOptions'] = 0x40

        ntCreate['Data']['FileName'] = filename

        smb.addCommand(ntCreate)

        self.sendSMB(smb)

        while 1:
            smb = self.recvSMB()
            if smb.isValidAnswer(SMB.SMB_COM_NT_CREATE_ANDX):
                # XXX Here we are ignoring the rest of the response
                ntCreateResponse   = SMBCommand(smb['Data'][0])
                ntCreateParameters = SMBNtCreateAndXResponse_Parameters(ntCreateResponse['Parameters'])

                return ntCreateParameters['Fid']

    def login_pass_the_hash(self, user, lmhash, nthash, domain = ''):
        if len(lmhash) % 2:     lmhash = '0%s' % lmhash
        if len(nthash) % 2:     nthash = '0%s' % nthash

        if lmhash: lmhash = self.get_ntlmv1_response(a2b_hex(lmhash))
        if nthash: nthash = self.get_ntlmv1_response(a2b_hex(nthash))

        self._login(user, lmhash, nthash, domain)

    def login_plaintext_password(self, name, password, domain = ''):
        # Password is only encrypted if the server passed us an "encryption key" during protocol dialect negotiation
        if password and self.__ntlm_dialect.get_encryption_key():
            lmhash = ntlm.compute_lmhash(password)
            nthash = ntlm.compute_nthash(password)
            lmhash = self.get_ntlmv1_response(lmhash)
            nthash = self.get_ntlmv1_response(nthash)
        else:
            lmhash = password
            nthash = ''
        self._login(name, lmhash, nthash, domain)

    def logoff(self):
        s = SMBPacket()
        s.set_command(SMB.SMB_COM_LOGOFF_ANDX)
        s.set_parameter_words('\xff\x00\x00\x00')
        self.send_smb(s)
        s = self.recv_packet()

    def list_shared(self):
        tid = self.tree_connect_andx('\\\\' + self.__remote_name + '\\IPC$')

        buf = StringIO()
        try:
            self.send_trans(tid, '', '\\PIPE\\LANMAN\0', '\x00\x00WrLeh\0B13BWz\0\x01\x00\xe0\xff', '')
            numentries = 0
            share_list = [ ]
            while 1:
                s = self.recv_packet()
                if self.isValidAnswer(s,SMB.SMB_COM_TRANSACTION):
                    has_more, _, transparam, transdata = self.__decode_trans(s.get_parameter_words(), s.get_buffer())
                    if not numentries:
                        status, data_offset, numentries = unpack('<HHH', transparam[:6])
                    buf.write(transdata)

                    if not has_more:
                        share_data = buf.getvalue()
                        offset = 0
                        for i in range(0, numentries):
                            name = share_data[offset:string.find(share_data, '\0', offset)]
                            type, commentoffset = unpack('<HH', share_data[offset + 14:offset + 18])
                            comment = share_data[commentoffset-data_offset:share_data.find('\0', commentoffset-data_offset)]
                            offset = offset + 20
                            share_list.append(SharedDevice(name, type, comment))
                        return share_list
        finally:
            buf.close()
            self.disconnect_tree(tid)

    def list_path(self, service, path = '*', password = None):
        path = string.replace(path, '/', '\\')

        tid = self.tree_connect_andx('\\\\' + self.__remote_name + '\\' + service, password)
        try:
            self.trans2(tid, '\x01\x00', '\x00', '\x16\x00\x00\x02\x06\x00\x04\x01\x00\x00\x00\x00' + path + '\x00', '')

            while 1:
                s = self.recv_packet()
                if self.isValidAnswer(s,SMB.SMB_COM_TRANSACTION2):
                    has_more, _, transparam, transdata = self.__decode_trans(s.get_parameter_words(), s.get_buffer())
                    sid, searchcnt, eos, erroffset, lastnameoffset = unpack('<HHHHH', transparam)
                    files = [ ]
                    offset = 0
                    data_len = len(transdata)
                    while offset < data_len:
                        nextentry, fileindex, lowct, highct, lowat, highat, lowmt, highmt, lowcht, hightcht, loweof, higheof, lowsz, highsz, attrib, longnamelen, easz, shortnamelen = unpack('<lL12LLlLB', transdata[offset:offset + 69])
                        files.append(SharedFile(highct << 32 | lowct, highat << 32 | lowat, highmt << 32 | lowmt, higheof << 32 | loweof, highsz << 32 | lowsz, attrib, transdata[offset + 70:offset + 70 + shortnamelen], transdata[offset + 94:offset + 94 + longnamelen]))
                        offset = offset + nextentry
                        if not nextentry:
                            break
                    return files
        finally:
            self.disconnect_tree(tid)

    def retr_file(self, service, filename, callback, mode = SMB_O_OPEN, offset = 0, password = None):
        filename = string.replace(filename, '/', '\\')

        fid = -1
        tid = self.tree_connect_andx('\\\\' + self.__remote_name + '\\' + service, password)
        try:
            fid, attrib, lastwritetime, datasize, grantedaccess, filetype, devicestate, action, serverfid = self.open_andx(tid, filename, mode, SMB_ACCESS_READ | SMB_SHARE_DENY_WRITE)

            if not datasize:
                datasize = self.query_file_info(tid, fid)

            if self.__ntlm_dialect.is_rawmode():
                self.__raw_retr_file(tid, fid, offset, datasize, callback)
            else:
                self.__nonraw_retr_file(tid, fid, offset, datasize, callback)
        finally:
            if fid >= 0:
                self.close(tid, fid)
            self.disconnect_tree(tid)

    def stor_file(self, service, filename, callback, mode = SMB_O_CREAT | SMB_O_TRUNC, offset = 0, password = None):
        filename = string.replace(filename, '/', '\\')

        fid = -1
        tid = self.tree_connect_andx('\\\\' + self.__remote_name + '\\' + service, password)
        try:
            fid, attrib, lastwritetime, datasize, grantedaccess, filetype, devicestate, action, serverfid = self.open_andx(tid, filename, mode, SMB_ACCESS_WRITE | SMB_SHARE_DENY_WRITE)
            
            # If the max_transmit buffer size is more than 16KB, upload process using non-raw mode is actually
            # faster than using raw-mode.
            if self.__ntlm_dialect.get_max_buffer() < 16384 and self.__ntlm_dialect.is_rawmode():
                # Once the __raw_stor_file returns, fid is already closed
                self.__raw_stor_file(tid, fid, offset, datasize, callback)
                fid = -1
            else:
                self.__nonraw_stor_file(tid, fid, offset, datasize, callback)
        finally:
            if fid >= 0:
                self.close(tid, fid)
            self.disconnect_tree(tid)

    def stor_file_nonraw(self, service, filename, callback, mode = SMB_O_CREAT | SMB_O_TRUNC, offset = 0, password = None):
        filename = string.replace(filename, '/', '\\')

        fid = -1
        tid = self.tree_connect_andx('\\\\' + self.__remote_name + '\\' + service, password)
        try:
            fid, attrib, lastwritetime, datasize, grantedaccess, filetype, devicestate, action, serverfid = self.open_andx(tid, filename, mode, SMB_ACCESS_WRITE | SMB_SHARE_DENY_WRITE)
            self.__nonraw_stor_file(tid, fid, offset, datasize, callback)
        finally:
            if fid >= 0:
                self.close(tid, fid)
            self.disconnect_tree(tid)

    def copy(self, src_service, src_path, dest_service, dest_path, callback = None, write_mode = SMB_O_CREAT | SMB_O_TRUNC, src_password = None, dest_password = None):
        dest_path = string.replace(dest_path, '/', '\\')
        src_path = string.replace(src_path, '/', '\\')
        src_tid = self.tree_connect_andx('\\\\' + self.__remote_name + '\\' + src_service, src_password)

        dest_tid = -1
        try:
            if src_service == dest_service:
                dest_tid = src_tid
            else:
                dest_tid = self.tree_connect_andx('\\\\' + self.__remote_name + '\\' + dest_service, dest_password)
            
            dest_fid = self.open_andx(dest_tid, dest_path, write_mode, SMB_ACCESS_WRITE | SMB_SHARE_DENY_WRITE)[0]
            src_fid, _, _, src_datasize, _, _, _, _, _ = self.open_andx(src_tid, src_path, SMB_O_OPEN, SMB_ACCESS_READ | SMB_SHARE_DENY_WRITE)

            if callback:
                callback(0, src_datasize)

            max_buf_size = (self.__ntlm_dialect.get_max_buffer() >> 10) << 10
            read_offset = 0
            write_offset = 0
            while read_offset < src_datasize:
                self.__send_smb_packet(SMB.SMB_COM_READ_ANDX, 0, 0, src_tid, 0, pack('<BBHHLHHLH', 0xff, 0, 0, src_fid, read_offset, max_buf_size, max_buf_size, 0, 0), '')
                while 1:
                    s = self.recv_packet()
                    if self.isValidAnswer(s,SMB.SMB_COM_READ_ANDX):
                        offset = unpack('<H', s.get_parameter_words()[2:4])[0]
                        data_len, dataoffset = unpack('<HH', s.get_parameter_words()[10+offset:14+offset])
                        if data_len == len(d):
                            self.__send_smb_packet(SMB.SMB_COM_WRITE_ANDX, 0, 0, dest_tid, 0, pack('<BBHHLLHHHHH', 0xff, 0, 0, dest_fid, write_offset, 0, 0, 0, 0, data_len, 59), d)
                        else:
                            self.__send_smb_packet(SMB.SMB_COM_WRITE_ANDX, 0, 0, dest_tid, 0, pack('<BBHHLLHHHHH', 0xff, 0, 0, dest_fid, write_offset, 0, 0, 0, 0, data_len, 59), d[dataoffset - 59:dataoffset - 59 + data_len])
                        while 1:
                            s = self.recv_packet()
                            if self.isValidAnswer(s,SMB.SMB_COM_WRITE_ANDX):
                                offset = unpack('<H', s.get_parameter_words()[2:4])[0]
                                write_offset = write_offset + unpack('<H', s.get_parameter_words()[4+offset:6+offset])[0]
                                break
                        read_offset = read_offset + data_len
                        if callback:
                            callback(read_offset, src_datasize)
                        break
                
        finally:
            self.disconnect_tree(src_tid)
            if dest_tid > -1 and src_service != dest_service:
                self.disconnect_tree(dest_tid)

    def check_dir(self, service, path, password = None):
        tid = self.tree_connect_andx('\\\\' + self.__remote_name + '\\' + service, password)
        try:
            self.__send_smb_packet(SMB.SMB_COM_CHECK_DIRECTORY, 0x08, 0, tid, 0, '', '\x04' + path + '\x00')

            while 1:
                s = self.recv_packet()
                if self.isValidAnswer(s,SMB.SMB_COM_CHECK_DIRECTORY):
                    return
        finally:
            self.disconnect_tree(s.get_tid())

    def remove(self, service, path, password = None):
        # Perform a list to ensure the path exists
        self.list_path(service, path, password)

        tid = self.tree_connect_andx('\\\\' + self.__remote_name + '\\' + service, password)
        try:
            self.__send_smb_packet(SMB.SMB_COM_DELETE, 0x08, 0, tid, 0, pack('<H', ATTR_HIDDEN | ATTR_SYSTEM | ATTR_ARCHIVE), '\x04' + path + '\x00')

            while 1:
                s = self.recv_packet()
                if self.isValidAnswer(s,SMB.SMB_COM_DELETE):
                    return
        finally:
            self.disconnect_tree(s.get_tid())

    def rmdir(self, service, path, password = None):
        # Check that the directory exists
        self.check_dir(service, path, password)

        tid = self.tree_connect_andx('\\\\' + self.__remote_name + '\\' + service, password)
        try:
            self.__send_smb_packet(SMB.SMB_COM_DELETE_DIRECTORY, 0x08, 0, tid, 0, '', '\x04' + path + '\x00')

            while 1:
                s = self.recv_packet()
                if self.isValidAnswer(s,SMB.SMB_COM_DELETE_DIRECTORY):
                    return
        finally:
            self.disconnect_tree(s.get_tid())

    def mkdir(self, service, path, password = None):
        tid = self.tree_connect_andx('\\\\' + self.__remote_name + '\\' + service, password)
        try:
            s = SMBPacket()
            s.set_command(SMB.SMB_COM_CREATE_DIRECTORY)
            s.set_flags(0x08)
            s.set_flags2(0)
            s.set_tid(tid)
            s.set_parameter_words('') # check this! don't know if i don'thave to put this
            s.set_buffer('\x04' + path + '\x00')
            self.send_smb(s)
            s = self.recv_packet()
            if self.isValidAnswer(s,SMB.SMB_COM_CREATE_DIRECTORY):
                return 1
            return 0
        finally:
            self.disconnect_tree(s.get_tid())

    def rename(self, service, old_path, new_path, password = None):
        tid = self.tree_connect_andx('\\\\' + self.__remote_name + '\\' + service, password)
        try:
            s = SMBPacket()
            s.set_command(SMB.SMB_COM_RENAME)
            s.set_flags(0x08)
            s.set_flags2(0)
            s.set_tid(tid)
            s.set_parameter_words(pack('<H', ATTR_SYSTEM | ATTR_HIDDEN | ATTR_DIRECTORY))
            s.set_buffer('\x04' + old_path + '\x00\x04' + new_path + '\x00')
            self.send_smb(s)
            s = self.recv_packet()
            if self.isValidAnswer(s,SMB.SMB_COM_RENAME):
                return 1
            return 0
        finally:
            self.disconnect_tree(s.get_tid())

    def browse_domains(self):
        return self.__browse_servers(SV_TYPE_DOMAIN_ENUM, SMBDomain, '')

    def browse_servers_for_domain(self, domain = None):
        if not domain:
            domain = self.__server_domain

        return self.__browse_servers(SV_TYPE_SERVER | SV_TYPE_PRINTQ_SERVER | SV_TYPE_WFW | SV_TYPE_NT, SMBMachine, domain)

    def get_socket(self):
        return self.__sess.get_socket()


ERRDOS = { 1: 'Invalid function',
           2: 'File not found',
           3: 'Invalid directory',
           4: 'Too many open files',
           5: 'Access denied',
           6: 'Invalid file handle. Please file a bug report.',
           7: 'Memory control blocks destroyed',
           8: 'Out of memory',
           9: 'Invalid memory block address',
           10: 'Invalid environment',
           11: 'Invalid format',
           12: 'Invalid open mode',
           13: 'Invalid data',
           15: 'Invalid drive',
           16: 'Attempt to remove server\'s current directory',
           17: 'Not the same device',
           18: 'No files found',
           32: 'Sharing mode conflicts detected',
           33: 'Lock request conflicts detected',
           80: 'File already exists'
           }

ERRSRV = { 1: 'Non-specific error',
           2: 'Bad password',
           4: 'Access denied',
           5: 'Invalid tid. Please file a bug report.',
           6: 'Invalid network name',
           7: 'Invalid device',
           49: 'Print queue full',
           50: 'Print queue full',
           51: 'EOF on print queue dump',
           52: 'Invalid print file handle',
           64: 'Command not recognized. Please file a bug report.',
           65: 'Internal server error',
           67: 'Invalid path',
           69: 'Invalid access permissions',
           71: 'Invalid attribute mode',
           81: 'Server is paused',
           82: 'Not receiving messages',
           83: 'No room to buffer messages',
           87: 'Too many remote user names',
           88: 'Operation timeout',
           89: 'Out of resources',
           91: 'Invalid user handle. Please file a bug report.',
           250: 'Temporarily unable to support raw mode for transfer',
           251: 'Temporarily unable to support raw mode for transfer',
           252: 'Continue in MPX mode',
           65535: 'Unsupported function'
           }

ERRHRD = { 19: 'Media is write-protected',
           20: 'Unknown unit',
           21: 'Drive not ready',
           22: 'Unknown command',
           23: 'CRC error',
           24: 'Bad request',
           25: 'Seek error',
           26: 'Unknown media type',
           27: 'Sector not found',
           28: 'Printer out of paper',
           29: 'Write fault',
           30: 'Read fault',
           31: 'General failure',
           32: 'Open conflicts with an existing open',
           33: 'Invalid lock request',
           34: 'Wrong disk in drive',
           35: 'FCBs not available',
           36: 'Sharing buffer exceeded'
           }

