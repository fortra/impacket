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
# Modified by Alberto Solino <asolino@coresecurity.com>

import os, sys, socket, string, re, select, errno
from time import strftime, gmtime
from random import randint
from struct import pack, unpack

import nmb

# Try to load mxCrypto's DES module to perform password encryption if required.
# Password will not be encrypted if mxCrypto's DES module is not loaded.
try:
    from Crypto.Ciphers import DES
except ImportError:
    DES = None

try:
    from cStringIO import StringIO
except ImportError:
    from StringIO import StringIO

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

# NT Specific commands
NT_CREATE_ANDX = 0xa2



def ascii_to_wide( aBuffer ):
	aStr = ''
	for c in aBuffer:
		aStr += c
		aStr += '\x00'
	aStr += '\x00\x00'
	return aStr

def wide_to_ascii( aBuffer, anOffset = 0):
	offset = anOffset
	aStr = ''
	while 1:
		ch = unpack( 'c', aBuffer[offset] )[0]
		if ch == '\x00':
			break
		else:
			aStr = aStr + ch
			offset = offset + 2
	return aStr


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

    def get_mtime(self):
        return self.__mtime

    def get_atime(self):
        return self.__atime

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
    SMB_COM_CREATE_DIR = 0x00
    SMB_COM_DELETE_DIR = 0x01
    SMB_COM_CLOSE = 0x04
    SMB_COM_DELETE = 0x06
    SMB_COM_RENAME = 0x07
    SMB_COM_CHECK_DIR = 0x10
    SMB_COM_READ_RAW = 0x1a
    SMB_COM_WRITE_RAW = 0x1d
    SMB_COM_TRANSACTION = 0x25
    SMB_COM_TRANSACTION2 = 0x32
    SMB_COM_OPEN_ANDX = 0x2d
    SMB_COM_READ_ANDX = 0x2e
    SMB_COM_WRITE_ANDX = 0x2f
    SMB_COM_TREE_DISCONNECT = 0x71
    SMB_COM_NEGOTIATE = 0x72
    SMB_COM_SESSION_SETUP_ANDX = 0x73
    SMB_COM_LOGOFF = 0x74
    SMB_COM_TREE_CONNECT_ANDX = 0x75
    
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
    FLAGS2_UNICODE = 0x8000

    def __init__(self, remote_name, remote_host, my_name = None, host_type = nmb.TYPE_SERVER, sess_port = nmb.NETBIOS_SESSION_PORT, timeout=None):
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

        try:
            self.__sess = nmb.NetBIOSSession(my_name, remote_name, remote_host, host_type, sess_port, timeout)
        except socket.error, ex:
            raise ex

        # Initialize values __ntlm_dialect, __is_pathcaseless
        self.__neg_session()
        
        # If the following assertion fails, then mean that the encryption key is not sent when
        # encrypted authentication is required by the server.
        assert (self.__ntlm_dialect.is_auth_mode() == SMB.SECURITY_AUTH_PLAINTEXT) or (self.__ntlm_dialect.is_auth_mode() == SMB.SECURITY_AUTH_ENCRYPTED and self.__ntlm_dialect.get_encryption_key() and self.__ntlm_dialect.get_encryption_key_len() >= 8)

        # Call login() without any authentication information to setup a session if the remote server
        # is in share mode.
        if self.__ntlm_dialect.is_share_mode() == SMB.SECURITY_SHARE_SHARE:
            self.login('', '')
            
    def set_timeout(self, timeout):
        self.__timeout = timeout
        
    def __del__(self):
        if self.__sess:
            self.__sess.close()

    def __decode_smb(self, data):
        _, cmd, err_class, _, err_code, flags1, flags2, _, tid, pid, uid, mid, wcount = unpack('<4sBBBHBH12sHHHHB', data[:33])
        param_end = 33 + wcount * 2
        return cmd, err_class, err_code, flags1, flags2, tid, uid, mid, data[33:param_end], data[param_end + 2:]

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

    def send_smb(self,s):
        s.set_uid(self.__uid)
        s.set_pid(os.getpid())
        self.__sess.send_packet(s.rawData())

    def __send_smb_packet(self, cmd, status, flags, flags2, tid, mid, params = '', data = ''):
        wordcount = len(params)
        assert wordcount & 0x1 == 0
        self.__sess.send_packet(pack('<4sBLBH12sHHHHB', '\xffSMB', cmd, status, flags, flags2, '\0' * 12, tid, os.getpid(), self.__uid, mid, wordcount / 2) + params + pack('<H', len(data)) + data)

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


    def connect_tree(self, path, service, password):
        s = SMBPacket()
        s.set_command(SMB.SMB_COM_TREE_CONNECT_ANDX)
        s.set_flags(8)
        if password:
            # Password is only encrypted if the server passed us an "encryption" during protocol dialect
            # negotiation and mxCrypto's DES module is loaded.
            if self.__ntlm_dialect.get_encryption_key() and DES:
                password = self.__deshash(password)
            s.set_parameter_words(pack('<BBHHH', 0xff, 0, 0, 0, len(password)))
            s.set_buffer(password + string.upper(path) + '\0' + service + '\0')
        else:
            s.set_parameter_words(pack('<BBHHH', 0xff, 0, 0, 0, 1))
            s.set_buffer('\0' + string.upper(path) + '\0' + service + '\0')
        self.send_smb(s)

        while 1:
            s = self.recv_packet()
            if self.isValidAnswer(s,SMB.SMB_COM_TREE_CONNECT_ANDX):
                return s.get_tid()

    def get_server_time(self):
        high, low = self.__ntlm_dialect.get_utc()
        min = self.__ntlm_dialect.get_minutes_utc()
        return display_time(high, low, min)

    def disconnect_tree(self, tid):
        s = SMBPacket()
        s.set_command(SMB.SMB_COM_TREE_DISCONNECT)
        s.set_tid(tid)
        self.send_smb(s)
        s = self.recv_packet()

    def open_file(self, tid, filename, open_mode, access_mode):
        s = SMBPacket()
        s.set_command(SMB.SMB_COM_OPEN_ANDX)
        s.set_flags(0x8)
        s.set_flags2(SMB.FLAGS2_LONG_FILENAME)
        s.set_tid(tid)
        s.set_parameter_words(pack('<BBHHHHHLHLLL', 0xff, 0, 0, 0, access_mode, ATTR_READONLY | ATTR_HIDDEN | ATTR_ARCHIVE, 0, 0, open_mode, 0, 0, 0))
        s.set_buffer(filename + '\x00')
        self.send_smb(s)
        
        while 1:
            s = self.recv_packet()
            if self.isValidAnswer(s,SMB.SMB_COM_OPEN_ANDX):
                fid, attrib, lastwritetime, datasize, grantedaccess, filetype, devicestate, action, serverfid = unpack('<HHLLHHHHL', s.get_parameter_words()[4:28])
                return fid, attrib, lastwritetime, datasize, grantedaccess, filetype, devicestate, action, serverfid
        
    def __close_file(self, tid, fid):
        s = SMBPacket()
        s.set_command(SMB.SMB_COM_CLOSE)
        s.set_tid(tid)
        s.set_parameter_words(pack('<HL', fid, 0))
        self.send_smb(s)
        s = self.recv_packet()

    def send_trans(self, tid, setup, name, param, data):
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
            
        self.__send_smb_packet(SMB.SMB_COM_TRANSACTION, 0, self.__is_pathcaseless, SMB.FLAGS2_LONG_FILENAME, tid, 0, pack('<HHHHBBHLHHHHHBB', param_len, data_len, 1024, 65504, 0, 0, 0, 0, 0, param_len, param_offset, data_len, data_offset, setup_len / 2, 0) + setup, name + param + data)

    def trans2(self, tid, setup, name, param, data):
        data_len = len(data)
        name_len = len(name)
        param_len = len(param)
        setup_len = len(setup)

        assert setup_len & 0x01 == 0

        param_offset = name_len + setup_len + 63
        data_offset = param_offset + param_len
            
        self.__send_smb_packet(SMB.SMB_COM_TRANSACTION2, 0, self.__is_pathcaseless, SMB.FLAGS2_LONG_FILENAME, tid, 0, pack('<HHHHBBHLHHHHHBB', param_len, data_len, 1024, self.__ntlm_dialect.get_max_buffer(), 0, 0, 0, 0, 0, param_len, param_offset, data_len, data_offset, setup_len / 2, 0) + setup, name  + param + data)

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
            self.__send_smb_packet(SMB.SMB_COM_READ_ANDX, 0, 0, 0, tid, 0, pack('<BBHHLHHLH', 0xff, 0, 0, fid, read_offset, max_buf_size, max_buf_size, 0, 0), '')
            while 1:
                s = self.recv_packet()
                if self.isValidAnswer(s,SMB.SMB_COM_READ_ANDX):
                    offset = unpack('<H', s.get_parameter_words()[2:4])[0]
                    data_len, dataoffset = unpack('<HH', s.get_parameter_words()[10+offset:14+offset])
                    if data_len == len(s.get_buffer()):
                        callback(s.get_buffer())
                    else:
                        callback(s.get_buffer()[dataoffset - 59:dataoffset - 59 + data_len])
                        read_offset = read_offset + data_len
                    break

    def __raw_retr_file(self, tid, fid, offset, datasize, callback):
        max_buf_size = self.__ntlm_dialect.get_max_buffer() & ~0x3ff  # Write in multiple KB blocks
        read_offset = offset
        while read_offset < datasize:
            self.__send_smb_packet(SMB.SMB_COM_READ_RAW, 0, 0, 0, tid, 0, pack('<HLHHLH', fid, read_offset, 0xffff, 0, 0, 0), '')
            s = self.__sess.recv_packet(self.__timeout)
            if s.rawData():
                callback(s.get_trailer())
                read_offset = read_offset + len(s.get_trailer())
            else:
                # No data returned. Need to send SMB_COM_READ_ANDX to find out what is the error.
                self.__send_smb_packet(SMB.SMB_COM_READ_ANDX, 0, 0, 0, tid, 0, pack('<BBHHLHHLH', 0xff, 0, 0, fid, read_offset, max_buf_size, max_buf_size, 0, 0), '')
                while 1:
                    s = self.recv_packet()
                    if self.isValidAnswer(s,SMB.SMB_COM_READ_ANDX):
                        #cmd, err_class, err_code, flags1, flags2, _, _, mid, params, d = self.__decode_smb(data)
                        offset = unpack('<H', s.get_parameter_words()[2:4])[0]
                        data_len, dataoffset = unpack('<HH', s.get_parameter_words()[10+offset:14+offset])
                        if data_len == 0:
                            # Premature EOF!
                            return
                        # By right we should not have data returned in the reply.
                        elif data_len == len(s.get_buffer()):
                            callback(s.get_buffer())
                        else:
                            callback(s.get_buffer()[dataoffset - 59:dataoffset - 59 + data_len])
                        read_offset = read_offset + data_len
                        break

    def __nonraw_stor_file(self, tid, fid, offset, datasize, callback):
        max_buf_size = self.__ntlm_dialect.get_max_buffer() & ~0x3ff  # Write in multiple KB blocks
        write_offset = offset
        while 1:
            data = callback(max_buf_size)
            if not data:
                break
            
            self.__send_smb_packet(SMB.SMB_COM_WRITE_ANDX, 0, 0, 0, tid, 0, pack('<BBHHLLHHHHH', 0xff, 0, 0, fid, write_offset, 0, 0, 0, 0, len(data), 59), data)
            
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
            self.__send_smb_packet(SMB.SMB_COM_WRITE_RAW, 0, 0, 0, tid, 0, pack('<HHHLLHLHH', fid, read_len, 0, write_offset, 0, 0, 0, 0, 59), '')
            while 1:
                s = self.recv_packet()
                if self.isValidAnswer(s,SMB.SMB_COM_WRITE_RAW):
                    self.__sess.send_packet(read_data)
                    write_offset = write_offset + read_len
                    break

        # We need to close fid to check whether the last raw packet is written successfully
        self.__send_smb_packet(SMB.SMB_COM_CLOSE, 0, 0, 0, tid, 0, pack('<HL', fid, 0), '')
        while 1:
            s = self.recv_packet()
            if self.isValidAnswer(s,SMB.SMB_COM_CLOSE):
                if s.get_error_class() == 0x00 and s.get_error_code() == 0x00:
                    return

    def __browse_servers(self, server_flags, container_type, domain):
        tid = self.connect_tree('\\\\' + self.__remote_name + '\\IPC$', SERVICE_ANY)

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
        

    def __expand_des_key(self, key):
        # Expand the key from a 7-byte password key into a 8-byte DES key
        s = chr(((ord(key[0]) >> 1) & 0x7f) << 1)
        s = s + chr(((ord(key[0]) & 0x01) << 6 | ((ord(key[1]) >> 2) & 0x3f)) << 1)
        s = s + chr(((ord(key[1]) & 0x03) << 5 | ((ord(key[2]) >> 3) & 0x1f)) << 1)
        s = s + chr(((ord(key[2]) & 0x07) << 4 | ((ord(key[3]) >> 4) & 0x0f)) << 1)
        s = s + chr(((ord(key[3]) & 0x0f) << 3 | ((ord(key[4]) >> 5) & 0x07)) << 1)
        s = s + chr(((ord(key[4]) & 0x1f) << 2 | ((ord(key[5]) >> 6) & 0x03)) << 1)
        s = s + chr(((ord(key[5]) & 0x3f) << 1 | ((ord(key[6]) >> 7) & 0x01)) << 1)
        s = s + chr((ord(key[6]) & 0x7f) << 1)
        return s

    def __deshash(self, password):
        # This is done according to Samba's encryption specification (docs/html/ENCRYPTION.html)
        if len(password) > 14:
            p14 = string.upper(password[:14])
        else:
            p14 = string.upper(password) + '\0' * (14 - len(password))
        p21 = DES(self.__expand_des_key(p14[:7])).encrypt('\x4b\x47\x53\x21\x40\x23\x24\x25') + DES(self.__expand_des_key(p14[7:])).encrypt('\x4b\x47\x53\x21\x40\x23\x24\x25') + '\0' * 5
        return DES(self.__expand_des_key(p21[:7])).encrypt(self.__ntlm_dialect.get_encryption_key()) + DES(self.__expand_des_key(p21[7:14])).encrypt(self.__ntlm_dialect.get_encryption_key()) + DES(self.__expand_des_key(p21[14:])).encrypt(self.__ntlm_dialect.get_encryption_key())

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

    def login(self, name, password, domain = ''):
        # Password is only encrypted if the server passed us an "encryption" during protocol dialect
        # negotiation and mxCrypto's DES module is loaded.
        if self.__ntlm_dialect.get_encryption_key() and DES:
            password = self.__deshash(password)
        s = SMBPacket()
        s.set_command(SMB.SMB_COM_SESSION_SETUP_ANDX)
        s.set_parameter_words(pack('<ccHHHHLHHLL', '\xff', '\0', 0, 65535, 2, os.getpid(), self.__ntlm_dialect.get_session_key(), len(password), 0, 0, SMB.CAP_RAW_MODE))
        s.set_buffer(password + name + '\0' + domain + '\0' + os.name + '\0' + 'pysmb\0')
        self.send_smb(s)
        
        while 1:
            s = self.recv_packet()
            if self.isValidAnswer(s,SMB.SMB_COM_SESSION_SETUP_ANDX):
                # We will need to use this uid field for all future requests/responses
                self.__uid = s.get_uid()
                security_bloblen = unpack('<H', s.get_parameter_words()[4:6])[0]
                if s.get_flags2() & SMB.FLAGS2_UNICODE:
                    offset = security_bloblen
                    if offset & 0x01:
                        offset = offset + 1
                    # Skip server OS
                    end = offset
                    while ord(s.get_buffer()[end]) or ord(s.get_buffer()[end + 1]):
                        end = end + 2
                    try:
                        self.__server_os = unicode(s.get_buffer()[offset:end], 'utf_16_le')
                    except NameError:
                        self.__server_os = s.get_buffer()[offset:end]
                    end = end + 2
                    offset = end
                    # Skip server lanman
                    while ord(s.get_buffer()[end]) or ord(s.get_buffer()[end + 1]):
                        end = end + 2
                    try:
                        self.__server_lanman = unicode(s.get_buffer()[offset:end], 'utf_16_le')
                    except NameError:
                        self.__server_lanman = s.get_buffer()[offset:end]
                    end = end + 2
                    offset = end
                    while ord(s.get_buffer()[end]) or ord(s.get_buffer()[end + 1]):
                        end = end + 2
                    try:
                        self.__server_domain = unicode(s.get_buffer()[offset:end], 'utf_16_le')
                    except NameError:
                        self.__server_domain = s.get_buffer()[offset:end]
                else:
                    idx1 = string.find(s.get_buffer(), '\0', security_bloblen)
                    if idx1 != -1:
                        self.__server_os = s.get_buffer()[:idx1]
                        idx2 = string.find(s.get_buffer(), '\0', idx1 + 1)
                        if idx2 != -1:
                            self.__server_lanman = s.get_buffer()[idx1 + 1:idx2]
                            idx3 = string.find(s.get_buffer(), '\0', idx2 + 1)
                            if idx3 != -1:
                                self.__server_domain = s.get_buffer()[idx2 + 1:idx3]
                return 1

    def logoff(self):
        s = SMBPacket()
        s.set_command(SMB.SMB_COM_LOGOFF)
        s.set_parameter_words('\xff\x00\x00\x00')
        self.send_smb(s)
        s = self.recv_packet()

    def list_shared(self):
        tid = self.connect_tree('\\\\' + self.__remote_name + '\\IPC$', SERVICE_ANY,None)

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
                        numentries = unpack('<H', transparam[4:6])[0]
                    buf.write(transdata)

                    if not has_more:
                        share_data = buf.getvalue()
                        offset = 0
                        for i in range(0, numentries):
                            name = share_data[offset:string.find(share_data, '\0', offset)]
                            type, commentoffset = unpack('<HH', share_data[offset + 14:offset + 18])
                            comment = share_data[commentoffset:string.find(transdata, '\0', commentoffset)]
                            offset = offset + 20
                            share_list.append(SharedDevice(name, type, comment))
                        return share_list
        finally:
            buf.close()
            self.disconnect_tree(tid)

    def list_path(self, service, path = '*', password = None):
        path = string.replace(path, '/', '\\')

        tid = self.connect_tree('\\\\' + self.__remote_name + '\\' + service, SERVICE_ANY, password)
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
        tid = self.connect_tree('\\\\' + self.__remote_name + '\\' + service, SERVICE_ANY, password)
        try:
            fid, attrib, lastwritetime, datasize, grantedaccess, filetype, devicestate, action, serverfid = self.open_file(tid, filename, mode, SMB_ACCESS_READ | SMB_SHARE_DENY_WRITE)

            if not datasize:
                datasize = self.query_file_info(tid, fid)

            if self.__ntlm_dialect.is_rawmode():
                self.__raw_retr_file(tid, fid, offset, datasize, callback)
            else:
                self.__nonraw_retr_file(tid, fid, offset, datasize, callback)
        finally:
            if fid >= 0:
                self.__close_file(tid, fid)
            self.disconnect_tree(tid)

    def stor_file(self, service, filename, callback, mode = SMB_O_CREAT | SMB_O_TRUNC, offset = 0, password = None):
        filename = string.replace(filename, '/', '\\')

        fid = -1
        tid = self.connect_tree('\\\\' + self.__remote_name + '\\' + service, SERVICE_ANY, password)
        try:
            fid, attrib, lastwritetime, datasize, grantedaccess, filetype, devicestate, action, serverfid = self.open_file(tid, filename, mode, SMB_ACCESS_WRITE | SMB_SHARE_DENY_WRITE)

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
                self.__close_file(tid, fid)
            self.disconnect_tree(tid)

    def copy(self, src_service, src_path, dest_service, dest_path, callback = None, write_mode = SMB_O_CREAT | SMB_O_TRUNC, src_password = None, dest_password = None):
        dest_path = string.replace(dest_path, '/', '\\')
        src_path = string.replace(src_path, '/', '\\')
        src_tid = self.connect_tree('\\\\' + self.__remote_name + '\\' + src_service, SERVICE_ANY, src_password)

        dest_tid = -1
        try:
            if src_service == dest_service:
                dest_tid = src_tid
            else:
                dest_tid = self.connect_tree('\\\\' + self.__remote_name + '\\' + dest_service, SERVICE_ANY, dest_password)
            
            dest_fid = self.open_file(dest_tid, dest_path, write_mode, SMB_ACCESS_WRITE | SMB_SHARE_DENY_WRITE)[0]
            src_fid, _, _, src_datasize, _, _, _, _, _ = self.open_file(src_tid, src_path, SMB_O_OPEN, SMB_ACCESS_READ | SMB_SHARE_DENY_WRITE)

            if callback:
                callback(0, src_datasize)

            max_buf_size = (self.__ntlm_dialect.get_max_buffer() >> 10) << 10
            read_offset = 0
            write_offset = 0
            while read_offset < src_datasize:
                self.__send_smb_packet(SMB.SMB_COM_READ_ANDX, 0, 0, 0, src_tid, 0, pack('<BBHHLHHLH', 0xff, 0, 0, src_fid, read_offset, max_buf_size, max_buf_size, 0, 0), '')
                while 1:
                    s = self.recv_packet()
                    if self.isValidAnswer(s,SMB.SMB_COM_READ_ANDX):
                        offset = unpack('<H', s.get_parameter_words()[2:4])[0]
                        data_len, dataoffset = unpack('<HH', s.get_parameter_words()[10+offset:14+offset])
                        if data_len == len(d):
                            self.__send_smb_packet(SMB.SMB_COM_WRITE_ANDX, 0, 0, 0, dest_tid, 0, pack('<BBHHLLHHHHH', 0xff, 0, 0, dest_fid, write_offset, 0, 0, 0, 0, data_len, 59), d)
                        else:
                            self.__send_smb_packet(SMB.SMB_COM_WRITE_ANDX, 0, 0, 0, dest_tid, 0, pack('<BBHHLLHHHHH', 0xff, 0, 0, dest_fid, write_offset, 0, 0, 0, 0, data_len, 59), d[dataoffset - 59:dataoffset - 59 + data_len])
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
        tid = self.connect_tree('\\\\' + self.__remote_name + '\\' + service, SERVICE_ANY, password)
        try:
            self.__send_smb_packet(SMB.SMB_COM_CHECK_DIR, 0, 0x08, 0, tid, 0, '', '\x04' + path + '\x00')

            while 1:
                s = self.recv_packet()
                if self.isValidAnswer(s,SMB.SMB_COM_CHECK_DIR):
                    return
        finally:
            self.disconnect_tree(s.get_tid())

    def remove(self, service, path, password = None):
        # Perform a list to ensure the path exists
        self.list_path(service, path, password)

        tid = self.connect_tree('\\\\' + self.__remote_name + '\\' + service, SERVICE_ANY, password)
        try:
            self.__send_smb_packet(SMB.SMB_COM_DELETE, 0, 0x08, 0, tid, 0, pack('<H', ATTR_HIDDEN | ATTR_SYSTEM | ATTR_ARCHIVE), '\x04' + path + '\x00')

            while 1:
                s = self.recv_packet()
                if self.isValidAnswer(s,SMB.SMB_COM_DELETE):
                    return
        finally:
            self.disconnect_tree(s.get_tid())

    def rmdir(self, service, path, password = None):
        # Check that the directory exists
        self.check_dir(service, path, password)

        tid = self.connect_tree('\\\\' + self.__remote_name + '\\' + service, SERVICE_ANY, password)
        try:
            self.__send_smb_packet(SMB.SMB_COM_DELETE_DIR, 0, 0x08, 0, tid, 0, '', '\x04' + path + '\x00')

            while 1:
                s = self.recv_packet()
                if self.isValidAnswer(s,SMB.SMB_COM_DELETE_DIR):
                    return
        finally:
            self.disconnect_tree(s.get_tid())

    def mkdir(self, service, path, password = None):
        tid = self.connect_tree('\\\\' + self.__remote_name + '\\' + service, SERVICE_ANY, password)
        try:
            s = SMBPacket()
            s.set_command(SMB.SMB_COM_CREATE_DIR)
            s.set_flags(0x08)
            s.set_flags2(0)
            s.set_tid(tid)
            s.set_parameter_words('') # check this! don't know if i don'thave to put this
            s.set_buffer('\x04' + path + '\x00')
            self.send_smb(s)
            s = self.recv_packet()
            if self.isValidAnswer(s,SMB.SMB_COM_CREATE_DIR):
                return 1
            return 0
        finally:
            self.disconnect_tree(s.get_tid())

    def rename(self, service, old_path, new_path, password = None):
        tid = self.connect_tree('\\\\' + self.__remote_name + '\\' + service, SERVICE_ANY, password)
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

    def nt_create(self,tid,filename):
        s = SMBPacket()
        s.set_command(NT_CREATE_ANDX)
        s.set_flags(0x18)
        s.set_flags2(SMB.FLAGS2_LONG_FILENAME)
        s.set_tid(tid)
        s.set_uid(self.__uid)
        s.set_parameter_words(pack('<BBHBHLLLLLLLLLLB', 0xff, 0, 0,0, len(filename),0x16,0,0x2019F, 0,0,0,0x3,0x1,0x40,0x2,3))
        s.set_buffer(filename + '\x00')
        self.send_smb(s)
        s = self.recv_packet()
        if self.isValidAnswer(s,NT_CREATE_ANDX):
            handle = s.get_parameter_words()[5:7]
            return handle
        return 0

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

def display_time(filetime_high, filetime_low, minutes_utc=0):
    d = filetime_high*4.0*1.0*(1<<30)
    d += filetime_low
    d *= 1.0e-7
    d -= (369.0*365.25*24*60*60-(3.0*24*60*60+6.0*60*60))
    if minutes_utc == 0:
        r = (strftime("%a, %d %b %Y %H:%M:%S",gmtime(d)), minutes_utc/60)[0]
    else:
        r = "%s GMT %d " % (strftime("%a, %d %b %Y %H:%M:%S",gmtime(d)), minutes_utc/60)
    return r
