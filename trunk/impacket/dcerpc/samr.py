################################################################################
# DEPRECATION WARNING!                                                         #
# This library will be deprecated soon. You should use impacket.dcerpc.v5      #
# classes instead                                                              #
################################################################################
# Copyright (c) 2003-2012 CORE Security Technologies
#
# This software is provided under under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# $Id$
#
# Author: Alberto Solino
#
# Description:
#   SAMR (Security Account Manager Remote) interface implementation.
#

import array
from time import strftime, gmtime
from struct import *

from impacket import ImpactPacket
from impacket.dcerpc import ndrutils, dcerpc
from impacket.structure import Structure
from impacket.uuid import uuidtup_to_bin

MSRPC_UUID_SAMR   = uuidtup_to_bin(('12345778-1234-ABCD-EF00-0123456789AC', '1.0'))

KNOWN_SIDS = {
}

OP_NUM_CREATE_USER_IN_DOMAIN    = 0xC
OP_NUM_ENUM_USERS_IN_DOMAIN     = 0xD
OP_NUM_CREATE_ALIAS_IN_DOMAIN   = 0xE

def display_time(filetime_high, filetime_low, minutes_utc=0):
    if filetime_low == 4294967295L:
        r = "Infinity"
        return r 
    d = filetime_high*4.0*1.0*(1<<30)
    d += filetime_low
    d *= 1.0e-7
    d -= (369.0*365.25*24*60*60-(3.0*24*60*60+6.0*60*60))
    if d < 1:
        r = "Undefined"
        return r
    
    try:
        gmtime(d)
    except Exception:
        d = 0

    if minutes_utc == 0:
        r = (strftime("%a, %d %b %Y %H:%M:%S",gmtime(d)), minutes_utc/60)[0]
    else:
        r = "%s GMT %d " % (strftime("%a, %d %b %Y %H:%M:%S",gmtime(d)), minutes_utc/60)
    return r

class MSRPCArray:
    def __init__(self, id=0, len=0, size=0):
        self._length = len
        self._size = size
        self._id = id
        self._max_len = 0
        self._offset = 0
        self._length2 = 0
        self._name = ''

    def set_max_len(self, n):
        self._max_len = n
    def set_offset(self, n):
        self._offset = n
    def set_length2(self, n):
        self._length2 = n
    def get_size(self):
        return self._size
    def set_name(self, n):
        self._name = n
    def get_name(self):
        return self._name
    def get_id(self):
        return self._id
    def rawData(self):
        return pack('<HHLLLL', self._length, self._size, 0x12345678, self._max_len, self._offset, self._length2) + self._name.encode('utf-16le')

class MSRPCNameArray:
    def __init__(self, data = None):
        self._count = 0
        self._max_count = 0
        self._elements = []

        if data: self.load(data)

    def load(self, data):
        ptr = unpack('<L', data[:4])[0]
        index = 4
        if 0 == ptr: # No data. May be a bug in certain versions of Samba.
            return

        self._count, _, self._max_count = unpack('<LLL', data[index:index+12])
        index += 12

        # Read each object's header.
        for i in range(0, self._count):
            aindex, length, size, _ = unpack('<LHHL', data[index:index+12])
            self._elements.append(MSRPCArray(aindex, length, size))
            index += 12

        # Read the objects themselves.
        for element in self._elements:
            max_len, offset, curlen = unpack('<LLL', data[index:index+12])
            index += 12
            element.set_name(unicode(data[index:index+2*curlen], 'utf-16le'))
            element.set_max_len(max_len)
            element.set_offset(offset)
            element.set_length2(curlen)
            index += 2*curlen
            if curlen & 0x1: index += 2 # Skip padding.

    def elements(self):
        return self._elements

    def rawData(self):
        ret = pack('<LLLL', 0x74747474, self._count, 0x47474747, self._max_count)
        pos_ret = []
        for i in xrange(0, self._count):
            ret += pack('<L', self._elements[i].get_id())
            data = self._elements[i].rawData()
            ret += data[:8]
            pos_ret += data[8:]

        return ret + pos_ret

class MSRPCUserInfo:
    ITEMS = {'Account Name':0,
             'Full Name':1,
             'Home':2,
             'Home Drive':3,
             'Script':4,
             'Profile':5,
             'Description':6,
             'Workstations':7,
             'Comment':8,
             'Parameters':9,
             'Logon hours':10
             }

    def __init__(self, data = None):
        self._logon_time_low = 0
        self._logon_time_high = 0
        self._logoff_time_low = 0
        self._logoff_time_high = 0
        self._kickoff_time_low = 0
        self._kickoff_time_high = 0
        self._pwd_last_set_low = 0
        self._pwd_last_set_high = 0
        self._pwd_can_change_low = 0
        self._pwd_can_change_high = 0
        self._pwd_must_change_low = 0
        self._pwd_must_change_high = 0
        self._items = []
        self._rid = 0
        self._group = 0
        self._acct_ctrl = 0
        self._bad_pwd_count = 0
        self._logon_count = 0
        self._country = 0
        self._codepage = 0
        self._nt_pwd_set = 0
        self._lm_pwd_set = 0

        if data: self.set_header(data)

    def set_header(self,data):
        index = 8
        self._logon_time_low, self._logon_time_high, self._logoff_time_low, self._logoff_time_high, self._kickoff_time_low,self._kickoff_time_high, self._pwd_last_set_low,self._pwd_last_set_high, self._pwd_can_change_low,self._pwd_can_change_high, self._pwd_must_change_low, self._pwd_must_change_high = unpack('<LLLLLLLLLLLL',data[index:index+48])
        index += 48
        for i in range(0,len(MSRPCUserInfo.ITEMS)-1):
            length, size, id = unpack('<HHL',data[index:index+8])
            self._items.append(MSRPCArray(length, size, id))
            index += 8

        index += 24     # salteo los unknowns
        item_count = unpack('<L',data[index:index+4])[0]
        index += 4 + (item_count+1) * 4  # Esto no lo se!! salteo buffer
        self._rid, self._group, self._acct_ctr,_ = unpack('<LLLL',data[index: index+16])
        index += 16
        logon_divisions, _, id = unpack('<HHL',data[index:index+8])
        self._items.append(MSRPCArray(logon_divisions, _, id))
        index += 8
        self._bad_pwd_count, self._logon_count, self._country, self._codepage = unpack('<HHHH', data[index: index + 8])
        index += 8
        self._nt_pwd_set, self._lm_pwd_set,_,_= unpack('<BBBB', data[index:index+4])
        index += 4

        for item in self._items[:-1]: # Except LOGON_HOUNS
            if 0 == item.get_size():
                continue
            max_len, offset, curlen = unpack('<LLL', data[index:index+12])
            index += 12
            item.set_name(unicode(data[index:index+2*curlen], 'utf-16le'))
            item.set_max_len(max_len)
            item.set_offset(offset)
            item.set_length2(curlen)
            index += 2*curlen
            if curlen & 0x1: index += 2 # Skip padding.

        # Process LOGON_HOURS.
        # This is a bitmask of logon_divisions bits. Normally logon_divisions is 168, one bit per hour of a whole week.
        item = self._items[10]
        max_len, offset, curlen = unpack('<LLL', data[index:index+12])
        index += 12
        item.set_name('Unlimited')
        # I admit this routine is not very clever. We could do a better mapping to human readable format.
        for b in data[index: index+curlen]:
            if 0xFF != ord(b):
                item.set_name('Unknown')

    def get_num_items(self):
        return len(self._items)
    def get_items(self):
        return self._items
    def get_logon_time(self):
        return display_time(self._logon_time_high, self._logon_time_low)
    def get_logoff_time(self):
        return display_time(self._logoff_time_high, self._logoff_time_low)
    def get_kickoff_time(self):
        return display_time(self._kickoff_time_high, self._kickoff_time_low)
    def get_pwd_last_set(self):
        return display_time(self._pwd_last_set_high, self._pwd_last_set_low)
    def get_pwd_can_change(self):
        return display_time(self._pwd_can_change_high, self._pwd_can_change_low)
    def get_group_id(self):
        return self._group
    def get_bad_pwd_count(self):
        return self._bad_pwd_count
    def get_logon_count(self):
        return self._logon_count
    def get_pwd_must_change(self):
        return display_time(self._pwd_must_change_high, self._pwd_must_change_low)
    def is_enabled(self):
        return not (self._acct_ctr & 0x01)

    def print_friendly(self):
        print "Last Logon: " + display_time(self._logon_time_high, self._logon_time_low)
        print "Last Logoff: " + display_time(self._logoff_time_high, self._logoff_time_low)
        print "Kickoff Time: " + display_time(self._kickoff_time_high, self._kickoff_time_low)
        print "PWD Last Set: " + display_time(self._pwd_last_set_high, self._pwd_last_set_low)
        print "PWD Can Change: " + display_time(self._pwd_can_change_high, self._pwd_can_change_low)
        print "Group id: %d" % self._group
        print "Bad pwd count: %d" % self._bad_pwd_count
        print "Logon count: %d" % self._logon_count
        print "PWD Must Change: " + display_time(self._pwd_must_change_high, self._pwd_must_change_low)
        for i in MSRPCUserInfo.ITEMS.keys():
            print i + ': ' + self._items[MSRPCUserInfo.ITEMS[i]].get_name()
        print
        return

class SAMR_RPC_SID_IDENTIFIER_AUTHORITY(Structure):
    structure = (
        ('Value','6s'),
    )

class SAMR_RPC_SID(Structure):
    structure = (
        ('Revision','<B'),
        ('SubAuthorityCount','<B'),
        ('IdentifierAuthority',':',SAMR_RPC_SID_IDENTIFIER_AUTHORITY),
        ('SubLen','_-SubAuthority','self["SubAuthorityCount"]*4'),
        ('SubAuthority',':'),
    )

    def fromCanonical(self, canonical):
       items = canonical.split('-')
       self['Revision'] = int(items[1])
       self['IdentifierAuthority'] = SAMR_RPC_SID_IDENTIFIER_AUTHORITY()
       self['IdentifierAuthority']['Value'] = '\x00\x00\x00\x00\x00' + pack('B',int(items[2]))
       self['SubAuthorityCount'] = len(items) - 3
       ans = ''
       for i in range(self['SubAuthorityCount']):
           ans += pack('<L', int(items[i+3]))
       self['SubAuthority'] = ans

    def formatCanonical(self):
       ans = 'S-%d-%d' % (self['Revision'], ord(self['IdentifierAuthority']['Value'][5]))
       for i in range(self['SubAuthorityCount']):
           ans += '-%d' % ( unpack('<L',self['SubAuthority'][i*4:i*4+4])[0])
       return ans

class SAMROpenAlias(Structure):
    opnum = 27
    alignment = 4
    structure = (
        ('ContextHandle','20s'),
        ('AccessMask','<L'),
        ('AliasId','<L'),
    )

class SAMROpenAliasResponse(Structure):
    structure = (
        ('ContextHandle','20s'),
        ('ErrorCode','<L'),
    )

class SAMRGetMembersInAlias(Structure):
    opnum = 33
    alignment = 4
    structure = (
        ('ContextHandle','20s'),
    )

class SAMRGetMembersInAliasResponse(Structure):
    structure = (
        ('BuffSize','_-pEnumerationBuffer','len(self.rawData)-8'),
        ('Count','<L'),
        ('pEnumerationBuffer',':'),
        ('ErrorCode','<L'),
    )

class SAMREnumerateAliasesInDomain(Structure):
    opnum = 15
    alignment = 4
    structure = (
        ('ContextHandle','20s'),
        ('ResumeHandle','<L=0'),
        ('PreferedMaximumLength','<L=0xffffffff'),
    )

class SAMREnumerateAliasesInDomainResponse(Structure):
    structure = (
        ('ResumeHandle','<L=0'),
        ('BuffSize','_-pEnumerationBuffer','len(self.rawData)-12'),
        ('pEnumerationBuffer',':'),
        ('CountReturned','<L'),
        ('ErrorCode','<L'),
    )

class SAMRConnectHeader(ImpactPacket.Header):
    OP_NUM = 0x39

    __SIZE = 4

    def __init__(self, aBuffer = None):
        ImpactPacket.Header.__init__(self, SAMRConnectHeader.__SIZE)

        self.__sptr = ndrutils.NDRPointer()

        self.set_server('')
        self.set_access_mask(0x2000000)

        if aBuffer: self.load_header(aBuffer)

    def get_server(self):
        return ndrutils.NDRPointer(self.get_bytes()[:-4].tostring(), ndrutils.NDRString)
    def set_server(self, name):
        ss = ndrutils.NDRString()
        ss.set_string(name)
        self.__sptr.set_pointer(ss)
        data = self.__sptr.rawData()
        self.get_bytes()[:-4] = array.array('B', data)

    def get_access_mask(self):
        return self.get_long(-4, '<')
    def set_access_mask(self, mask):
        self.set_long(-4, mask, '<')


    def get_header_size(self):
        var_size = len(self.get_bytes()) - SAMRConnectHeader.__SIZE
        assert var_size > 0
        return SAMRConnectHeader.__SIZE + var_size


class SAMRRespConnectHeader(ImpactPacket.Header):
    __SIZE = 24

    def __init__(self, aBuffer = None):
        ImpactPacket.Header.__init__(self, SAMRRespConnectHeader.__SIZE)
        if aBuffer: self.load_header(aBuffer)

    def get_context_handle(self):
        return self.get_bytes().tostring()[:20]
    def set_context_handle(self, handle):
        assert 20 == len(handle)
        self.get_bytes()[:20] = array.array('B', handle)

    def get_return_code(self):
        return self.get_long(20, '<')
    def set_return_code(self, code):
        self.set_long(20, code, '<')


    def get_header_size(self):
        return SAMRRespConnectHeader.__SIZE


class SAMREnumDomainsHeader(ImpactPacket.Header):
    OP_NUM = 0x6

    __SIZE = 28

    def __init__(self, aBuffer = None):
        ImpactPacket.Header.__init__(self, SAMREnumDomainsHeader.__SIZE)

        self.set_pref_max_size(8192)

        if aBuffer: self.load_header(aBuffer)

    def get_context_handle(self):
        return self.get_bytes().tolist()[:20]
    def set_context_handle(self, handle):
        assert 20 == len(handle)
        self.get_bytes()[:20] = array.array('B', handle)

    def get_resume_handle(self):
        return self.get_long(20, '<')
    def set_resume_handle(self, handle):
        self.set_long(20, handle, '<')

    def get_pref_max_size(self):
        return self.get_long(24, '<')
    def set_pref_max_size(self, size):
        self.set_long(24, size, '<')


    def get_header_size(self):
        return SAMREnumDomainsHeader.__SIZE


class SAMRRespEnumDomainHeader(ImpactPacket.Header):
    __SIZE = 12

    def __init__(self, aBuffer = None):
        ImpactPacket.Header.__init__(self, SAMRRespEnumDomainHeader.__SIZE)
        if aBuffer: self.load_header(aBuffer)


    def get_resume_handle(self):
        return self.get_long(0, '<')
    def set_resume_handle(self, handle):
        self.set_long(0, handle, '<')

    def get_domains(self):
        return MSRPCNameArray(self.get_bytes()[4:-8].tostring())
    def set_domains(self, domains):
        assert isinstance(domains, MSRPCNameArray)
        self.get_bytes()[4:-8] = array.array('B', domains.rawData())

    def get_entries_num(self):
        return self.get_long(-8, '<')
    def set_entries_num(self, num):
        self.set_long(-8, num, '<')

    def get_return_code(self):
        return self.get_long(-4, '<')
    def set_return_code(self, code):
        self.set_long(-4, code, '<')


    def get_header_size(self):
        var_size = len(self.get_bytes()) - SAMRRespEnumDomainHeader.__SIZE
        assert var_size > 0
        return SAMRRespEnumDomainHeader.__SIZE + var_size


class SAMRLookupDomainHeader(ImpactPacket.Header):
    OP_NUM = 0x5

    __SIZE = 20

    def __init__(self, aBuffer = None):
        ImpactPacket.Header.__init__(self, SAMRLookupDomainHeader.__SIZE)
        if aBuffer: self.load_header(aBuffer)

    def get_context_handle(self):
        return self.get_bytes().tolist()[:20]
    def set_context_handle(self, handle):
        assert 20 == len(handle)
        self.get_bytes()[:20] = array.array('B', handle)

    def get_domain(self):
        return MSRPCArray(self.get_bytes().tolist()[20:])
    def set_domain(self, domain):
        assert isinstance(domain, MSRPCArray)
        self.get_bytes()[20:] = array.array('B', domain.rawData())


    def get_header_size(self):
        var_size = len(self.get_bytes()) - SAMRLookupDomainHeader.__SIZE
        assert var_size > 0
        return SAMRLookupDomainHeader.__SIZE + var_size


class SAMRRespLookupDomainHeader(ImpactPacket.Header):
    __SIZE = 36

    def __init__(self, aBuffer = None):
        ImpactPacket.Header.__init__(self, SAMRRespLookupDomainHeader.__SIZE)
        if aBuffer: self.load_header(aBuffer)

##     def get_sid_count(self):
##         return self.get_long(4, '<')
##     def set_sid_count(self, count):
##         self.set_long(4, count, '<')

##     def get_domain_sid(self):
##         return self.get_bytes().tolist()[8:8+24]
##     def set_domain_sid(self, sid):
##         assert 24 == len(sid)
##         self.get_bytes()[8:8+24] = array.array('B', sid)

    def get_domain_sid(self):
        return self.get_bytes().tolist()[4:4+28]
    def set_domain_sid(self, sid):
        assert 28 == len(sid)
        self.get_bytes()[4:4+28] = array.array('B', sid)

    def get_return_code(self):
        return self.get_long(32, '<')
    def set_return_code(self, code):
        self.set_long(32, code, '<')


    def get_header_size(self):
        return SAMRRespLookupDomainHeader.__SIZE


class SAMROpenDomainHeader(ImpactPacket.Header):
    OP_NUM = 0x7

    __SIZE = 52

    def __init__(self, aBuffer = None):
        ImpactPacket.Header.__init__(self, SAMROpenDomainHeader.__SIZE)

        self.set_access_mask(0x304)

        if aBuffer: self.load_header(aBuffer)


    def get_context_handle(self):
        return self.get_bytes().tolist()[:20]
    def set_context_handle(self, handle):
        assert 20 == len(handle)
        self.get_bytes()[:20] = array.array('B', handle)

    def get_access_mask(self):
        return self.get_long(20, '<')
    def set_access_mask(self, mask):
        self.set_long(20, mask, '<')

##     def get_sid_count(self):
##         return self.get_long(24, '<')
##     def set_sid_count(self, count):
##         self.set_long(24, count, '<')

##     def get_domain_sid(self):
##         return self.get_bytes().tolist()[28:28+24]
##     def set_domain_sid(self, sid):
##         assert 24 == len(sid)
##         self.get_bytes()[28:28+24] = array.array('B', sid)

    def get_domain_sid(self):
        return self.get_bytes().tolist()[24:24+28]
    def set_domain_sid(self, sid):
        assert 28 == len(sid)
        self.get_bytes()[24:24+28] = array.array('B', sid)


    def get_header_size(self):
        return SAMROpenDomainHeader.__SIZE


class SAMRRespOpenDomainHeader(ImpactPacket.Header):
    __SIZE = 24

    def __init__(self, aBuffer = None):
        ImpactPacket.Header.__init__(self, SAMRRespOpenDomainHeader.__SIZE)
        if aBuffer: self.load_header(aBuffer)

    def get_context_handle(self):
        return self.get_bytes().tolist()[:20]
    def set_context_handle(self, handle):
        assert 20 == len(handle)
        self.get_bytes()[:20] = array.array('B', handle)

    def get_return_code(self):
        return self.get_long(20, '<')
    def set_return_code(self, code):
        self.set_long(20, code, '<')


    def get_header_size(self):
        return SAMRRespOpenDomainHeader.__SIZE


class SAMREnumDomainUsersHeader(ImpactPacket.Header):
    OP_NUM = OP_NUM_ENUM_USERS_IN_DOMAIN

    __SIZE = 32

    def __init__(self, aBuffer = None):
        ImpactPacket.Header.__init__(self, SAMREnumDomainUsersHeader.__SIZE)

        self.set_pref_max_size(3275)

        if aBuffer: self.load_header(aBuffer)

    def get_context_handle(self):
        return self.get_bytes().tolist()[:20]
    def set_context_handle(self, handle):
        assert 20 == len(handle)
        self.get_bytes()[:20] = array.array('B', handle)

    def get_resume_handle(self):
        return self.get_long(20, '<')
    def set_resume_handle(self, handle):
        self.set_long(20, handle, '<')

    def get_account_control(self):
        return self.get_long(24, '<')
    def set_account_control(self, mask):
        self.set_long(24, mask, '<')

    def get_pref_max_size(self):
        return self.get_long(28, '<')
    def set_pref_max_size(self, size):
        self.set_long(28, size, '<')


    def get_header_size(self):
        return SAMREnumDomainUsersHeader.__SIZE


class SAMRRespEnumDomainUsersHeader(ImpactPacket.Header):
    __SIZE = 16

    def __init__(self, aBuffer = None):
        ImpactPacket.Header.__init__(self, SAMRRespEnumDomainUsersHeader.__SIZE)
        if aBuffer: self.load_header(aBuffer)

    def get_resume_handle(self):
        return self.get_long(0, '<')
    def set_resume_handle(self, handle):
        self.set_long(0, handle, '<')

    def get_users(self):
        return MSRPCNameArray(self.get_bytes()[4:-8].tostring())
    def set_users(self, users):
        assert isinstance(users, MSRPCNameArray)
        self.get_bytes()[4:-8] = array.array('B', users.rawData())

    def get_entries_num(self):
        return self.get_long(-8, '<')
    def set_entries_num(self, num):
        self.set_long(-8, num, '<')

    def get_return_code(self):
        return self.get_long(-4, '<')
    def set_return_code(self, code):
        self.set_long(-4, code, '<')


    def get_header_size(self):
        var_size = len(self.get_bytes()) - SAMRRespEnumDomainUsersHeader.__SIZE
        assert var_size > 0
        return SAMRRespEnumDomainUsersHeader.__SIZE + var_size


class SAMROpenUserHeader(ImpactPacket.Header):
    OP_NUM = 0x22

    __SIZE = 28

    def __init__(self, aBuffer = None):
        ImpactPacket.Header.__init__(self, SAMROpenUserHeader.__SIZE)

        self.set_access_mask(0x2011B)

        if aBuffer: self.load_header(aBuffer)

    def get_context_handle(self):
        return self.get_bytes().tolist()[:20]
    def set_context_handle(self, handle):
        assert 20 == len(handle)
        self.get_bytes()[:20] = array.array('B', handle)

    def get_access_mask(self):
        return self.get_long(20, '<')
    def set_access_mask(self, mask):
        self.set_long(20, mask, '<')

    def get_rid(self):
        return self.get_long(24, '<')
    def set_rid(self, id):
        self.set_long(24, id, '<')


    def get_header_size(self):
        return SAMROpenUserHeader.__SIZE


class SAMRRespOpenUserHeader(ImpactPacket.Header):
    __SIZE = 24

    def __init__(self, aBuffer = None):
        ImpactPacket.Header.__init__(self, SAMRRespOpenUserHeader.__SIZE)
        if aBuffer: self.load_header(aBuffer)

    def get_context_handle(self):
        return self.get_bytes().tolist()[:20]
    def set_context_handle(self, handle):
        assert 20 == len(handle)
        self.get_bytes()[:20] = array.array('B', handle)

    def get_return_code(self):
        return self.get_long(20, '<')
    def set_return_code(self, code):
        self.set_long(20, code, '<')


    def get_header_size(self):
        return SAMRRespOpenUserHeader.__SIZE


class SAMRQueryUserInfoHeader(ImpactPacket.Header):
    OP_NUM = 0x24

    __SIZE = 22

    def __init__(self, aBuffer = None):
        ImpactPacket.Header.__init__(self, SAMRQueryUserInfoHeader.__SIZE)

        self.set_level(21)

        if aBuffer: self.load_header(aBuffer)

    def get_context_handle(self):
        return self.get_bytes().tolist()[:20]
    def set_context_handle(self, handle):
        assert 20 == len(handle)
        self.get_bytes()[:20] = array.array('B', handle)

    def get_level(self):
        return self.get_word(20, '<')
    def set_level(self, level):
        self.set_word(20, level, '<')


    def get_header_size(self):
        return SAMRQueryUserInfoHeader.__SIZE


class SAMRRespQueryUserInfoHeader(ImpactPacket.Header):
    __SIZE = 4

    def __init__(self, aBuffer = None):
        ImpactPacket.Header.__init__(self, SAMRRespQueryUserInfoHeader.__SIZE)
        if aBuffer: self.load_header(aBuffer)

    def get_user_info(self):
        return MSRPCUserInfo(self.get_bytes()[:-4].tostring())
    def set_user_info(self, info):
        assert isinstance(info, MSRPCUserInfo)
        self.get_bytes()[:-4] = array.array('B', info.rawData())

    def get_return_code(self):
        return self.get_long(-4, '<')
    def set_return_code(self, code):
        self.set_long(-4, code, '<')


    def get_header_size(self):
        var_size = len(self.get_bytes()) - SAMRRespQueryUserInfoHeader.__SIZE
        assert var_size > 0
        return SAMRRespQueryUserInfoHeader.__SIZE + var_size


class SAMRCloseRequestHeader(ImpactPacket.Header):
    OP_NUM = 0x1

    __SIZE = 20

    def __init__(self, aBuffer = None):
        ImpactPacket.Header.__init__(self, SAMRCloseRequestHeader.__SIZE)
        if aBuffer: self.load_header(aBuffer)

    def get_context_handle(self):
        return self.get_bytes().tolist()[:20]
    def set_context_handle(self, handle):
        assert 20 == len(handle)
        self.get_bytes()[:20] = array.array('B', handle)


    def get_header_size(self):
        return SAMRCloseRequestHeader.__SIZE


class SAMRRespCloseRequestHeader(ImpactPacket.Header):
    __SIZE = 24

    def __init__(self, aBuffer = None):
        ImpactPacket.Header.__init__(self, SAMRRespCloseRequestHeader.__SIZE)
        if aBuffer: self.load_header(aBuffer)

    def get_context_handle(self):
        return self.get_bytes().tolist()[:20]
    def set_context_handle(self, handle):
        assert 20 == len(handle)
        self.get_bytes()[:20] = array.array('B', handle)

    def get_return_code(self):
        return self.get_long(20, '<')
    def set_return_code(self, code):
        self.set_long(20, code, '<')


    def get_header_size(self):
        return SAMRRespCloseRequestHeader.__SIZE


class DCERPCSamr:
    def __init__(self, dcerpc):
        self._dcerpc = dcerpc

    def doRequest(self, request, noAnswer = 0, checkReturn = 1):
        self._dcerpc.call(request.opnum, request)
        if noAnswer:
            return
        else:
            answer = self._dcerpc.recv()
            return answer

    def connect(self):
        samrcon = SAMRConnectHeader()
        samrcon.set_server('*SMBSERVER')
        self._dcerpc.send(samrcon)
        data = self._dcerpc.recv()
        retVal = SAMRRespConnectHeader(data)
        return retVal

    def enumdomains(self,context_handle):
        enumdom = SAMREnumDomainsHeader()
        enumdom.set_context_handle(context_handle)
        self._dcerpc.send(enumdom)
        data = self._dcerpc.recv()
        retVal = SAMRRespEnumDomainHeader(data)
        return retVal

    def lookupdomain(self,context_handle,domain):
        lookupdom = SAMRLookupDomainHeader()
        lookupdom.set_context_handle(context_handle)
        lookupdom.set_domain(domain)
        self._dcerpc.send(lookupdom)
        data = self._dcerpc.recv()
        retVal = SAMRRespLookupDomainHeader(data)
        return retVal

    def opendomain(self,context_handle,domain_sid):
        opendom = SAMROpenDomainHeader()
        opendom.set_context_handle(context_handle)
        opendom.set_domain_sid(domain_sid)
        self._dcerpc.send(opendom)
        data = self._dcerpc.recv()
        retVal = SAMRRespOpenDomainHeader(data)
        return retVal

    def enumusers(self,context_handle, resume_handle = 0):
        enumusers = SAMREnumDomainUsersHeader()
        enumusers.set_context_handle(context_handle)
        enumusers.set_resume_handle(resume_handle)
        self._dcerpc.send(enumusers)
        data = self._dcerpc.recv()
        retVal = SAMRRespEnumDomainUsersHeader(data)
        return retVal

    def openuser(self,context_handle, rid):
        openuser = SAMROpenUserHeader()
        openuser.set_context_handle(context_handle)
        openuser.set_rid(rid)
        self._dcerpc.send(openuser)
        data = self._dcerpc.recv()
        retVal = SAMRRespOpenUserHeader(data)
        return retVal

    def queryuserinfo(self,context_handle):
        userinfo = SAMRQueryUserInfoHeader()
        userinfo.set_context_handle(context_handle)
        self._dcerpc.send(userinfo)
        data = self._dcerpc.recv()
        retVal = SAMRRespQueryUserInfoHeader(data)
        return retVal

    def closerequest(self,context_handle):
        closereq = SAMRCloseRequestHeader()
        closereq.set_context_handle(context_handle)
        self._dcerpc.send(closereq)
        data = self._dcerpc.recv()
        retVal = SAMRRespCloseRequestHeader(data)
        return retVal

    def EnumerateAliasesInDomain(self, context_handle):
        enumAliases = SAMREnumerateAliasesInDomain()
        enumAliases['ContextHandle'] = context_handle
        ans = self.doRequest(enumAliases, checkReturn = 0)
        packet = SAMREnumerateAliasesInDomainResponse(ans)
        enum = MSRPCNameArray(packet['pEnumerationBuffer'])
        return enum.elements()

    def OpenAlias(self, context_handle, alias_id):
        open_alias = SAMROpenAlias()
        open_alias['ContextHandle'] = context_handle
        open_alias['AliasId'] = alias_id
        open_alias['AccessMask'] = 0x2000C
        ans = self.doRequest(open_alias)
        packet = SAMROpenAliasResponse(ans)
        return packet

    def GetMembersInAlias(self, context_handle):
        alias_members = SAMRGetMembersInAlias()
        alias_members['ContextHandle'] = context_handle
        ans = self.doRequest(alias_members)
        packet = SAMRGetMembersInAliasResponse(ans)
        # Now parse the Aliases
        if packet['Count'] > 0:
           # Skipping the pointer data
           data = packet['pEnumerationBuffer'][8:]
           # Skipping the referent ID for each entry
           data = data[4*packet['Count']:]
        entries = []
        for i in range(packet['Count']):
           # Skip the count ID
           data = data[4:]
           entry = SAMR_RPC_SID(data)
           entries.append(entry)
           data = data[len(entry):]
        packet['EnumerationBuffer'] = entries 
        return packet

