# Copyright (c) 2003 CORE Security Technologies
#
# This software is provided under under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# $Id$
#
# Description:
#   SAMR (Security Account Manager Remote) interface implementation.
#
# Author:
#   Alberto Solino (beto)
#   Javier Kohen (jkohen)

import array
from struct import *

from impacket import ImpactPacket
from impacket.smb import display_time
import dcerpc
import ndrutils

MSRPC_UUID_SAMR   = '\x78\x57\x34\x12\x34\x12\xcd\xab\xef\x00\x01\x23\x45\x67\x89\xac\x01\x00\x00\x00'

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
            self._items.append(dcerpc.MSRPCArray(length, size, id))
            index += 8

        index += 24     # salteo los unknowns
        item_count = unpack('<L',data[index:index+4])[0]
        index += 4 + (item_count+1) * 4  # Esto no lo se!! salteo buffer
        self._rid, self._group, self._acct_ctr,_ = unpack('<LLLL',data[index: index+16])
        index += 16
        logon_divisions, _, id = unpack('<HHL',data[index:index+8])
        self._items.append(dcerpc.MSRPCArray(logon_divisions, _, id))
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
        if self._pwd_must_change_low == 4294967295L:
            return "Infinity" 
        else:
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
        if self._pwd_must_change_low == 4294967295L:
            print "PWD Must Change: Infinity" 
        else:
            print "PWD Must Change: " + display_time(self._pwd_must_change_high, self._pwd_must_change_low)
        for i in MSRPCUserInfo.ITEMS.keys():
            print i + ': ' + self._items[MSRPCUserInfo.ITEMS[i]].get_name()
        print
        return


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
        return dcerpc.MSRPCNameArray(self.get_bytes()[4:-8].tostring())
    def set_domains(self, domains):
        assert isinstance(domains, dcerpc.MSRPCNameArray)
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
        return dcerpc.MSRPCArray(self.get_bytes().tolist()[20:])
    def set_domain(self, domain):
        assert isinstance(domain, dcerpc.MSRPCArray)
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
    OP_NUM = 0xD

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
        return dcerpc.MSRPCNameArray(self.get_bytes()[4:-8].tostring())
    def set_users(self, users):
        assert isinstance(users, dcerpc.MSRPCNameArray)
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

    def enumusers(self,context_handle):
        enumusers = SAMREnumDomainUsersHeader()
        enumusers.set_context_handle(context_handle)
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
