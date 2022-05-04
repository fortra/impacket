#!/usr/bin/env python
# Impacket - Collection of Python classes for working with network protocols.
#
# SECUREAUTH LABS. Copyright (C) 2022 SecureAuth Corporation. All rights reserved.
#
# This software is provided under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Description:
#   A tool for connecting to MS Exchange via RPC over HTTP v2
#
#   Notes about -rpc-hostname:
#     Our RPC over HTTP v2 implementation tries to extract the
#     target's NetBIOS name via NTLMSSP and use it as RPC Server name.
#     If it fails, you have to manually get the target RPC Server name
#     from the Autodiscover service and set it in the -rpc-hostname parameter.
#
# Author:
#   Arseniy Sharoglazov <mohemiv@gmail.com> / Positive Technologies (https://www.ptsecurity.com/)
#
# References:
#   - https://swarm.ptsecurity.com/attacking-ms-exchange-web-interfaces/
#

from __future__ import print_function
import base64
import codecs
import logging
import argparse
import binascii
import sys
from six import PY3

from impacket import uuid, version
from impacket.http import AUTH_BASIC
from impacket.examples import logger
from impacket.examples.utils import parse_target
from impacket.structure import parse_bitmask
from impacket.dcerpc.v5 import transport, nspi
from impacket.mapi_constants import PR_CONTAINER_FLAGS_VALUES, MAPI_PROPERTIES
from impacket.dcerpc.v5.nspi import CP_TELETEX, ExchBinaryObject, \
    get_guid_from_dn, get_dn_from_guid
from impacket.dcerpc.v5.rpch import RPC_PROXY_REMOTE_NAME_NEEDED_ERR, \
    RPC_PROXY_HTTP_IN_DATA_401_ERR, RPC_PROXY_CONN_A1_0X6BA_ERR, \
    RPC_PROXY_CONN_A1_404_ERR, RPC_PROXY_RPC_OUT_DATA_404_ERR, \
    RPC_PROXY_CONN_A1_401_ERR

PY37ORHIGHER = sys.version_info >= (3, 7)
PR_CONTAINER_FLAGS       = 0x36000003
PR_ENTRYID               = 0x0fff0102
PR_DEPTH                 = 0x30050003
PR_EMS_AB_IS_MASTER      = 0xfffb000B
PR_EMS_AB_CONTAINERID    = 0xfffd0003
PR_EMS_AB_PARENT_ENTRYID = 0xfffc0102
PR_DISPLAY_NAME          = 0x3001001F
PR_EMS_AB_OBJECT_GUID    = 0x8c6d0102
PR_INSTANCE_KEY          = 0x0ff60102

DELIMITER = "======================="

class Exchanger:
    def __init__(self):
        self._username = ''
        self._password = ''
        self._domain = ''
        self._lmhash = ''
        self._nthash = ''

        self._extended_output = False
        self._output_type = 'hex'

        self._stringbinding = None
        self._rpctransport = None

        self.__outputFileName = None
        self.__outputFd = None

    def conenct_mapi(self):
        raise NotImplementedError('Virtual method. Not implemented in subclass!')

    def connect_rpc(self):
        raise NotImplementedError('Virtual method. Not implemented in subclass!')

    def load_autodiscover(self):
        # This should be implemented only as optional,
        # and the implementation should support processing emails
        # which do not belong to the used for the authentication account
        raise NotImplementedError('Not Implemented!')

    def set_credentials(self, username='', password='', domain='', hashes=None):
        self._username = username
        self._password = password
        self._domain = domain
        self._lmhash = ''
        self._nthash = ''

        if hashes is not None:
            self._lmhash, self._nthash = hashes.split(':')

    def set_extended_output(self, output_mode):
        self._extended_output = output_mode

    def set_output_type(self, output_type):
        self._output_type = output_type

    def set_output_file(self, filename):
        self.__outputFileName = filename
        self.__outputFd = open(self.__outputFileName, 'w+')

    def print(self, text):
        if self.__outputFd != None:
            if PY3:
                self.__outputFd.write(text + '\n')
            else:
                self.__outputFd.write((text + '\n').encode('utf-8'))
        print(text)

    def _encode_binary(self, bytestr):
        if PY3 and self._output_type == "hex":
            return "0x%s" % str(binascii.hexlify(bytestr), 'ascii')
        elif self._output_type == "hex":
            return "0x%s" % binascii.hexlify(bytestr)
        elif PY3:
            return str(base64.b64encode(bytestr), 'ascii')
        else:
            return base64.b64encode(bytestr)

    def __del__(self):
        if self.__outputFd != None:
            self.__outputFd.close()
        self.__outputFd = None

class NSPIAttacks(Exchanger):
    PROPS_GUID = [PR_EMS_AB_OBJECT_GUID]

    PROPS_MINUMAL = [
            0x3a00001F, # mailNickname
            0x39fe001F, # mail
            0x80270102, # objectSID
            0x30070040, # whenCreated
            0x30080040, # whenChanged
            0x8c6d0102, # objectGUID
        ]

    PROPS_EXTENDED = PROPS_MINUMAL + [
            # Names
            0x3a0f001f, # cn
            0x8202001f, # name
            0x0fff0102, # PR_ENTRYID
            0x3001001f, # PR_DISPLAY_NAME
            0x3a20001f, # PR_TRANSMITABLE_DISPLAY_NAME
            0x39ff001f, # displayNamePrintable
            0x800f101f, # proxyAddresses
            0x8171001f, # lDAPDisplayName
            0x8102101f, # ou
            0x804b001F, # adminDisplayName

            # Text Properties
            0x806f101f, # description
            0x3004001f, # info
            0x8069001f, # c
            0x3a26001f, # co
            0x3a2a001f, # postalCode
            0x3a28001f, # st
            0x3a29001f, # streetAddress
            0x3a09001f, # homePhone
            0x3a1c001f, # mobile
            0x3a1b101f, # otherTelephone
            0x3a16001f, # company
            0x3a18001f, # department
            0x3a17001f, # title
            0x3a11001f, # sn
            0x3a0a001f, # initials
            0x3a06001f, # givenName

            # Attributes of Types
            0x0ffe0003, # PR_OBJECT_TYPE
            0x39000003, # PR_DISPLAY_TYPE
            0x80bd0003, # instanceType

            # Exchange Extension Attributes
            0x802d001F, # extensionAttribute1
            0x802e001F, # extensionAttribute2
            0x802f001F, # extensionAttribute3
            0x8030001F, # extensionAttribute4
            0x8031001F, # extensionAttribute5
            0x8032001F, # extensionAttribute6
            0x8033001F, # extensionAttribute7
            0x8034001F, # extensionAttribute8
            0x8035001F, # extensionAttribute9
            0x8036001F, # extensionAttribute10
            0x8c57001F, # extensionAttribute11
            0x8c58001F, # extensionAttribute12
            0x8c59001F, # extensionAttribute13
            0x8c60001F, # extensionAttribute14
            0x8c61001F, # extensionAttribute15

            # 0x8c9e0102, # thumbnailPhoto, large

            # Configuration
            0x81b6101e, # protocolSettings
            0x8c9f001e, # msExchUserCulture
            0x8c730102, # msExchMailboxGuid
            0x8c96101e, # msExchResourceAddressLists, exists only for Exchange Organization object
            0x8c750102, # msExchMasterAccountSid
            0x8cb5000b, # msExchEnableModeration
            0x8cb30003, # msExchGroupJoinRestriction
            0x8ce20003, # msExchGroupMemberCount

            # Useful when lookuping DNTs
            0x813b101e, # subRefs
            0x8170101e, # networkAddress
            0x8011001e, # targetAddress
            0x8175101e, # url

            # Useful for distinguishing accounts
            0x8c6a1102, # userCertificate

            # Assigned MId
            0x0ff60102, # PR_INSTANCE_KEY
    ]

    # MS-OXNSPI
    # 2.1 Transport
    # For the network protocol sequence RPC over HTTPS,
    # this protocol MUST use the well-known endpoint 6004.
    DEFAULT_STRING_BINDING = 'ncacn_http:%s[6004,RpcProxy=%s:443]'

    def __init__(self):
        Exchanger.__init__(self)

        self.__handler = None

        self.htable = {}
        self.anyExistingContainerID = -1

        self.props = list()
        self.stat = nspi.STAT()
        self.stat['CodePage'] = nspi.CP_TELETEX

    def connect_rpc(self, remoteName, rpcHostname=''):
        self._stringbinding = self.DEFAULT_STRING_BINDING % (rpcHostname, remoteName)
        logging.debug('StringBinding %s' % self._stringbinding)

        self._rpctransport = transport.DCERPCTransportFactory(self._stringbinding)
        self._rpctransport.set_credentials(self._username, self._password, self._domain,
                                           self._lmhash, self._nthash)

        self.__dce = self._rpctransport.get_dce_rpc()

        # MS-OXNSPI
        # 3.1.4 Message Processing Events and Sequencing Rules
        #
        # This protocol MUST indicate to the RPC runtime that it
        # is to perform a strict Network Data Representation (NDR) data
        # consistency check at target level 6.0, as specified in [MS-RPCE].
        self.__dce.set_credentials(self._username, self._password, self._domain,
                                   self._lmhash, self._nthash)
        self.__dce.set_auth_level(6)

        self.__dce.connect()
        self.__dce.bind(nspi.MSRPC_UUID_NSPI)

        resp = nspi.hNspiBind(self.__dce, self.stat)
        self.__handler = resp['contextHandle']

    def update_stat(self, table_MId):
        stat = nspi.STAT()
        stat['CodePage'] = CP_TELETEX
        stat['ContainerID'] = NSPIAttacks._int_to_dword(table_MId)

        resp = nspi.hNspiUpdateStat(self.__dce, self.__handler, stat)
        self.stat = resp['pStat']

    def load_htable(self):
        resp = nspi.hNspiGetSpecialTable(self.__dce, self.__handler)
        resp_simpl = nspi.simplifyPropertyRowSet(resp['ppRows'])

        self._parse_and_set_htable(resp_simpl)

    def load_htable_stat(self):
        for MId in self.htable:
            self.update_stat(MId)
            self.htable[MId]['count'] = self.stat['TotalRecs']
            self.htable[MId]['start_mid'] = self.stat['CurrentRec']

    def load_htable_containerid(self):
        if self.anyExistingContainerID != -1:
            return

        if self.htable == {}:
            self.load_htable()

        for MId in self.htable:
            self.update_stat(MId)

            if self.stat['CurrentRec'] > 0:
                self.anyExistingContainerID = NSPIAttacks._int_to_dword(MId)
                return

    def _parse_and_set_htable(self, htable):
        self.htable = {}

        for ab in htable:
            MId = ab[PR_EMS_AB_CONTAINERID]

            self.htable[MId] = {}
            self.htable[MId]['flags'] = ab[PR_CONTAINER_FLAGS]

            if MId == 0:
                self.htable[0]['name'] = "Default Global Address List"
            else:
                self.htable[MId]['name'] = ab[PR_DISPLAY_NAME]
                self.htable[MId]['guid'] = get_guid_from_dn(ab[PR_ENTRYID])

            if PR_EMS_AB_PARENT_ENTRYID in ab:
                self.htable[MId]['parent_guid'] = get_guid_from_dn(ab[PR_EMS_AB_PARENT_ENTRYID])

            if PR_DEPTH in ab:
                self.htable[MId]['depth'] = ab[PR_DEPTH]
            else:
                self.htable[MId]['depth'] = 0

            if PR_EMS_AB_IS_MASTER in ab:
                self.htable[MId]['is_master'] = ab[PR_EMS_AB_IS_MASTER]
            else:
                self.htable[MId]['is_master'] = 0

    @staticmethod
    def _int_to_dword(number):
        if number > 0:
            return number
        else:
            return (number + (1 << 32)) % (1 << 32)

    def print_htable(self, parent_guid=None):
        MIds_print = []

        for MId in self.htable:
            if parent_guid == None and 'parent_guid' not in self.htable[MId]:
                MIds_print.append(MId)
            elif parent_guid != None and 'parent_guid' in self.htable[MId] and self.htable[MId]['parent_guid'] == parent_guid:
                MIds_print.append(MId)

        for MId in MIds_print:
            ab = self.htable[MId]
            ab['printed'] = True
            indent = '    ' * ab['depth']

            # Table name
            print("%s%s" % (indent, ab['name']))

            # Count
            if 'count' in ab:
                print("%sTotalRecs: %d" % (indent, ab['count']))

            # Table params
            if MId != 0:
                guid = uuid.bin_to_string(ab['guid']).lower()
                print("%sGuid: %s" % (indent, guid))
            else:
                print("%sGuid: None" % indent)

            if ab['is_master'] != 0:
                print("%sPR_EMS_AB_IS_MASTER attribute is set!" % indent)

            if self._extended_output:
                dword = NSPIAttacks._int_to_dword(MId)
                print("%sAssigned MId: 0x%.08X (%d)" % (indent, dword, MId))

                if 'start_mid' in ab:
                    dword = NSPIAttacks._int_to_dword(ab['start_mid'])
                    if dword == 2:
                        print("%sAssigned first record MId: 0x00000002 (MID_END_OF_TABLE)" % indent)
                    else:
                        print("%sAssigned first record MId: 0x%.08X (%d)" % (indent, dword, ab['start_mid']))

                flags = parse_bitmask(PR_CONTAINER_FLAGS_VALUES, ab['flags'])
                print("%sFlags: %s" % (indent, flags))

            print()

            if MId != 0:
                self.print_htable(parent_guid=ab['guid'])

        if parent_guid == None:
            for MId in self.htable:
                if self.htable[MId]['printed'] == False:
                    print("Found parentless object!")
                    print("Name: %s" % self.htable[MId]['name'])
                    print("Guid: %s" % uuid.bin_to_string(self.htable[MId]['guid']).lower())
                    print("Parent guid: %s" % uuid.bin_to_string(self.htable[MId]['parent_guid']).lower())
                    dword = NSPIAttacks._int_to_dword(MId) if MId < 0 else MId
                    print("Assigned MId: 0x%.08X (%d)" % (dword, MId))
                    flags = parse_bitmask(PR_CONTAINER_FLAGS_VALUES, self.htable[MId]['flags'])
                    print("Flags: %s" % flags)
                    if self.htable[MId]['is_master'] != 0:
                        print("%sPR_EMS_AB_IS_MASTER attribute is set!" % indent)
                    print()

    def disconnect(self):
        nspi.hNspiUnbind(self.__dce, self.__handler)
        self.__dce.disconnect()

    def print_row(self, row_simpl, delimiter=None):
        empty = True

        for aulPropTag in row_simpl:
            PropertyId = aulPropTag >> 16
            PropertyType = aulPropTag & 0xFFFF

            # Error, e.g. MAPI_E_NOT_FOUND
            if PropertyType == 0x000A:
                continue

            # PtypEmbeddedTable
            if PropertyType == 0x000D:
                continue

            empty = False

            if PropertyId in MAPI_PROPERTIES:
                property_name = MAPI_PROPERTIES[PropertyId][1]
                if property_name is None:
                    property_name = MAPI_PROPERTIES[PropertyId][5]
                if property_name is None:
                    property_name = MAPI_PROPERTIES[PropertyId][6]
            else:
                property_name = "0x%.8x" % aulPropTag

            if self._extended_output:
                property_name = "%s, 0x%.8x" % (property_name, aulPropTag)

            if isinstance(row_simpl[aulPropTag], ExchBinaryObject):
                self.print("%s: %s" % (property_name, self._encode_binary(row_simpl[aulPropTag])))
            else:
                self.print("%s: %s" % (property_name, row_simpl[aulPropTag]))

        if empty == False and delimiter != None:
            self.print(delimiter)

    def load_props(self):
        if len(self.props) > 0:
            return

        resp = nspi.hNspiQueryColumns(self.__dce, self.__handler)

        for prop in resp['ppColumns']['aulPropTag']:
            PropertyTag = prop['Data']
            PropertyType = PropertyTag & 0xFFFF

            if PropertyType == 0x000D:
                # Skipping PtypEmbeddedTable to reduce traffic
                continue

            self.props.append(PropertyTag)

    def req_print_table_rows(self, table_MId=None, attrs=[], count=50, eTable=None, onlyCheck=False):
        printOnlyGUIDs = False
        useAsExplicitTable = False

        if self.anyExistingContainerID == -1:
            self.load_htable_containerid()

        if table_MId == None and eTable == None:
            raise Exception("Wrong arguments!")
        elif table_MId != None and eTable != None:
            raise Exception("Wrong arguments!")
        elif table_MId != None:
            # Let's call NspiUpdateStat
            # It's important when the given MId is taken from the hierarchy table,
            # especially in Multi-Tenant environments
            self.update_stat(table_MId)

            # Table end reached
            if self.stat['CurrentRec'] == nspi.MID_END_OF_TABLE:
                # Returning False to support onlyCheck
                return False
        else:
            # eTable != None
            useAsExplicitTable = True

        if attrs == self.PROPS_GUID:
            # GUIDS
            firstReqProps = self.PROPS_GUID
            printOnlyGUIDs = True
        elif attrs == self.PROPS_MINUMAL:
            # MINIMAL
            firstReqProps = self.PROPS_MINUMAL
        elif attrs == []:
            # FULL
            # Requesting a list of all the properties that the server knows
            if self.props == []:
                self.load_props()
            attrs = self.props

            # To avoid MAPI_E_NOT_ENOUGH_RESOURCES error we request MIds,
            # and then use them as an Explicit Table
            firstReqProps = [PR_INSTANCE_KEY]
            useAsExplicitTable = True
        else:
            # EXTENDED and custom
            #
            # To avoid MAPI_E_NOT_ENOUGH_RESOURCES error we request MIds,
            # and then use them as an Explicit Table
            firstReqProps = [PR_INSTANCE_KEY]
            useAsExplicitTable = True

        if onlyCheck:
            attrs = self.PROPS_GUID
            firstReqProps = self.PROPS_GUID
            useAsExplicitTable = True

        while True:
            if eTable == None:
                resp = nspi.hNspiQueryRows(self.__dce, self.__handler,
                    pStat=self.stat, Count=count, pPropTags=firstReqProps)
                self.stat = resp['pStat']

                try:
                    # Addressing to PropertyRowSet_r must be inside try / except,
                    # as if the server returned a wrong result, it can be in
                    # multiple of forms, and we cannot easily determine it
                    # before parsing
                    resp_rows = nspi.simplifyPropertyRowSet(resp['ppRows'])
                except Exception as e:
                    resp.dumpRaw()
                    logging.error(str(e))
                    raise Exception("NspiQueryRows returned wrong result")

                if onlyCheck:
                    if len(resp_rows) == 0:
                        return False

                    for row in resp_rows:
                        # PropertyId = 0x8C6D (objectGUID)
                        # PropertyType = 0x000A (error)
                        if 0x8C6D000A not in row:
                            return True

                    return False

            if useAsExplicitTable:
                if eTable == None:
                    eTableInt = []
                    for row in resp_rows:
                        eTableInt.append(row[PR_INSTANCE_KEY])
                else:
                    eTableInt = eTable

                resp = nspi.hNspiQueryRows(self.__dce, self.__handler,
                    ContainerID=self.anyExistingContainerID, Count=count, pPropTags=attrs, lpETable=eTableInt)

                try:
                    # Addressing to PropertyRowSet_r must be inside try / except,
                    # as if the server returned a wrong result, it can be in
                    # multiple of forms, and we cannot easily determine it
                    # before parsing
                    resp_rows = nspi.simplifyPropertyRowSet(resp['ppRows'])
                except Exception as e:
                    resp.dumpRaw()
                    logging.error(str(e))
                    raise Exception("NspiQueryRows returned wrong result while processing explicit table")

                if onlyCheck:
                    if len(resp_rows) == 0:
                        return False

                    for row in resp_rows:
                        # PropertyId = 0x8C6D (objectGUID)
                        # PropertyType = 0x000A (error)
                        if 0x8C6D000A not in row:
                            return True

                    return False

            if printOnlyGUIDs:
                for row in resp_rows:
                    if PR_EMS_AB_OBJECT_GUID in row:
                        objectGuid = row[PR_EMS_AB_OBJECT_GUID]
                        self.print(objectGuid)
                    else:
                        # Empty row (wrong MId)
                        pass
            else:
                for row in resp_rows:
                    self.print_row(row, DELIMITER)

            # When the caller specified eTable it's always one NspiQueryRows call
            if eTable != None:
                break

            # Table end reached
            # It also MUST be checked after NspiUpdateStat
            if self.stat['CurrentRec'] == nspi.MID_END_OF_TABLE:
                break

            # This should not happen
            if len(resp_rows) == 0:
                break

    def req_print_guid(self, guid=None, attrs=[], count=50, guidFile=None):
        if guid == None and guidFile == None:
            raise Exception("Wrong arguments!")
        elif guid != None and guidFile != None:
            raise Exception("Wrong arguments!")

        if attrs == []:
            # Requesting a list of all the properties that the server knows
            if self.props == []:
                self.load_props()
            attrs = self.props

        if guid:
            printedLines = self._req_print_guid([guid], attrs)
            if printedLines == 0:
                raise Exception("Object with specified GUID not found!")
            return

        fd = open(guidFile, 'r')
        line = fd.readline()

        while True:
            guidList = []
            # EOF
            if line == '':
                break

            # Reading N lines from the file
            for i in range(count):
                line = fd.readline()
                guid = line.strip()

                if guid == '' or line[0] == '#':
                    continue

                guidList.append(guid)

            # Multiple empty lines or EOF
            if len(guidList) == 0:
                continue

            # Processing
            self._req_print_guid(guidList, attrs, DELIMITER)

        fd.close()

    def _req_print_guid(self, guidList, attrs, delimiter=None):
        legacyDNList = []

        for guid in guidList:
            legacyDNList.append(get_dn_from_guid(guid, minimize=True))

        resp = nspi.hNspiResolveNamesW(self.__dce, self.__handler, pPropTags=attrs, paStr=legacyDNList)

        try:
            # Addressing to PropertyRowSet_r must be inside try / except,
            # as if the server returned a wrong result, it can be in
            # multiple of forms, and we cannot easily determine it
            # before parsing
            if resp['ppRows']['cRows'] <= 0:
                return 0

            # Addressing to PropertyRowSet_r must be inside try / except,
            # as if the server returned a wrong result, it can be in
            # multiple of forms, and we cannot easily determine it
            # before parsing
            resp_rows = nspi.simplifyPropertyRowSet(resp['ppRows'])
        except Exception as e:
            resp.dumpRaw()
            logging.error(str(e))
            raise Exception("NspiResolveNamesW returned wrong result")

        for row in resp_rows:
            self.print_row(row, delimiter)

        return resp['ppRows']['cRows']

    def req_print_dnt(self, start_dnt, stop_dnt, attrs=[], count=50, checkIfEmpty=False):
        if count <= 0 or start_dnt < 0 or stop_dnt < 0 or stop_dnt > 0xFFFFFFFF or start_dnt > 0xFFFFFFFF:
            raise Exception("Wrong arguments!")

        if stop_dnt >= start_dnt:
            step = count
            rstep = 1
        else:
            step = -count
            rstep = -1

        stop_dnt += rstep
        dnt1 = start_dnt
        dnt2 = start_dnt + step

        while True:
            if step > 0 and dnt2 > stop_dnt:
                dnt2 = stop_dnt
            elif step < 0 and dnt2 < stop_dnt:
                dnt2 = stop_dnt

            self.print("# MIds %d-%d:" % (dnt1, dnt2 - rstep))

            if checkIfEmpty:
                # Speed up the process by reducing the length of request/response
                exists = self.req_print_table_rows(attrs=attrs, eTable=range(dnt1, dnt2, rstep), onlyCheck=True)
                if exists:
                    self.req_print_table_rows(attrs=attrs, eTable=range(dnt1, dnt2, rstep))
            else:
                self.req_print_table_rows(attrs=attrs, eTable=range(dnt1, dnt2, rstep))

            if dnt2 == stop_dnt:
                break

            dnt1 += step
            dnt2 += step

class ExchangerHelper:
    def __init__(self, domain, username, password, remoteName):
        self.__domain = domain
        self.__username = username
        self.__password = password
        self.__remoteName = remoteName

        self.exch = None

    def run(self, options):
        module = options.module.lower()
        submodule = options.submodule.lower()

        if module == 'nspi':
            # Checking options before connecting to the server
            self.nspi_check(submodule, options)
            self.nspi_run(submodule, options)
        else:
            raise Exception("%s module not found" % module)

    def nspi_run(self, submodule, options):
        self.exch = NSPIAttacks()
        self.exch.set_credentials(self.__username, self.__password, self.__domain, options.hashes)
        self.exch.set_extended_output(options.debug)

        if submodule in ['dump-tables', 'guid-known', 'dnt-lookup'] and options.output_file != None:
            self.exch.set_output_file(options.output_file)

        self.exch.connect_rpc(self.__remoteName, options.rpc_hostname)

        if submodule == 'list-tables':
            self.nspi_list_tables(options)
        elif submodule == 'dump-tables':
            self.nspi_dump_tables(options)
        elif submodule == 'guid-known':
            self.nspi_guid_known(options)
        elif submodule == 'dnt-lookup':
            self.nspi_dnt_lookup(options)

        self.exch.disconnect()

    def nspi_check(self, submodule, options):
        if submodule == 'dump-tables' and options.name == None and options.guid == None:
            dump_tables.print_help()
            sys.exit(1)

        if submodule == 'dump-tables' and options.name != None and options.guid != None:
            logging.error("Specify only one of -name or -guid")
            sys.exit(1)

        if submodule == 'guid-known' and options.guid == None and options.guid_file == None:
            guid_known.print_help()
            sys.exit(1)

        if submodule == 'guid-known' and options.guid != None and options.guid_file != None:
            logging.error("Specify only one of -guid or -guid-file")
            sys.exit(1)

    def nspi_list_tables(self, options):
        self.exch.load_htable()

        if options.count:
            self.exch.load_htable_stat()

        self.exch.print_htable()

    def nspi_dump_tables(self, options):
        self.exch.set_output_type(options.output_type)

        if options.lookup_type == None or options.lookup_type == 'MINIMAL':
            propTags = NSPIAttacks.PROPS_MINUMAL
        elif options.lookup_type == 'EXTENDED':
            propTags = NSPIAttacks.PROPS_EXTENDED
        elif options.lookup_type == 'GUIDS':
            propTags = NSPIAttacks.PROPS_GUID
        else:
            # FULL
            propTags = []

        if options.name != None and options.name.lower() in ['gal', 'default global address list', 'global address list']:
            logging.info("Lookuping Global Address List")
            table_MId = 0
        else:
            # 2.2.8
            # The client obtains Minimal Entry IDs for STAT ContainerID
            # from the server's address book hierarchy table
            #
            # We cannot convert the GUID to a MId via NspiDNToMId or similar operations because it
            # may not work in Multi-Tenant environments
            self.exch.load_htable()

            if options.guid != None:
                logging.info("Search for an address book with objectGUID = %s" % options.guid)
                guid = uuid.string_to_bin(options.guid)
                name = None
            else:
                guid = None
                name = options.name

            table_MId = 0

            for MId in self.exch.htable:
                if MId == 0:
                    # GAL
                    continue

                if guid is not None:
                    # -guid
                    if self.exch.htable[MId]['guid'] == guid:
                        logging.debug("MId %d is assigned for %s object" % (MId, options.guid))
                        logging.info("Lookuping %s" % self.exch.htable[MId]['name'])
                        table_MId = MId
                        break
                else:
                    # -name
                    if self.exch.htable[MId]['name'] == name:
                        guid = uuid.bin_to_string(self.exch.htable[MId]['guid'])
                        logging.debug("MId %d is assigned for %s object" % (MId, guid))
                        logging.info("Lookuping address book with objectGUID = %s" % guid)
                        table_MId = MId
                        break

            if table_MId == 0:
                logging.error("Specified address book not found!")
                sys.exit(1)

        self.exch.req_print_table_rows(table_MId, propTags, options.rows_per_request)

    def nspi_guid_known(self, options):
        self.exch.set_output_type(options.output_type)

        if options.lookup_type == None or options.lookup_type == 'MINIMAL':
            propTags = NSPIAttacks.PROPS_MINUMAL
        elif options.lookup_type == 'EXTENDED':
            propTags = NSPIAttacks.PROPS_EXTENDED
        else:
            # FULL
            propTags = []

        if options.guid != None:
            self.exch.req_print_guid(options.guid, propTags)
        else:
            self.exch.req_print_guid(attrs=propTags, count=options.rows_per_request, guidFile=options.guid_file)

    def nspi_dnt_lookup(self, options):
        if options.lookup_type == None or options.lookup_type == 'EXTENDED':
            propTags = NSPIAttacks.PROPS_EXTENDED
        elif options.lookup_type == 'GUIDS':
            propTags = NSPIAttacks.PROPS_GUID
        else:
            # FULL
            propTags = []

        self.exch.req_print_dnt(options.start_dnt, options.stop_dnt, attrs=propTags,
            count=options.rows_per_request, checkIfEmpty=True)

# Process command-line arguments.
if __name__ == '__main__':
    # Init the example's logger theme
    logger.init()

    # Explicitly changing the stdout encoding format
    if sys.stdout.encoding is None:
        # Output is redirected to a file
        sys.stdout = codecs.getwriter('utf8')(sys.stdout)

    print(version.BANNER)

    class SmartFormatter(argparse.HelpFormatter):
        def _split_lines(self, text, width):
            if text.startswith('R|'):
                return text[2:].splitlines()
            else:
                return argparse.HelpFormatter._split_lines(self, text, width)

    def localized_arg(bytestring):
        unicode_string = bytestring.decode(sys.getfilesystemencoding())
        return unicode_string

    parser = argparse.ArgumentParser(add_help=True, description="A tool to abuse Exchange services")
    parser.add_argument('target', action='store', help='[[domain/]username[:password]@]<targetName or address>')
    parser.add_argument('-debug', action='store_true', help='Turn DEBUG and EXTENDED output ON')
    #parser.add_argument('-transport', choices=['RPC', 'MAPI'], nargs='?', default='RPC', help='Protocol to use')
    parser.add_argument('-rpc-hostname', action='store', help='A name of the server in GUID (preferred) '
        'or NetBIOS name format (see description in the beggining of this file)')

    group = parser.add_argument_group('authentication')
    group.add_argument('-hashes', action="store", metavar = "LMHASH:NTHASH", help='NTLM hashes, format is LMHASH:NTHASH')

    if PY37ORHIGHER:
        subparsers = parser.add_subparsers(help='A module name', dest='module', required=True)
    else:
        subparsers = parser.add_subparsers(help='A module name', dest='module')

    # NSPI module
    nspi_parser = subparsers.add_parser('nspi', help='Attack NSPI interface')

    # Attacks for NSPI protocol
    if PY37ORHIGHER:
        nspi_attacks = nspi_parser.add_subparsers(help='A submodule name', dest='submodule', required=True)
    else:
        nspi_attacks = nspi_parser.add_subparsers(help='A submodule name', dest='submodule')

    list_tables = nspi_attacks.add_parser('list-tables', help='List Address Books')
    list_tables.add_argument('-count', action='store_true', help='Request total number of records in each table')


    dump_tables = nspi_attacks.add_parser('dump-tables', formatter_class=SmartFormatter, help='Dump Address Books')
    dump_tables.add_argument('-lookup-type', choices=['MINIMAL', 'EXTENDED', 'FULL', 'GUIDS'], nargs='?', default='MINIMAL',
        help='R|Lookup type:\n'
             '  MINIMAL  - Request limited set of fields (default)\n'
             '  EXTENDED - Request extended set of fields\n'
             '  FULL     - Request all fields for each row\n'
             '  GUIDS    - Request only GUIDs')
    dump_tables.add_argument('-rows-per-request', action='store', type=int, metavar="50", default=50,
        help='Limit the number of rows per request')

    if PY3:
        dump_tables.add_argument('-name', action='store', help='Dump table with the specified name (inc. GAL)')
    else:
        dump_tables.add_argument('-name', action='store', help='Dump table with the specified name (inc. GAL)',
            type=localized_arg)

    dump_tables.add_argument('-guid', action='store', help='Dump table with the specified GUID')
    dump_tables.add_argument('-output-type', choices=['hex', 'base64'], nargs='?', default='hex',
        help='Output format for binary objects')
    dump_tables.add_argument('-output-file', action='store', help='Output filename')

    guid_known = nspi_attacks.add_parser('guid-known', formatter_class=SmartFormatter,
        help='Retrieve Active Directory objects by GUID / GUIDs')
    guid_known.add_argument('-guid', action='store', help='Dump object with the specified GUID')
    guid_known.add_argument('-guid-file', action='store', help='Dump objects using GUIDs from file')
    guid_known.add_argument('-lookup-type', choices=['MINIMAL', 'EXTENDED', 'FULL'], nargs='?', default='MINIMAL',
        help='R|Lookup type:\n'
             '  MINIMAL  - Request limited set of fields (default)\n'
             '  EXTENDED - Request extended set of fields\n'
             '  FULL     - Request all fields for each row')
    guid_known.add_argument('-rows-per-request', action='store', type=int, metavar="50", default=50,
        help='Limit the number of rows per request')
    guid_known.add_argument('-output-type', choices=['hex', 'base64'], nargs='?', default='hex',
        help='Output format for binary objects')
    guid_known.add_argument('-output-file', action='store', help='Output filename')

    dnt_lookup = nspi_attacks.add_parser('dnt-lookup', formatter_class=SmartFormatter, help='Lookup Distinguished Name Tags')
    dnt_lookup.add_argument('-lookup-type', choices=['EXTENDED', 'FULL', 'GUIDS'], nargs='?', default='EXTENDED',
        help='R|Lookup type:\n'
             '  EXTENDED - Request extended set of fields (default)\n'
             '  FULL     - Request all fields for each row\n'
             '  GUIDS    - Request only GUIDs')
    dnt_lookup.add_argument('-rows-per-request', action='store', type=int, metavar="350", default=350,
        help='Limit the number of rows per request')

    dnt_lookup.add_argument('-start-dnt', action='store', type=int, metavar="500000", default=500000,
        help='A DNT to start from')
    dnt_lookup.add_argument('-stop-dnt', action='store', type=int, metavar="0", default=0,
        help='A DNT to lookup to')

    dnt_lookup.add_argument('-output-type', choices=['hex', 'base64'], nargs='?', default='hex',
        help='Output format for binary objects')
    dnt_lookup.add_argument('-output-file', action='store', help='Output filename')

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    options = parser.parse_args()

    if options.debug is True:
        logging.getLogger().setLevel(logging.DEBUG)
        # Print the Library's installation path
        logging.debug(version.getInstallationPath())
    else:
        logging.getLogger().setLevel(logging.INFO)

    domain, username, password, remoteName = parse_target(options.target)

    if domain is None:
        domain = ''

    if password == '' and username != '' and options.hashes is None:
        from getpass import getpass
        password = getpass("Password:")

    if options.rpc_hostname == '':
        # Preventing false feedback that empty hostname means something for Exchange
        # For autodetect -rpc-hostname should be skipped
        logging.error("-rpc-hostname cannot be empty")
        sys.exit(1)

    if options.rpc_hostname is None:
        # Autodetect
        options.rpc_hostname = ''

    try:
        exchHelper = ExchangerHelper(domain, username, password, remoteName)
        exchHelper.run(options)
    except KeyboardInterrupt:
        logging.error("KeyboardInterrupt")
    except Exception as e:
        #raise

        # This may contain UTF-8
        error_text = 'Protocol failed: %s' % e
        logging.critical(error_text)

        if 'NspiQueryRows returned wrong result' in error_text and \
            options.submodule.lower() == 'dnt-lookup':
            logging.critical("Most likely ntdsai.dll in lsass.exe has crashed "
                             "on a Domain Controller while processing a DNT which "
                             "does not support to be requested via MS-NSPI. "
                             "The DC is probably rebooting. "
                             "This can happend in Multi-Tenant Environment. "
                             "You can try to request different DNT range")

        if 'Connection reset by peer' in error_text and \
            exchHelper.exch._rpctransport.rts_ping_received == True and \
            options.submodule.lower() == 'dnt-lookup':
            logging.critical("Most likely ntdsai.dll in lsass.exe has crashed "
                             "on a Domain Controller while processing a DNT which "
                             "does not support to be requested via MS-NSPI. "
                             "The DC is probably rebooting. "
                             "This can happend in Multi-Tenant Environment. "
                             "You can try to request different DNT range")

        # This usually happens when the target is RDG
        # Probably may happen for Exchange 2003 / 2007 / 2010
        if RPC_PROXY_CONN_A1_0X6BA_ERR in error_text:
            logging.critical("This usually means the target has no ACL to connect to "
                             "this endpoint using RPC Proxy")
            logging.critical("Is the server a MS Exchange?")
            if options.rpc_hostname == '':
                logging.critical("Try to specify -rpc-hostname (see description in the "
                                 "beggining of this file)")
            else:
                logging.critical("Try to specify different -rpc-hostname, or enumerate "
                                 "endpoints via rpcmap.py / rpcdump.py")

        # It's Exchange or Exchange behind TMG, but the RPC Server name is wrong
        if RPC_PROXY_RPC_OUT_DATA_404_ERR in error_text or \
           RPC_PROXY_CONN_A1_404_ERR in error_text:
            if options.rpc_hostname == '':
                logging.critical("Cannot determine the right RPC Server name. Specify -rpc-hostname "
                                 "(see description in the beggining of this file)")
            else:
                logging.critical("The specified RPC Server is incorrect. "
                                 "Try to specify different -rpc-hostname")

        if RPC_PROXY_REMOTE_NAME_NEEDED_ERR in error_text:
            logging.critical("Specify -rpc-hostname (see description in the beggining of this file)")

        # Wrong credentials
        if RPC_PROXY_HTTP_IN_DATA_401_ERR in error_text or RPC_PROXY_CONN_A1_401_ERR in error_text:
            logging.critical("Wrong credentials!")

        # Show a reminder if Basic
        if RPC_PROXY_HTTP_IN_DATA_401_ERR in error_text or RPC_PROXY_CONN_A1_401_ERR in error_text:
            if exchHelper.exch._rpctransport.get_auth_type() == AUTH_BASIC and domain == '':
                logging.critical("The server requested Basic authentication which "
                                 "may require you to specify the domain. "
                                 "Your domain is empty!")

        if RPC_PROXY_CONN_A1_401_ERR in error_text or \
           RPC_PROXY_CONN_A1_404_ERR in error_text:
            logging.info("A proxy in front of the target server detected (may be WAF / SIEM)")
