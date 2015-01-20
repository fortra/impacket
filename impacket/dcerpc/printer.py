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

from impacket.structure import Structure
from impacket.uuid import uuidtup_to_bin

MSRPC_UUID_SPOOLSS   = uuidtup_to_bin(('12345678-1234-ABCD-EF00-0123456789AB', '1.0'))

def zeroize(s):
    return '\x00'.join(str(s)) + '\x00'

class SpoolSS_DevModeContainer(Structure):
    alignment = 4
    structure = (
            ('cbBuf','<L-DevMode'),
            ('pDevMode','<L&DevMode'),
            ('DevMode',':'),
        )

class SpoolSS_OpenPrinter(Structure):
    alignment = 4
    opnum = 1
    structure = (
            ('pPrinterName','<L&PrinterName'),
            ('PrinterName','w'),
            # ('pDataType','<L&DataType'),
            ('pDevMode','<L&DevMode'),
            ('DevMode',':',SpoolSS_DevModeContainer),
            ('AccessRequired','<L'),
            ('DataType','w'),
        )
            
class SpoolSS_PrinterInfo1(Structure):
    alignment = 4
    structure = (
            ('level','<L=1'),
            ('_level','<L=1'),
            ('pPrinterInfo1','<L=0x08081200'),
            ('flags','<L'),
            ('pDescription','<L&Description'),
            ('pName','<L&Name'),
            ('pComment','<L&Comment'),
            ('Description','w'),
            ('Name','w'),
            ('Comment','w'),
        )

class SpoolSS_PrinterInfo2(Structure):
    alignment = 4
    structure = (
            ('level','<L=2'),
            ('_level','<L=2'),
            ('pPrinterInfo2','<L=0x08081200'),
            ('pServerName', '<L&ServerName'),
            ('pPrinterName', '<L&PrinterName'),
            ('pShareName', '<L&ShareName'),
            ('pPortName', '<L&PortName'),
            ('pDriverName', '<L&DriverName'),
            ('pComment', '<L&Comment'),
            ('pLocation', '<L&Location'),
            ('pDevMode', '<L&DevMode'),
            ('pSepFile', '<L&SepFile'),
            ('pPrintProcessor', '<L&PrintProcessor'),
            ('pDatatype', '<L&Datatype'),
            ('pParameters', '<L&Parameters'),
            ('pSecurityDescriptor', '<L&SecurityDescriptor'),
            ('Attributes', '<L=0'),
            ('Priority', '<L=0'),
            ('DefaultPriority', '<L=0'),
            ('StartTime', '<L=0'),
            ('UntilTime', '<L=0'),
            ('Status', '<L=0'),
            ('cjobs', '<L=0'),
            ('AveragePPM', '<L=0'),
            ('ServerName', 'w'),
            ('PrinterName', 'w'),
            ('ShareName', 'w'),
            ('PortName', 'w'),
            ('DriverName', 'w'),
            ('Comment', 'w'),
            ('Location', 'w'),
            ('DevMode', ':'),
            ('SepFile', 'w'),
            ('PrintProcessor', 'w'),
            ('Datatype', 'w'),
            ('Parameters', 'w'),
            ('SecurityDescriptor', ':'),
            )

class SpoolSS_AddPrinter(Structure):
    # opnum from http://bob.marlboro.edu/~msie/2003/it1/tools/ethereal/ethereal-0.9.7/packet-dcerpc-spoolss.h
    opnum = 5
    alignment = 4
    structure = (
            ('pName','<L&Name'),
            ('Name','w'),
            ('info',':',SpoolSS_PrinterInfo2),
            ('blob',':'),
    )

class SpoolSS_DeletePrinter(Structure):
    opnum = 6
    alignment = 4
    structure = (
            ('handle','<L'),
    )

class SpoolSS_AddPrinterEx(Structure):
    opnum = 0x46
    alignment = 4
    structure = (
            ('pName','<L=0x12345678'),
            ('Name','w'),
            ('info',':',SpoolSS_PrinterInfo2),
            ('blob',':'),
    )

class SpoolSS_EnumPrinters(Structure):
    opnum = 0
    alignment = 4
    structure = (
            ('flags','<L'),
            ('pName','<L&Name'),
            ('Name','w'),
            ('level','<L'),
            ('pPrinterEnum','<L&PrinterEnum'),
            ('_cbBuf','<L-PrinterEnum'),
            ('PrinterEnum',':'),
            ('cbBuf','<L-PrinterEnum'),
        )

class SpoolSS_EnumPrinters_answer(Structure):
    alignment = 4
    structure = (
            ('pPrinterEnum','<L&PrinterEnum'),
            ('cbPrinterEnum','<L-PrinterEnum'),
            ('PrinterEnum',':'),
            ('cbNeeded','<L'),
            ('cReturned','<L'),
        )

class SpoolSS_EnumPorts(Structure):
    # fields order (in the wire) from:
    # http://samba.vernstok.nl/docs/htmldocs/manpages-4/pidl.1.html
    opnum = 0x23
    alignment = 4
    structure = (
            ('pName','<L&Name'),
            ('Name','w'),
            ('level','<L'),
            ('pPort','<L&Port'),
            ('_cbBuf','<L-Port'),
            ('Port',':'),
            ('cbBuf','<L-Port'),
        )

class SpoolSS_EnumPorts_answer(Structure):
    alignment = 4
    structure = (
            ('pPort','<L&Port'),
            ('cbPort','<L-Port'),
            ('Port',':'),
            ('cbNeeded','<L'),
            ('cReturned','<L'),
        )

class SpoolSS_AddPort(Structure):
    opnum = 37
    alignment = 4
    structure = (
            ('pName','<L&Name'),
            ('Name','w'),
            ('hWnd','<L'),
            ('pMonitorName','<L&MonitorName'),
            ('MonitorName','w'),
        )
 
class SpoolSS_PortInfo1(Structure):
    alignment = 4
    structure = (
            ('level','<L=1'),
            ('_level','<L=1'),
            ('pPortInfo1','<L=0x08081200'),
            ('pName','<L&Name'),
            ('Name','w'),
        )

class SpoolSS_AddPortEx(Structure):
    opnum = 61
    alignment = 4
    structure = (
            ('pName','<L&Name'),
            ('Name','w'),
            ('Port',':',SpoolSS_PortInfo1),
            ('cbMonitorData','<L-MonitorData'),
            ('MonitorData',':'),
            # ('pMonitorName','<L&MonitorName'),
            ('MonitorName','w'),
        )
 
class SpoolSS_AddPrintProcessor(Structure):
    opnum = 14
    alignment = 4
    structure = (
            ('pName','<L&Name'),
            ('Name','w'),
            ('pEnvironment','<L&Environment'),
            ('pPathName','<L&PathName'),
            ('pPrintProcessorName','<L&PrintProcessorName'),
            ('Environment','w'),
            ('PathName','w'),
            ('PrintProcessorName','w'),
        )

class SpoolSS_EnumMonitors(Structure):
    # fields order (in the wire) from:
    # http://samba.vernstok.nl/docs/htmldocs/manpages-4/pidl.1.html
    opnum = 0x24
    alignment = 4
    structure = (
            ('pName','<L&Name'),
            ('Name','w'),
            ('level','<L'),
            ('pMonitor','<L&Monitor'),
            ('_cbBuf','<L-Monitor'),
            ('Monitor',':'),
            ('cbBuf','<L-Monitor'),
        )

class SpoolSS_AddMonitor(Structure):
    # fields order (in the wire) from:
    # http://samba.vernstok.nl/docs/htmldocs/manpages-4/pidl.1.html
    opnum = 0x2e
    alignment = 4
    structure = (
            ('pHostName','<L&HostName'),
            ('HostName','w'),
            ('level','<L'),
            ('level','<L'),
            ('pLevel','<L&level'),
            ('pName','<L&Name'),
            ('pEnvironment','<L&Environment'),
            ('pDLLName','<L&DLLName'),
            ('Name','w'),
            ('Environment','w'),
            ('DLLName','w'),
        )

class SpoolSS_EnumMonitors_answer(Structure):
    alignment = 4
    structure = (
            ('pMonitor','<L&Monitor'),
            ('cbMonitor','<L-Monitor'),
            ('Monitor',':'),
            ('cbNeeded','<L'),
            ('cReturned','<L'),
        )

PRINTER_ENUM_DEFAULT     = 0x00000001
PRINTER_ENUM_LOCAL       = 0x00000002
PRINTER_ENUM_CONNECTIONS = 0x00000004
PRINTER_ENUM_FAVORITE    = 0x00000004
PRINTER_ENUM_NAME        = 0x00000008
PRINTER_ENUM_REMOTE      = 0x00000010
PRINTER_ENUM_SHARED      = 0x00000020
PRINTER_ENUM_NETWORK     = 0x00000040

class PrintSpooler:
    def __init__(self, dce):
        self.dce = dce

    def doRequest(self, request, noAnswer = 0, checkReturn = 1):
        self.dce.call(request.opnum, request)
        if noAnswer:
            return
        else:
            answer = self.dce.recv()
            if checkReturn and answer[-4:] != '\x00\x00\x00\x00':
                raise Exception, 'DCE-RPC call returned an error.'
            return answer
    
    def enumPrinters(self, name, flags = 0, level = 1):
        # first get the number of bytes needed
        enumPrinters = SpoolSS_EnumPrinters()
        enumPrinters['level'] = level
        enumPrinters['flags'] = flags
        enumPrinters['Name'] = name
        enumPrinters['PrinterEnum'] = ''
        ans = SpoolSS_EnumPrinters_answer(self.doRequest(enumPrinters, checkReturn = 0))
        #print("enumPrinters() needing %d bytes" % ans['cbNeeded'])

        # do the real request
        enumPrinters = SpoolSS_EnumPrinters()
        enumPrinters['level'] = level
        enumPrinters['flags'] = flags
        enumPrinters['Name'] = name
        enumPrinters['PrinterEnum'] = '\x00' * ans['cbNeeded']

        ans = SpoolSS_EnumPrinters_answer(self.doRequest(enumPrinters, checkReturn = 0))
        return ans
        
    def openPrinter(self, printerName, dataType, devMode, accessRequired):
        openPrinter = SpoolSS_OpenPrinter()
        if printerName: openPrinter['PrinterName'] = zeroize(printerName+'\x00')
        if dataType:    openPrinter['DataType']    = zeroize(dataType+'\x00')
        if devMode:
            devModeC = SpoolSS_DevModeContainer()
            # devModeC['DevMode'] = devModeC
            devModeC['cbBuf'] = 0
            devModeC['pDevMode'] = 0
            devModeC['DevMode'] = ''
            openPrinter['DevMode'] = '\x00\x00\x00\x00'
            openPrinter['pDevMode'] = 0
        openPrinter['AccessRequired'] = accessRequired

        return self.doRequest(openPrinter, checkReturn = 0)

    def enumPorts(self, level = 1, noAnswer = 0):
        # this one calls ntdll_RtlAcquirePebLock and ntdll_RtlReleasePebLock

        # first get the number of bytes needed
        enumPorts = SpoolSS_EnumPorts()
        enumPorts['level'] = level
        enumPorts['Port'] = ''
        if noAnswer:
            self.doRequest(enumPorts, noAnswer = 1)
        else:
            ans = SpoolSS_EnumPorts_answer(self.doRequest(enumPorts, checkReturn = 0))

            # do the real request
            enumPorts = SpoolSS_EnumPorts()
            # enumPorts['Name'] = '\\\x00\\\x00hola\x00\x00'
            enumPorts['level'] = level
            enumPorts['Port'] = '\x00'*ans['cbNeeded']
            ans = SpoolSS_EnumPorts_answer(self.doRequest(enumPorts, checkReturn = 0))
            # ans.dump('answer')
        
    def enumMonitors(self, level = 1):
        # first get the number of bytes needed
        enumMonitors = SpoolSS_EnumMonitors()
        enumMonitors['level'] = level
        enumMonitors['Monitor'] = ''
        ans = SpoolSS_EnumMonitors_answer(self.doRequest(enumMonitors, checkReturn = 0))

        # do the real request
        enumMonitors = SpoolSS_EnumMonitors()
        # enumMonitors['Name'] = '\\\x00\\\x00hola\x00\x00'
        enumMonitors['level'] = level
        enumMonitors['Monitor'] = '\x00'*ans['cbNeeded']
        ans = SpoolSS_EnumMonitors_answer(self.doRequest(enumMonitors, checkReturn = 0))
        # ans.dump('answer')
        
    def addMonitor(self, name, monitorName, environment, dllName):
        addMonitor = SpoolSS_AddMonitor()
        addMonitor['level'] = 2
        addMonitor['HostName'] = zeroize(name)
        addMonitor['Name'] = zeroize(monitorName) 
        addMonitor['Environment'] = zeroize(environment) 
        addMonitor['DLLName'] = zeroize(dllName) 
        ans = self.doRequest(addMonitor, checkReturn = 0)
        print "%r" % ans
        
    def addPort(self):
        addPort = SpoolSS_AddPort()
        addPort['Name'] = zeroize('\\192.168.22.90\x00')
        addPort['hWnd'] = 0
        addPort['MonitorName'] = zeroize('LanMan Print Services Port\x00')

        return self.doRequest(addPort)

    def addPortEx(self):
        port = SpoolSS_PortInfo1()
        port['Name'] = zeroize('Port Name\x00')

        addPortEx = SpoolSS_AddPortEx()
        addPortEx['Name'] = zeroize('\\\\192.168.22.90\x00')
        addPortEx['Port'] = port
        addPortEx['cbMonitorData'] = 0
        addPortEx['MonitorData'] = '\x00'*4
        addPortEx['MonitorName'] = zeroize('Monitor Name\x00')

        return self.doRequest(addPortEx)

    def addPrintProcessor(self):
        addPrintProcessor = SpoolSS_AddPrintProcessor()
        # addPrintProcessor['Name'] = zeroize('\\\\192.168.22.90\x00')
        addPrintProcessor['Environment'] = zeroize('Windows NT x86\x00')
        addPrintProcessor['PathName'] = zeroize('C:\\hola\\manola\x00')
        addPrintProcessor['PrintProcessorName'] = zeroize('chaucha\x00')

        return self.doRequest(addPrintProcessor)

    def deletePrinter(self, handle):
        deletePrinter = SpoolSS_DeletePrinter()
        deletePrinter['handle'] = handle
        self.doRequest(deletePrinter)

    def addPrinter(self, serverName, name, level = 1, flags = 0, comment = None, description = None):
        addPrinter = SpoolSS_AddPrinter()
        # length(Name)+length(PrinterName)+2+2 must be the size of the chunk following the overflown

        if serverName is not None:
            addPrinter['Name'] = serverName

        if level == 1:
                addPrinter['info'] = SpoolSS_PrinterInfo1()
                addPrinter['info']['Name'] = name
                addPrinter['info']['Description'] = description
                addPrinter['info']['flags'] = flags
        elif level == 2:
            addPrinter['info'] = SpoolSS_PrinterInfo2()
            addPrinter['info']['PrinterName'] = name
        else: 
            raise Exception, "Unknown PRINTER_INFO level"

        addPrinter['info']['Comment'] = comment

        addPrinter['blob'] = (                # to be improved
                "\x00\x00\x00\x00"*4
                )

        # addPrinter.dump('addPrinter')
        # addPrinter['info'].dump('info')
        return self.doRequest(addPrinter, checkReturn = 0)

    def addPrinterEx(self, serverName, name, comment = None):
        addPrinterEx = SpoolSS_AddPrinterEx()

        # length(Name)+length(PrinterName)+2+2 must be the size of the chunk following the overflow in mem

        addPrinterEx['Name'] = serverName

        addPrinterEx['info'] = SpoolSS_PrinterInfo2()
        addPrinterEx['info']['PrinterName'] = name
        addPrinterEx['info']['Comment'] = comment

        addPrinterEx['blob'] = (                # to be improved
                "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                "\x01\x00\x00\x00\x01\x00\x00\x00"

                "\xf8\xf3\x30\x00"
                "\x1c\x00\x00\x00"
                "\xf0\x62\xc9\x00"
                "\xe0\xf1\x30\x00"
                "\x93\x08\x00\x00"
                "\x03\x00\x00\x00"
                "\x00\x00\x00\x00"
                "\x00\x00\x00\x00"

                "\x08\x00\x00\x00\x00\x00\x00\x00\x08\x00\x00\x00"

                # \\ERATO
                "\x5c\x00\x5c\x00\x45\x00\x52\x00\x41\x00\x54\x00\x4f\x00\x00\x00"

                "\x0e\x00\x00\x00\x00\x00\x00\x00\x0e\x00\x00\x00"

                # Administrator
                "\x41\x00\x64\x00\x6d\x00\x69\x00\x6e\x00\x69\x00\x73\x00\x74\x00"
                "\x72\x00\x61\x00\x74\x00\x6f\x00\x72\x00\x00\x00"
            )

        return self.doRequest(addPrinterEx)



