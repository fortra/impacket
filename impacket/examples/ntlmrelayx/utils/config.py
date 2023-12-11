# Impacket - Collection of Python classes for working with network protocols.
#
# SECUREAUTH LABS. Copyright (C) 2022 SecureAuth Corporation. All rights reserved.
#
# This software is provided under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Description:
#   Config utilities
#
#   Configuration class which holds the config specified on the
#   command line, this can be passed to the tools' servers and clients
#
# Author:
#  Dirk-jan Mollema / Fox-IT (https://www.fox-it.com)
#
from impacket.examples.utils import parse_credentials


class NTLMRelayxConfig:
    def __init__(self):

        self.daemon = True

        # Set the value of the interface ip address
        self.interfaceIp = None

        self.listeningPort = None

        self.domainIp = None

        self.machineAccount = None
        self.machineHashes = None
        self.target = None
        self.mode = None
        self.redirecthost = None
        self.outputFile = None
        self.attacks = None
        self.lootdir = None
        self.randomtargets = False
        self.encoding = None
        self.ipv6 = False
        self.remove_mic = False
        self.disableMulti = False

        self.command = None

        # WPAD options
        self.serve_wpad = False
        self.wpad_host = None
        self.wpad_auth_num = 0
        self.smb2support = False

        # WPAD options
        self.serve_wpad = False
        self.wpad_host = None
        self.wpad_auth_num = 0
        self.smb2support = False

        # SMB options
        self.exeFile = None
        self.interactive = False
        self.enumLocalAdmins = False
        self.SMBServerChallenge = None

        # RPC options
        self.rpc_mode = None
        self.rpc_use_smb = False
        self.auth_smb = ''
        self.smblmhash = None
        self.smbnthash = None
        self.port_smb = 445

        # LDAP options
        self.dumpdomain = True
        self.addda = True
        self.aclattack = True
        self.validateprivs = True
        self.escalateuser = None

        # MSSQL options
        self.queries = []

        # Registered protocol clients
        self.protocolClients = {}

        # SOCKS options
        self.runSocks = False
        self.socksServer = None

        # HTTP options
        self.remove_target = False

        # WebDAV options
        self.serve_image = False

        # AD CS attack options
        self.isADCSAttack = False
        self.template = None
        self.altName = None

        # Shadow Credentials attack options
        self.IsShadowCredentialsAttack = False
        self.ShadowCredentialsPFXPassword = None
        self.ShadowCredentialsExportType = None
        self.ShadowCredentialsOutfilePath = None

    def setSMBChallenge(self, value):
        self.SMBServerChallenge = value

    def setSMB2Support(self, value):
        self.smb2support = value

    def setProtocolClients(self, clients):
        self.protocolClients = clients

    def setInterfaceIp(self, ip):
        self.interfaceIp = ip

    def setListeningPort(self, port):
        self.listeningPort = port

    def setRunSocks(self, socks, server):
        self.runSocks = socks
        self.socksServer = server

    def setOutputFile(self, outputFile):
        self.outputFile = outputFile

    def setTargets(self, target):
        self.target = target

    def setExeFile(self, filename):
        self.exeFile = filename

    def setCommand(self, command):
        self.command = command

    def setEnumLocalAdmins(self, enumLocalAdmins):
        self.enumLocalAdmins = enumLocalAdmins

    def setDisableMulti(self, disableMulti):
        self.disableMulti = disableMulti

    def setEncoding(self, encoding):
        self.encoding = encoding

    def setMode(self, mode):
        self.mode = mode

    def setAttacks(self, attacks):
        self.attacks = attacks

    def setLootdir(self, lootdir):
        self.lootdir = lootdir

    def setRedirectHost(self, redirecthost):
        self.redirecthost = redirecthost

    def setDomainAccount(self, machineAccount, machineHashes, domainIp):
        # Don't set this if we're not exploiting it
        if not self.remove_target:
            return
        if machineAccount is None or machineHashes is None or domainIp is None:
            raise Exception("You must specify machine-account/hashes/domain all together!")
        self.machineAccount = machineAccount
        self.machineHashes = machineHashes
        self.domainIp = domainIp

    def setRandomTargets(self, randomtargets):
        self.randomtargets = randomtargets

    def setLDAPOptions(self, dumpdomain, addda, aclattack, validateprivs, escalateuser, addcomputer, delegateaccess, dumplaps, dumpgmsa, dumpadcs, sid):
        self.dumpdomain = dumpdomain
        self.addda = addda
        self.aclattack = aclattack
        self.validateprivs = validateprivs
        self.escalateuser = escalateuser
        self.addcomputer = addcomputer
        self.delegateaccess = delegateaccess
        self.dumplaps = dumplaps
        self.dumpgmsa = dumpgmsa
        self.dumpadcs = dumpadcs
        self.sid = sid

    def setMSSQLOptions(self, queries):
        self.queries = queries

    def setRPCOptions(self, rpc_mode, rpc_use_smb, auth_smb, hashes_smb, rpc_smb_port):
        self.rpc_mode = rpc_mode
        self.rpc_use_smb = rpc_use_smb
        self.smbdomain, self.smbuser, self.smbpass = parse_credentials(auth_smb)

        if hashes_smb is not None:
            self.smblmhash, self.smbnthash = hashes_smb.split(':')
        else:
            self.smblmhash = ''
            self.smbnthash = ''

        self.rpc_smb_port = rpc_smb_port

    def setInteractive(self, interactive):
        self.interactive = interactive

    def setIMAPOptions(self, keyword, mailbox, dump_all, dump_max):
        self.keyword = keyword
        self.mailbox = mailbox
        self.dump_all = dump_all
        self.dump_max = dump_max

    def setIPv6(self, use_ipv6):
        self.ipv6 = use_ipv6

    def setWpadOptions(self, wpad_host, wpad_auth_num):
        if wpad_host is not None:
            self.serve_wpad = True
        self.wpad_host = wpad_host
        self.wpad_auth_num = wpad_auth_num

    def setExploitOptions(self, remove_mic, remove_target):
        self.remove_mic = remove_mic
        self.remove_target = remove_target

    def setWebDAVOptions(self, serve_image):
        self.serve_image = serve_image

    def setADCSOptions(self, template):
        self.template = template

    def setIsADCSAttack(self, isADCSAttack):
        self.isADCSAttack = isADCSAttack

    def setIsShadowCredentialsAttack(self, IsShadowCredentialsAttack):
        self.IsShadowCredentialsAttack = IsShadowCredentialsAttack

    def setShadowCredentialsOptions(self, ShadowCredentialsTarget, ShadowCredentialsPFXPassword, ShadowCredentialsExportType, ShadowCredentialsOutfilePath):
        self.ShadowCredentialsTarget = ShadowCredentialsTarget
        self.ShadowCredentialsPFXPassword = ShadowCredentialsPFXPassword
        self.ShadowCredentialsExportType = ShadowCredentialsExportType
        self.ShadowCredentialsOutfilePath = ShadowCredentialsOutfilePath

    def setAltName(self, altName):
        self.altName = altName

def parse_listening_ports(value):
    ports = set()
    for entry in value.split(","):
        items = entry.split("-")
        if len(items) > 2:
            raise ValueError
        if len(items) == 1:
            ports.add(int(items[0])) # Can raise ValueError if casted value not an Int, will be caught by calling method
            continue
        item1, item2 = map(int, items) # Can raise ValueError if casted values not an Int, will be caught by calling method
        if item2 < item1:
            raise ValueError("Upper bound in port range smaller than lower bound")
        ports.update(range(item1, item2 + 1))

    return ports
