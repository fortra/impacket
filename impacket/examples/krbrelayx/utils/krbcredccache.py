from impacket.krb5.constants import TicketFlags
from impacket.krb5.ccache import CCache, Header, Credential, Times, CountedOctetString, Principal, Ticket
from impacket.krb5 import types
from pyasn1.codec.der import encoder

try:
    from impacket.krb5.ccache import KeyBlockV4
except ImportError:
    from impacket.krb5.ccache import KeyBlock

class KrbCredCCache(CCache):
    """
    This is just the impacket ccache, but with an extra function to create it from
    a Krb Cred Ticket and ticket data
    """
    def fromKrbCredTicket(self, ticket, ticketdata):
        self.headers = []
        header = Header()
        header['tag'] = 1
        header['taglen'] = 8
        header['tagdata'] = '\xff\xff\xff\xff\x00\x00\x00\x00'
        self.headers.append(header)


        tmpPrincipal = types.Principal()
        tmpPrincipal.from_asn1(ticketdata, 'prealm', 'pname')
        self.principal = Principal()
        self.principal.fromPrincipal(tmpPrincipal)

        encASRepPart = ticketdata

        credential = Credential()
        server = types.Principal()
        server.from_asn1(encASRepPart, 'srealm', 'sname')
        tmpServer = Principal()
        tmpServer.fromPrincipal(server)

        credential['client'] = self.principal
        credential['server'] = tmpServer
        credential['is_skey'] = 0

        try:
            credential['key'] = KeyBlockV4()
        except NameError:
            credential['key'] = KeyBlock()
        credential['key']['keytype'] = int(encASRepPart['key']['keytype'])
        credential['key']['keyvalue'] = bytes(encASRepPart['key']['keyvalue'])
        credential['key']['keylen'] = len(credential['key']['keyvalue'])

        credential['time'] = Times()
        credential['time']['authtime'] = self.toTimeStamp(types.KerberosTime.from_asn1(encASRepPart['starttime']))
        credential['time']['starttime'] = self.toTimeStamp(types.KerberosTime.from_asn1(encASRepPart['starttime']))
        credential['time']['endtime'] = self.toTimeStamp(types.KerberosTime.from_asn1(encASRepPart['endtime']))
        credential['time']['renew_till'] = self.toTimeStamp(types.KerberosTime.from_asn1(encASRepPart['renew-till']))

        flags = self.reverseFlags(encASRepPart['flags'])
        credential['tktflags'] = flags

        credential['num_address'] = 0
        credential.ticket = CountedOctetString()
        credential.ticket['data'] = encoder.encode(ticket.clone(tagSet=Ticket.tagSet, cloneValueFlag=True))
        credential.ticket['length'] = len(credential.ticket['data'])
        credential.secondTicket = CountedOctetString()
        credential.secondTicket['data'] = ''
        credential.secondTicket['length'] = 0
        self.credentials.append(credential)
