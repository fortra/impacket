# Copyright (c) 2003-2012 CORE Security Technologies
#
# This software is provided under under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# $Id: dot11.py 227 2010-02-24 20:27:00Z 6e726d $
#
# Author:
#  Andres Blanco
#  Gustavo Moreira

#
# RFCs for the DNS Server service
#
# 1034 - Domain Names -- Concepts and Facilities [http://www.faqs.org/rfcs/rfc1034.html]
# 1035 - Domain Names -- Implementation and Specification [http://www.faqs.org/rfcs/rfc1035.html]
# 1123 - Requirements for Internet Hosts -- Application and Support [http://www.faqs.org/rfcs/rfc1123.html]
# 1886 - DNS Extensions to Support IP Version 6 [http://www.faqs.org/rfcs/rfc1886.html]
# 1995 - Incremental Zone Transfer in DNS [http://www.faqs.org/rfcs/rfc1995.html]
# 1996 - A Mechanism for Prompt Notification of Zone Changes (DNS NOTIFY) [http://www.faqs.org/rfcs/rfc1996.html]
# 2136 - Dynamic Updates in the Domain Name System (DNS UPDATE) [http://www.faqs.org/rfcs/rfc2136.html]
# 2181 - Clarifications to the DNS Specification [http://www.faqs.org/rfcs/rfc2181.html]
# 2308 - Negative Caching of DNS Queries (DNS NCACHE) [http://www.faqs.org/rfcs/rfc2308.html]
# 2535 - Domain Name System Security Extensions (DNSSEC) [http://www.faqs.org/rfcs/rfc2535.html]
# 2671 - Extension Mechanisms for DNS (EDNS0) [http://www.faqs.org/rfcs/rfc2671.html]
# 2782 - A DNS RR for specifying the location of services (DNS SRV) [http://www.faqs.org/rfcs/rfc2782.html]
# 2930 - Secret Key Establishment for DNS (TKEY RR) [http://www.faqs.org/rfcs/rfc2930.html]
# 3645 - Generic Security Service Algorithm for Secret Key Transaction Authentication for DNS (GSS-TSIG) [http://www.faqs.org/rfcs/rfc3645.html]
# 3646 - DNS Configuration options for Dynamic Host Configuration Protocol for IPv6 (DHCPv6) [http://www.faqs.org/rfcs/rfc3646.html]
#

import socket
import struct
from ImpactPacket import ProtocolPacket

class DNSFlags():
    'Bitmap with the flags of a dns packet.'
    # QR - Query/Response - 1 bit 
    QR_QUERY                = int("0000000000000000", 2)
    QR_RESPONSE             = int("1000000000000000", 2)
    # OP - Opcode - 4 bits
    OP_STANDARD_QUERY       = int("0000000000000000", 2) # Standard query.
    OP_INVERSE_QUERY        = int("0100000000000000", 2) # Inverse query.
    OP_STATUS_QUERY         = int("0010000000000000", 2) # Server status request.
    OP_NOTIFY               = int("0000100000000000", 2) # Notify.
    OP_UPDATE               = int("0100100000000000", 2) # Update.
    # AA - Authority Answer - 1 bit
    AA_NOT_AUTH_ANSWER      = int("0000000000000000", 2) # Not authoritative.
    AA_AUTH_ANSWER          = int("0000010000000000", 2) # Is authoritative.
    # TC - Truncated - 1 bit
    TC_NOT_TRUNCATED        = int("0000000000000000", 2) # Not truncated.
    TC_TRUNCATED            = int("0000001000000000", 2) # Message truncated.
    # RD - Recursion Desired - 1 bit
    RD_NOT_RECURSIVE_QUERY  = int("0000000000000000", 2) # Recursion not desired.
    RD_RECURSIVE_QUERY      = int("0000000100000000", 2) # Recursion desired.
    # RA - Recursion Available - 1 bit
    RA_NOT_AVAILABLE        = int("0000000000000000", 2) # Recursive query support not available.
    RA_AVAILABLE            = int("0000000010000000", 2) # Recursive query support available.
    # Z - 3 bits
    Z                       = int("0000000000000000", 2)
    # AD - Authenticated Data - 1 bit
    AUTHENTICATED_DATA      = int("0000000000100000", 2)
    # CD - Checking Disabled - 1 bit
    CHECKING_DISABLED       = int("0000000000010000", 2)
    # RCODE - 4 bits
    RCODE_NO_ERROR          = int("0000000000000000", 2) # The request completed successfully.
    RCODE_FORMAT_ERROR      = int("0000000000001000", 2) # The name server was unable to interpret the query.
    RCODE_SERVER_FAILURE    = int("0000000000000100", 2) # The name server was unable to process this query due to a problem with the name server.
    RCODE_NAME_ERROR        = int("0000000000001100", 2) # Meaningful only for responses from an authoritative name server, this code signifies that the domain name referenced in the query does not exist.
    RCODE_NOT_IMPLEMENTED   = int("0000000000000010", 2) # Not Implemented. The name server does not support the requested kind of query.
    RCODE_REFUSED           = int("0000000000001010", 2) # The name server refuses to perform the specified operation for policy reasons. 
    RCODE_YXDOMAIN          = int("0000000000000110", 2) # Name Exists when it should not.
    RCODE_YXRRSET           = int("0000000000001110", 2) # RR Set Exists when it should not.
    RCODE_NXRRSET           = int("0000000000000001", 2) # RR Set that should exist does not.
    RCODE_NOAUTH            = int("0000000000001001", 2) # Server Not Authoritative for zone.
    RCODE_NOTZONE           = int("0000000000000101", 2) # Name not contained in zone.

class DNSType():
    A            = 1     # IPv4 address.
    NS           = 2     # Authoritative name server.
    MD           = 3     # Mail destination. Obsolete use MX instead.
    MF           = 4     # Mail forwarder. Obsolete use MX instead.
    CNAME        = 5     # Canonical name for an alias.
    SOA          = 6     # Marks the start of a zone of authority.
    MB           = 7     # Mailbox domain name.
    MG           = 8     # Mail group member.
    MR           = 9     # Mail rename domain name.
    NULL         = 10    # Null resource record.
    WKS          = 11    # Well known service description.
    PTR          = 12    # Domain name pointer.
    HINFO        = 13    # Host information.
    MINFO        = 14    # Mailbox or mail list information.
    MX           = 15    # Mail exchange.
    TXT          = 16    # Text strings.
    RP           = 17    # Responsible Person.
    AFSDB        = 18    # AFS Data Base location.
    X25          = 19    # X.25 PSDN address.
    ISDN         = 20    # ISDN address.
    RT           = 21    # Route Through.
    NSAP         = 22    # NSAP address. NSAP style A record.
    NSAP_PTR     = 23    # NSAP pointer.
    SIG          = 24    # Security signature.
    KEY          = 25    # Security key.
    PX           = 26    # X.400 mail mapping information.
    GPOS         = 27    # Geographical Position.
    AAAA         = 28    # IPv6 Address.
    LOC          = 29    # Location Information.
    NXT          = 30    # Next Domain (obsolete).
    EID          = 31    # Endpoint Identifier.
    NB           = 32    # NetBIOS general Name Service.
    NBSTAT       = 33    # NetBIOS NODE STATUS.
    ATMA         = 34    # ATM Address.
    NAPTR        = 35    # Naming Authority Pointer.
    KX           = 36    # Key Exchanger.
    CERT         = 37
    A6           = 38
    DNAME        = 39
    SINK         = 40
    OPT          = 41
    APL          = 42
    DS           = 43    # Delegation Signer.
    SSHFP        = 44    # SSH Key Fingerprint.
    IPSECKEY     = 45
    RRSIG        = 46
    NSEC         = 47    # NextSECure.
    DNSKEY       = 48
    DHCID        = 49    # DHCP identifier.
    NSEC3        = 50
    NSEC3PARAM   = 51
    
    HIP          = 55    # Host Identity Protocol.
    NINFO        = 56
    RKEY         = 57
    
    SPF          = 99    # Sender Policy Framework.
    UINFO        = 100
    UID          = 101
    GID          = 102
    UNSPEC       = 103
    
    TKEY         = 249
    TSIG         = 250   # Transaction Signature.
    IXFR         = 251   # Incremental transfer.
    AXFR         = 252   # A request for a transfer of an entire zone.
    MAILB        = 253   # A request for mailbox-related records (MB, MG or MR).
    MAILA        = 254   # A request for mail agent RRs. Obsolete.
    ALL          = 255   # A request for all records.
    
    DNSSEC       = 32768 # Trust Authorities.
    DNSSEC       = 32769 # DNSSEC Lookaside Validation.
    
    @staticmethod
    def getTypeName(type):
        for item, value in DNSType.__dict__.items():
            if value == type:
                return item
    

class DNSClass():
    RESERVED     = 0
    IN           = 1 # Internet.
    CH           = 3 # Chaos.
    HS           = 4 # Hesiod.
    
    NONE         = 254
    ANY          = 255 # QCLASS only
    
    @staticmethod
    def getClassName(type):
        for item, value in DNSClass.__dict__.items():
            if value == type:
                return item

class DNS(ProtocolPacket):
    '''The Message Header is present in all messages. Never empty.
    Contains various flags and values which control the transaction.'''
    
    __TYPE_LEN       = 2 # Unsigned 16 bit value.
    __CLASS_LEN      = 2 # Unsigned 16 bit value.
    __POINTER_LEN    = 2 # A pointer is an unsigned 16-bit value.
    __TTL_LEN        = 4 # Unsigned 32 bit value. The time in seconds that the record may be cached.
    __RDLENGTH_LEN   = 2 # Unsigned 16-bit value that defines the length in bytes (octets) of the RDATA record.
    __TYPE_A_LEN     = 4 # Unsigned 32-bit value representing the IP address.
    __SERIAL_LEN     = 4 # Serial Number  Unsigned 32-bit integer.
    __REFRESH_LEN    = 4 # Refresh interval  Unsigned 32-bit integer.
    __RETRY_LEN      = 4 # Retry Interval  Unsigned 32-bit integer.
    __EXPIRATION_LEN = 4 # Expiration Limit  Unsigned 32-bit integer.
    __MINTTL_LEN     = 4 # Minimum TTL  Unsigned 32-bit integer.
    __PREF_LEN       = 2 # Preference  Unsigned 16-bit integer.
    __IS_POINTER   = int("11000000", 2)
    __OFFSETMASK   = int("00111111", 2)
    
    def __init__(self, aBuffer = None):
        self.__HEADER_BASE_SIZE = 12
        self.__TAIL_SIZE        = 0
        ProtocolPacket.__init__(self, self.__HEADER_BASE_SIZE, self.__TAIL_SIZE)
        if aBuffer:
            self.load_packet(aBuffer)
    
    def get_transaction_id(self):
        'Get 16 bit message ID.'
        return self.header.get_word(0)
    
    def set_transaction_id(self, value):
        'Set 16 bit message ID.'
        self.header.set_word(0, value)
    
    def get_flags(self):
        'Get 16 bit flags.'
        return self.header.get_word(2)
    
    def set_flags(self, value):
        'Set 16 bit flags.'
        self.header.set_word(2, value)
    
    def get_qdcount(self):
        'Get Unsigned 16 bit integer specifying the number of entries in the question section.'
        return self.header.get_word(4)
    
    def set_qdcount(self, value):
        'Set Unsigned 16 bit integer specifying the number of entries in the question section.'
        self.header.set_word(4, value)
    
    def get_ancount(self):
        'Get Unsigned 16 bit integer specifying the number of resource records in the answer section'
        return self.header.get_word(6)
    
    def set_ancount(self, value):
        'Set Unsigned 16 bit integer specifying the number of resource records in the answer section'
        self.header.set_word(6, value)
    
    def get_nscount(self):
        'Get Unsigned 16 bit integer specifying the number of name server resource records in the authority section.'
        return self.header.get_word(8)
    
    def set_nscount(self, value):
        'Set Unsigned 16 bit integer specifying the number of name server resource records in the authority section.'
        self.header.set_word(8, value)
    
    def get_arcount(self):
        'Get Unsigned 16 bit integer specifying the number of resource records in the additional records section.'
        return self.header.get_word(10)
    
    def set_arcount(self, value):
        'Set Unsigned 16 bit integer specifying the number of resource records in the additional records section.'
        self.header.set_word(10, value)
    
    def get_questions(self):
        'Get a list of the DNS Question.'
        return self.__get_questions()[0]
    
    def __get_questions(self):
        aux = []
        offset   = 0
        qdcount = self.get_qdcount()
        data    = self.get_body_as_string()
        for i in range(qdcount): # number of questions
            offset, qname = self.parseCompressedMessage(data, offset)
            qtype  = data[offset:offset+self.__TYPE_LEN]
            offset  += self.__TYPE_LEN
            qclass = data[offset:offset+self.__CLASS_LEN]
            offset  += self.__CLASS_LEN
            qtype  = struct.unpack("!H", qtype)[0]
            qclass = struct.unpack("!H", qclass)[0]
            aux.append((qname, qtype, qclass))
        return (aux, offset)

    def parseCompressedMessage(self, buffer, offset=0):
        'Parse compressed message defined on rfc1035 4.1.4.'
        if offset >= len(buffer):
            raise Exception("No more data to parse. Offset is bigger than length of buffer.")
        byte = struct.unpack("B", buffer[offset])[0]
        if byte & 0xC0 == 0xC0:
            pointer = struct.unpack("!H", buffer[offset:offset+2])[0] # network unsigned short
            pointer = (pointer & 0x3FFF) - self.__HEADER_BASE_SIZE
            offset += 2
            name = self.parseCompressedMessage(buffer, pointer)[1]
            return (offset, name)
        else:
            if byte == 0x00:
                offset += 1
                return (offset, '')
            offset += 1
            name = buffer[offset:offset+byte]
            offset += byte
            offset, unamed = self.parseCompressedMessage(buffer, offset)
            if not unamed:
                return (offset, name)
            else:
                return (offset, name + "." + unamed)
    
    def get_answers(self):
        return self.__get_answers()[0]
    
    def get_authoritatives(self):
        return self.__get_authoritatives()[0]
    
    def get_additionals(self):
        return self.__get_additionals()[0]
    
    def __get_answers(self):
        offset  = self.__get_questions()[1] # get the initial offset
        ancount = self.get_ancount()
        return self.__process_answer_structure(offset, ancount)
    
    def __get_authoritatives(self):
        'Get a list of the DNS Authoritatives.'
        offset  = self.__get_answers()[1] # get the initial offset
        nscount = self.get_nscount()
        return self.__process_answer_structure(offset, nscount)
    
    def __get_additionals(self):
        'Get a list of the DNS Additional Records.'
        offset  = self.__get_authoritatives()[1] # get the initial offset
        arcount = self.get_arcount()
        return self.__process_answer_structure(offset, arcount)
    
    def __process_answer_structure(self, offset, num):
        aux  = []
        data = self.get_body_as_string()
        for i in range(num):
            offset, qname = self.parseCompressedMessage(data, offset)
            qtype  = data[offset:offset+self.__TYPE_LEN]
            offset  += self.__TYPE_LEN
            qclass = data[offset:offset+self.__CLASS_LEN]
            offset  += self.__CLASS_LEN
            qtype  = struct.unpack("!H", qtype)[0]
            qclass = struct.unpack("!H", qclass)[0]
            qttl = data[offset:offset+self.__TTL_LEN]
            qttl = struct.unpack("!L", qttl)[0]
            offset  += self.__TTL_LEN
            qrdlength = data[offset:offset+self.__RDLENGTH_LEN]
            qrdlength = struct.unpack("!H", qrdlength)[0]
            offset  += self.__RDLENGTH_LEN
            qrdata = {}
            if qtype == DNSType.A:
                # IP Address  Unsigned 32-bit value representing the IP address
                qrdata["IPAddress"] = socket.inet_ntoa(data[offset:offset+qrdlength])
                offset  += self.__TYPE_A_LEN
            elif qtype == DNSType.SOA:
                # Primary NS  Variable length. The name of the Primary Master for the domain. May be a label, pointer or any combination.
                offset, primaryNs = self.parseCompressedMessage(data, offset)
                qrdata["PrimaryNS"] = primaryNs
                # Admin MB  Variable length. The administrator's mailbox. May be a label, pointer or any combination.
                offset, adminMb = self.parseCompressedMessage(data, offset)
                qrdata["AdminMB"] = adminMb
                # Serial Number  Unsigned 32-bit integer.
                qrdata["SerialNumber"] = struct.unpack("!L", data[offset:offset+self.__SERIAL_LEN])[0]
                offset += self.__SERIAL_LEN
                # Refresh interval  Unsigned 32-bit integer.
                qrdata["RefreshInterval"] = struct.unpack("!L", data[offset:offset+self.__REFRESH_LEN])[0]
                offset += self.__REFRESH_LEN
                # Retry Interval  Unsigned 32-bit integer.
                qrdata["RetryInterval"] = struct.unpack("!L", data[offset:offset+self.__RETRY_LEN])[0]
                offset += self.__RETRY_LEN
                # Expiration Limit  Unsigned 32-bit integer.
                qrdata["ExpirationLimit"] = struct.unpack("!L", data[offset:offset+self.__EXPIRATION_LEN])[0]
                offset += self.__EXPIRATION_LEN
                # Minimum TTL  Unsigned 32-bit integer.
                qrdata["MinimumTTL"] = struct.unpack("!L", data[offset:offset+self.__MINTTL_LEN])[0]
                offset += self.__MINTTL_LEN
            elif qtype == DNSType.MX:
                # Preference  Unsigned 16-bit integer.
                qrdata["Preference"] = struct.unpack("!H", data[offset:offset+self.__PREF_LEN])[0]
                # Mail Exchanger  The name host name that provides the service. May be a label, pointer or any combination.
                offset, mailExch = self.parseCompressedMessage(data, offset)
                qrdata["MailExchanger"] = mailExch
            elif qtype == DNSType.PTR or qtype == DNSType.NS or qtype == DNSType.CNAME:
                # Name  The host name that represents the supplied IP address (in the case of a PTR) or the NS name for the supplied domain (in the case of NS). May be a label, pointer or any combination.
                offset, name = self.parseCompressedMessage(data, offset)
                qrdata["Name"] = name
            else:
                offset  += qrdlength
            aux.append((qname, qtype, qclass, qttl, qrdata))
        return (aux, offset)
    
    def get_header_size(self):
        return 12
    
    def __str__(self):
        res = ""
        
        id      = self.get_transaction_id()
        flags   = self.get_flags()
        qdcount = self.get_qdcount()
        ancount = self.get_ancount()
        nscount = self.get_nscount()
        arcount = self.get_arcount()
        
        res += "DNS "
        if flags & DNSFlags.QR_RESPONSE:
            res += "RESPONSE\n"
        else:
            res += "QUERY\n"
        
        res += " - Transaction ID -- [0x%04x] %d\n" % (id, id)
        res += " - Flags ----------- [0x%04x] %d\n" % (flags, flags)
        res += " - QdCount --------- [0x%04x] %d\n" % (qdcount, qdcount)
        res += " - AnCount --------- [0x%04x] %d\n" % (ancount, ancount)
        res += " - NsCount --------- [0x%04x] %d\n" % (nscount, nscount)
        res += " - ArCount --------- [0x%04x] %d\n" % (arcount, arcount)
        
        if qdcount > 0:
            res += " - Questions:\n"
            questions = self.get_questions()
            questions.reverse()
            while(questions):
                qname, qtype, qclass = questions.pop()
                format = (qname, DNSType.getTypeName(qtype), qtype, DNSClass.getClassName(qclass), qclass)
                res += "  * Domain: %s - Type: %s [%04x] - Class: %s [%04x]\n" % format
        
        if ancount > 0:
            res += " - Answers:\n"
            answers = self.get_answers()
            answers.reverse()
            while(answers):
                qname, qtype, qclass, qttl, qrdata = answers.pop()
                format = (qname, DNSType.getTypeName(qtype), qtype, DNSClass.getClassName(qclass), qclass, qttl, repr(qrdata))
                res += "  * Domain: %s - Type: %s [%04x] - Class: %s [%04x] - TTL: %d seconds - %s\n" % format
        
        if nscount > 0:
            res += " - Authoritatives:\n"
            authoritatives = self.get_authoritatives()
            authoritatives.reverse()
            while(authoritatives):
                qname, qtype, qclass, qttl, qrdata = authoritatives.pop()
                format = (qname, DNSType.getTypeName(qtype), qtype, DNSClass.getClassName(qclass), qclass, qttl, repr(qrdata))
                res += "  * Domain: %s - Type: %s [%04x] - Class: %s [%04x] - TTL: %d seconds - %s\n" % format
        
        if arcount > 0:
            res += " - Additionals:\n"
            additionals = self.get_additionals()
            additionals.reverse()
            while(additionals):
                qname, qtype, qclass, qttl, qrdata = additionals.pop()
                format = (qname, DNSType.getTypeName(qtype), qtype, DNSClass.getClassName(qclass), qclass, qttl, repr(qrdata))
                res += "  * Domain: %s - Type: %s [%04x] - Class: %s [%04x] - TTL: %d seconds - %s\n" % format
        
        return res
    
    def get_packet(self):
        return Header.get_packet(self)

if __name__ == "__main__":
    pkts = [
            "\x6a\x8c\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03\x77\x77\x77" \
            "\x05\x74\x61\x72\x74\x61\x03\x63\x6f\x6d\x00\x00\x01\x00\x01",
            "\x6a\x8c\x81\x80\x00\x01\x00\x02\x00\x02\x00\x00\x03\x77\x77\x77" \
            "\x05\x74\x61\x72\x74\x61\x03\x63\x6f\x6d\x00\x00\x01\x00\x01\xc0" \
            "\x0c\x00\x05\x00\x01\x00\x00\x07\x08\x00\x02\xc0\x10\xc0\x10\x00" \
            "\x01\x00\x01\x00\x00\x07\x08\x00\x04\x45\x59\x1f\xc7\xc0\x10\x00" \
            "\x02\x00\x01\x00\x02\xa3\x00\x00\x0f\x03\x6e\x73\x31\x08\x62\x6c" \
            "\x75\x65\x68\x6f\x73\x74\xc0\x16\xc0\x10\x00\x02\x00\x01\x00\x02" \
            "\xa3\x00\x00\x06\x03\x6e\x73\x32\xc0\x4d",
            "\x82\x75\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03\x77\x77\x77" \
            "\x04\x6a\x68\x6f\x6e\x03\x63\x6f\x6d\x00\x00\x01\x00\x01",
            "\x82\x75\x81\x80\x00\x01\x00\x01\x00\x02\x00\x02\x03\x77\x77\x77" \
            "\x04\x6a\x68\x6f\x6e\x03\x63\x6f\x6d\x00\x00\x01\x00\x01\xc0\x0c" \
            "\x00\x01\x00\x01\x00\x00\x00\x05\x00\x04\xd1\x3b\xc3\x14\xc0\x10" \
            "\x00\x02\x00\x01\x00\x00\x06\xf8\x00\x0f\x03\x6e\x73\x31\x08\x74" \
            "\x72\x61\x66\x66\x69\x63\x7a\xc0\x15\xc0\x10\x00\x02\x00\x01\x00" \
            "\x00\x06\xf8\x00\x06\x03\x6e\x73\x32\xc0\x3e\xc0\x3a\x00\x01\x00" \
            "\x01\x00\x00\x00\x0d\x00\x04\xd1\x3b\xc2\xf6\xc0\x55\x00\x01\x00" \
            "\x01\x00\x00\x00\x85\x00\x04\xd1\x3b\xc3\xf6",
            "\xef\x55\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x04\x6d\x61\x69" \
            "\x6c\x06\x67\x6f\x6f\x67\x6c\x65\x03\x63\x6f\x6d\x00\x00\x01\x00" \
            "\x01",
            "\xef\x55\x81\x80\x00\x01\x00\x04\x00\x04\x00\x04\x04\x6d\x61\x69" \
            "\x6c\x06\x67\x6f\x6f\x67\x6c\x65\x03\x63\x6f\x6d\x00\x00\x01\x00" \
            "\x01\xc0\x0c\x00\x05\x00\x01\x00\x00\x06\x79\x00\x0f\x0a\x67\x6f" \
            "\x6f\x67\x6c\x65\x6d\x61\x69\x6c\x01\x6c\xc0\x11\xc0\x2d\x00\x01" \
            "\x00\x01\x00\x00\x00\x77\x00\x04\xd1\x55\xc3\x53\xc0\x2d\x00\x01" \
            "\x00\x01\x00\x00\x00\x77\x00\x04\xd1\x55\xc3\x12\xc0\x2d\x00\x01" \
            "\x00\x01\x00\x00\x00\x77\x00\x04\xd1\x55\xc3\x13\xc0\x11\x00\x02" \
            "\x00\x01\x00\x00\x00\x5d\x00\x06\x03\x6e\x73\x33\xc0\x11\xc0\x11" \
            "\x00\x02\x00\x01\x00\x00\x00\x5d\x00\x06\x03\x6e\x73\x34\xc0\x11" \
            "\xc0\x11\x00\x02\x00\x01\x00\x00\x00\x5d\x00\x06\x03\x6e\x73\x31" \
            "\xc0\x11\xc0\x11\x00\x02\x00\x01\x00\x00\x00\x5d\x00\x06\x03\x6e" \
            "\x73\x32\xc0\x11\xc0\x9c\x00\x01\x00\x01\x00\x00\x04\x4e\x00\x04" \
            "\xd8\xef\x20\x0a\xc0\xae\x00\x01\x00\x01\x00\x00\x06\x64\x00\x04" \
            "\xd8\xef\x22\x0a\xc0\x78\x00\x01\x00\x01\x00\x00\x00\x05\x00\x04" \
            "\xd8\xef\x24\x0a\xc0\x8a\x00\x01\x00\x01\x00\x00\x00\x08\x00\x04" \
            "\xd8\xef\x26\x0a"
           ]
    
    for pkt in pkts:
        d = DNS(pkt)
        print d
