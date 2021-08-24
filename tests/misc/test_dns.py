#!/usr/bin/env python
# Impacket - Collection of Python classes for working with network protocols.
#
# SECUREAUTH LABS. Copyright (C) 2021 SecureAuth Corporation. All rights reserved.
#
# This software is provided under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
import unittest

from impacket.dns import DNS


class DNSTests(unittest.TestCase):
    def test_str(self):
        def chk(b, t):
            self.assertEqual(str(DNS(b)), t)

        chk(b"\x6a\x8c\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03\x77\x77\x77"
            b"\x05\x74\x61\x72\x74\x61\x03\x63\x6f\x6d\x00\x00\x01\x00\x01",
            "DNS QUERY\n - Transaction ID -- [0x6a8c] 27276\n"
            " - Flags ----------- [0x0100] 256\n"
            " - QdCount --------- [0x0001] 1\n"
            " - AnCount --------- [0x0000] 0\n"
            " - NsCount --------- [0x0000] 0\n"
            " - ArCount --------- [0x0000] 0\n"
            " - Questions:\n"
            "  * Domain: www.tarta.com - Type: A [0x0001] - Class: IN [0x0001]\n")

        chk(b"\x6a\x8c\x81\x80\x00\x01\x00\x02\x00\x02\x00\x00\x03\x77\x77\x77"
            b"\x05\x74\x61\x72\x74\x61\x03\x63\x6f\x6d\x00\x00\x01\x00\x01\xc0"
            b"\x0c\x00\x05\x00\x01\x00\x00\x07\x08\x00\x02\xc0\x10\xc0\x10\x00"
            b"\x01\x00\x01\x00\x00\x07\x08\x00\x04\x45\x59\x1f\xc7\xc0\x10\x00"
            b"\x02\x00\x01\x00\x02\xa3\x00\x00\x0f\x03\x6e\x73\x31\x08\x62\x6c"
            b"\x75\x65\x68\x6f\x73\x74\xc0\x16\xc0\x10\x00\x02\x00\x01\x00\x02"
            b"\xa3\x00\x00\x06\x03\x6e\x73\x32\xc0\x4d",
            "DNS RESPONSE\n"
            " - Transaction ID -- [0x6a8c] 27276\n"
            " - Flags ----------- [0x8180] 33152\n"
            " - QdCount --------- [0x0001] 1\n"
            " - AnCount --------- [0x0002] 2\n"
            " - NsCount --------- [0x0002] 2\n"
            " - ArCount --------- [0x0000] 0\n"
            " - Questions:\n"
            "  * Domain: www.tarta.com - Type: A [0x0001] - Class: IN [0x0001]\n"
            " - Answers:\n"
            "  * Domain: www.tarta.com - Type: CNAME [0x0005] - Class: IN [0x0001] - TTL: 1800 seconds - {'Name': 'tarta.com'}\n"
            "  * Domain: tarta.com - Type: A [0x0001] - Class: IN [0x0001] - TTL: 1800 seconds - {'IPAddress': '69.89.31.199'}\n"
            " - Authoritative:\n"
            "  * Domain: tarta.com - Type: NS [0x0002] - Class: IN [0x0001] - TTL: 172800 seconds - {'Name': 'ns1.bluehost.com'}\n"
            "  * Domain: tarta.com - Type: NS [0x0002] - Class: IN [0x0001] - TTL: 172800 seconds - {'Name': 'ns2.bluehost.com'}\n")

        chk(b"\x82\x75\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03\x77\x77\x77"
            b"\x04\x6a\x68\x6f\x6e\x03\x63\x6f\x6d\x00\x00\x01\x00\x01",
            "DNS QUERY\n"
            " - Transaction ID -- [0x8275] 33397\n"
            " - Flags ----------- [0x0100] 256\n"
            " - QdCount --------- [0x0001] 1\n"
            " - AnCount --------- [0x0000] 0\n"
            " - NsCount --------- [0x0000] 0\n"
            " - ArCount --------- [0x0000] 0\n"
            " - Questions:\n"
            "  * Domain: www.jhon.com - Type: A [0x0001] - Class: IN [0x0001]\n")

        chk(b"\x82\x75\x81\x80\x00\x01\x00\x01\x00\x02\x00\x02\x03\x77\x77\x77"
            b"\x04\x6a\x68\x6f\x6e\x03\x63\x6f\x6d\x00\x00\x01\x00\x01\xc0\x0c"
            b"\x00\x01\x00\x01\x00\x00\x00\x05\x00\x04\xd1\x3b\xc3\x14\xc0\x10"
            b"\x00\x02\x00\x01\x00\x00\x06\xf8\x00\x0f\x03\x6e\x73\x31\x08\x74"
            b"\x72\x61\x66\x66\x69\x63\x7a\xc0\x15\xc0\x10\x00\x02\x00\x01\x00"
            b"\x00\x06\xf8\x00\x06\x03\x6e\x73\x32\xc0\x3e\xc0\x3a\x00\x01\x00"
            b"\x01\x00\x00\x00\x0d\x00\x04\xd1\x3b\xc2\xf6\xc0\x55\x00\x01\x00"
            b"\x01\x00\x00\x00\x85\x00\x04\xd1\x3b\xc3\xf6",
            "DNS RESPONSE\n"
            " - Transaction ID -- [0x8275] 33397\n"
            " - Flags ----------- [0x8180] 33152\n"
            " - QdCount --------- [0x0001] 1\n"
            " - AnCount --------- [0x0001] 1\n"
            " - NsCount --------- [0x0002] 2\n"
            " - ArCount --------- [0x0002] 2\n"
            " - Questions:\n"
            "  * Domain: www.jhon.com - Type: A [0x0001] - Class: IN [0x0001]\n"
            " - Answers:\n"
            "  * Domain: www.jhon.com - Type: A [0x0001] - Class: IN [0x0001] - TTL: 5 seconds - {'IPAddress': '209.59.195.20'}\n"
            " - Authoritative:\n"
            "  * Domain: jhon.com - Type: NS [0x0002] - Class: IN [0x0001] - TTL: 1784 seconds - {'Name': 'ns1.trafficz.com'}\n"
            "  * Domain: jhon.com - Type: NS [0x0002] - Class: IN [0x0001] - TTL: 1784 seconds - {'Name': 'ns2.trafficz.com'}\n"
            " - Additionals:\n"
            "  * Domain: ns1.trafficz.com - Type: A [0x0001] - Class: IN [0x0001] - TTL: 13 seconds - {'IPAddress': '209.59.194.246'}\n"
            "  * Domain: ns2.trafficz.com - Type: A [0x0001] - Class: IN [0x0001] - TTL: 133 seconds - {'IPAddress': '209.59.195.246'}\n")

        chk(b"\xef\x55\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x04\x6d\x61\x69"
            b"\x6c\x06\x67\x6f\x6f\x67\x6c\x65\x03\x63\x6f\x6d\x00\x00\x01\x00"
            b"\x01",
            "DNS QUERY\n"
            " - Transaction ID -- [0xef55] 61269\n"
            " - Flags ----------- [0x0100] 256\n"
            " - QdCount --------- [0x0001] 1\n"
            " - AnCount --------- [0x0000] 0\n"
            " - NsCount --------- [0x0000] 0\n"
            " - ArCount --------- [0x0000] 0\n"
            " - Questions:\n"
            "  * Domain: mail.google.com - Type: A [0x0001] - Class: IN [0x0001]\n")

        chk(b"\xef\x55\x81\x80\x00\x01\x00\x04\x00\x04\x00\x04\x04\x6d\x61\x69"
            b"\x6c\x06\x67\x6f\x6f\x67\x6c\x65\x03\x63\x6f\x6d\x00\x00\x01\x00"
            b"\x01\xc0\x0c\x00\x05\x00\x01\x00\x00\x06\x79\x00\x0f\x0a\x67\x6f"
            b"\x6f\x67\x6c\x65\x6d\x61\x69\x6c\x01\x6c\xc0\x11\xc0\x2d\x00\x01"
            b"\x00\x01\x00\x00\x00\x77\x00\x04\xd1\x55\xc3\x53\xc0\x2d\x00\x01"
            b"\x00\x01\x00\x00\x00\x77\x00\x04\xd1\x55\xc3\x12\xc0\x2d\x00\x01"
            b"\x00\x01\x00\x00\x00\x77\x00\x04\xd1\x55\xc3\x13\xc0\x11\x00\x02"
            b"\x00\x01\x00\x00\x00\x5d\x00\x06\x03\x6e\x73\x33\xc0\x11\xc0\x11"
            b"\x00\x02\x00\x01\x00\x00\x00\x5d\x00\x06\x03\x6e\x73\x34\xc0\x11"
            b"\xc0\x11\x00\x02\x00\x01\x00\x00\x00\x5d\x00\x06\x03\x6e\x73\x31"
            b"\xc0\x11\xc0\x11\x00\x02\x00\x01\x00\x00\x00\x5d\x00\x06\x03\x6e"
            b"\x73\x32\xc0\x11\xc0\x9c\x00\x01\x00\x01\x00\x00\x04\x4e\x00\x04"
            b"\xd8\xef\x20\x0a\xc0\xae\x00\x01\x00\x01\x00\x00\x06\x64\x00\x04"
            b"\xd8\xef\x22\x0a\xc0\x78\x00\x01\x00\x01\x00\x00\x00\x05\x00\x04"
            b"\xd8\xef\x24\x0a\xc0\x8a\x00\x01\x00\x01\x00\x00\x00\x08\x00\x04"
            b"\xd8\xef\x26\x0a",
            "DNS RESPONSE\n"
            " - Transaction ID -- [0xef55] 61269\n"
            " - Flags ----------- [0x8180] 33152\n"
            " - QdCount --------- [0x0001] 1\n"
            " - AnCount --------- [0x0004] 4\n"
            " - NsCount --------- [0x0004] 4\n"
            " - ArCount --------- [0x0004] 4\n"
            " - Questions:\n"
            "  * Domain: mail.google.com - Type: A [0x0001] - Class: IN [0x0001]\n"
            " - Answers:\n"
            "  * Domain: mail.google.com - Type: CNAME [0x0005] - Class: IN [0x0001] - TTL: 1657 seconds - {'Name': 'googlemail.l.google.com'}\n"
            "  * Domain: googlemail.l.google.com - Type: A [0x0001] - Class: IN [0x0001] - TTL: 119 seconds - {'IPAddress': '209.85.195.83'}\n"
            "  * Domain: googlemail.l.google.com - Type: A [0x0001] - Class: IN [0x0001] - TTL: 119 seconds - {'IPAddress': '209.85.195.18'}\n"
            "  * Domain: googlemail.l.google.com - Type: A [0x0001] - Class: IN [0x0001] - TTL: 119 seconds - {'IPAddress': '209.85.195.19'}\n"
            " - Authoritative:\n"
            "  * Domain: google.com - Type: NS [0x0002] - Class: IN [0x0001] - TTL: 93 seconds - {'Name': 'ns3.google.com'}\n"
            "  * Domain: google.com - Type: NS [0x0002] - Class: IN [0x0001] - TTL: 93 seconds - {'Name': 'ns4.google.com'}\n"
            "  * Domain: google.com - Type: NS [0x0002] - Class: IN [0x0001] - TTL: 93 seconds - {'Name': 'ns1.google.com'}\n"
            "  * Domain: google.com - Type: NS [0x0002] - Class: IN [0x0001] - TTL: 93 seconds - {'Name': 'ns2.google.com'}\n"
            " - Additionals:\n"
            "  * Domain: ns1.google.com - Type: A [0x0001] - Class: IN [0x0001] - TTL: 1102 seconds - {'IPAddress': '216.239.32.10'}\n"
            "  * Domain: ns2.google.com - Type: A [0x0001] - Class: IN [0x0001] - TTL: 1636 seconds - {'IPAddress': '216.239.34.10'}\n"
            "  * Domain: ns3.google.com - Type: A [0x0001] - Class: IN [0x0001] - TTL: 5 seconds - {'IPAddress': '216.239.36.10'}\n"
            "  * Domain: ns4.google.com - Type: A [0x0001] - Class: IN [0x0001] - TTL: 8 seconds - {'IPAddress': '216.239.38.10'}\n")


if __name__ == '__main__':
    unittest.main(verbosity=1)
