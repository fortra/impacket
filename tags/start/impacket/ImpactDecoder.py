#--
# $CoreSDI: ImpactDecoder.py,v 1.1.8.3 2003/10/07 18:18:45 jkohen Exp $
#
# Description:
#  Convenience packet unpackers for various network protocols
#  implemented in the ImpactPacket module.
#
# Author:
#  Javier Burroni (javier)
#  Bruce Leidl (brl)
#
# Copyright (c) 2001-2002 CORE Security Technologies, CORE SDI Inc.
# All rights reserved.
#
# This computer software is owned by Core SDI Inc. and is
# protected by U.S. copyright laws and other laws and by international
# treaties.  This computer software is furnished by CORE SDI Inc.
# pursuant to a written license agreement and may be used, copied,
# transmitted, and stored only in accordance with the terms of such
# license and with the inclusion of the above copyright notice.  This
# computer software or any other copies thereof may not be provided or
# otherwise made available to any other person.
#
#
# THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED
# WARRANTIES ARE DISCLAIMED. IN NO EVENT SHALL CORE SDI Inc. BE LIABLE
# FOR ANY DIRECT,  INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY OR
# CONSEQUENTIAL  DAMAGES RESULTING FROM THE USE OR MISUSE OF
# THIS SOFTWARE
#
#--

import ImpactPacket

"""Classes to convert from raw packets into a hierarchy of
ImpactPacket derived objects.

The protocol of the outermost layer must be known in advance, and the
packet must be fed to the corresponding decoder. From there it will
try to decode the raw data into a hierarchy of ImpactPacket derived
objects; if a layer's protocol is unknown, all the remaining data will
be wrapped into a ImpactPacket.Data object.
"""

class Decoder:
    def decode(self, aBuffer):
        pass

class EthDecoder(Decoder):
    def __init__(self):
        pass

    def decode(self, aBuffer):
        e = ImpactPacket.Ethernet(aBuffer)
        off = e.get_header_size()
        if e.get_ether_type() == ImpactPacket.IP.ethertype:
            self.ip_decoder = IPDecoder()
            packet = self.ip_decoder.decode(aBuffer[off:])
        elif e.get_ether_type() == ImpactPacket.ARP.ethertype:
            self.arp_decoder = ARPDecoder()
            packet = self.arp_decoder.decode(aBuffer[off:])
        else:
            self.data_decoder = DataDecoder()
            packet = self.data_decoder.decode(aBuffer[off:])

        e.contains(packet)
        return e

# Linux "cooked" capture encapsulation.
# Used, for instance, for packets returned by the "any" interface.
class LinuxSLLDecoder(Decoder):
    def __init__(self):
        pass

    def decode(self, aBuffer):
        e = ImpactPacket.LinuxSLL(aBuffer)
        off = 16
        if e.get_ether_type() == ImpactPacket.IP.ethertype:
            self.ip_decoder = IPDecoder()
            packet = self.ip_decoder.decode(aBuffer[off:])
        elif e.get_ether_type() == ImpactPacket.ARP.ethertype:
            self.arp_decoder = ARPDecoder()
            packet = self.arp_decoder.decode(aBuffer[off:])
        else:
            self.data_decoder = DataDecoder()
            packet = self.data_decoder.decode(aBuffer[off:])

        e.contains(packet)
        return e

class IPDecoder(Decoder):
    def __init__(self):
        pass

    def decode(self, aBuffer):
        i = ImpactPacket.IP(aBuffer)
        off = i.get_header_size()
        if i.get_ip_p() == ImpactPacket.UDP.protocol:
            self.udp_decoder = UDPDecoder()
            packet = self.udp_decoder.decode(aBuffer[off:])
        elif i.get_ip_p() == ImpactPacket.TCP.protocol:
            self.tcp_decoder = TCPDecoder()
            packet = self.tcp_decoder.decode(aBuffer[off:])
        elif i.get_ip_p() == ImpactPacket.ICMP.protocol:
            self.icmp_decoder = ICMPDecoder()
            packet = self.icmp_decoder.decode(aBuffer[off:])
        else:
            self.data_decoder = DataDecoder()
            packet = self.data_decoder.decode(aBuffer[off:])
        i.contains(packet)
        return i

class ARPDecoder(Decoder):
    def __init__(self):
        pass

    def decode(self, aBuffer):
        arp = ImpactPacket.ARP(aBuffer)
        off = arp.get_header_size()
        self.data_decoder = DataDecoder()
        packet = self.data_decoder.decode(aBuffer[off:])
        arp.contains(packet)
        return arp

class UDPDecoder(Decoder):
    def __init__(self):
        pass

    def decode(self, aBuffer):
        u = ImpactPacket.UDP(aBuffer)
        off = u.get_header_size()
        self.data_decoder = DataDecoder()
        packet = self.data_decoder.decode(aBuffer[off:])
        u.contains(packet)
        return u

class TCPDecoder(Decoder):
    def __init__(self):
        pass

    def decode(self, aBuffer):
        t = ImpactPacket.TCP(aBuffer)
        off = t.get_header_size()
        self.data_decoder = DataDecoder()
        packet = self.data_decoder.decode(aBuffer[off:])
        t.contains(packet)
        return t

class ICMPDecoder(Decoder):
    def __init__(self):
        pass

    def decode(self, aBuffer):
        ic = ImpactPacket.ICMP(aBuffer)
        off = ic.get_header_size()
        if ic.get_icmp_type() == ImpactPacket.ICMP.ICMP_UNREACH:
            self.ip_decoder = IPDecoder()
            packet = self.ip_decoder.decode(aBuffer[off:])
        else:
            self.data_decoder = DataDecoder()
            packet = self.data_decoder.decode(aBuffer[off:])
        ic.contains(packet)
        return ic

class DataDecoder(Decoder):
    def decode(self, aBuffer):
        d = ImpactPacket.Data(aBuffer)
        return d
