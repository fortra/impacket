# Copyright (c) 2003-2006 CORE Security Technologies
#
# This software is provided under under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# $Id$
#
# Description:
#  Convenience packet unpackers for various network protocols
#  implemented in the ImpactPacket module.
#
# Author:
#  Javier Burroni (javier)
#  Bruce Leidl (brl)

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
        end = i.get_ip_len()
        if i.get_ip_p() == ImpactPacket.UDP.protocol:
            self.udp_decoder = UDPDecoder()
            packet = self.udp_decoder.decode(aBuffer[off:end])
        elif i.get_ip_p() == ImpactPacket.TCP.protocol:
            self.tcp_decoder = TCPDecoder()
            packet = self.tcp_decoder.decode(aBuffer[off:end])
        elif i.get_ip_p() == ImpactPacket.ICMP.protocol:
            self.icmp_decoder = ICMPDecoder()
            packet = self.icmp_decoder.decode(aBuffer[off:end])
        else:
            self.data_decoder = DataDecoder()
            packet = self.data_decoder.decode(aBuffer[off:end])
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

class IPDecoderForICMP(Decoder):
    """This class was added to parse the IP header of ICMP unreachables packets
    If you use the "standard" IPDecoder, it might crash (see bug #4870) ImpactPacket.py
    because the TCP header inside the IP header is incomplete"""    
    def __init__(self):
        pass

    def decode(self, aBuffer):
        i = ImpactPacket.IP(aBuffer)
        off = i.get_header_size()
        if i.get_ip_p() == ImpactPacket.UDP.protocol:
            self.udp_decoder = UDPDecoder()
            packet = self.udp_decoder.decode(aBuffer[off:])
        else:
            self.data_decoder = DataDecoder()
            packet = self.data_decoder.decode(aBuffer[off:])
        i.contains(packet)
        return i

class ICMPDecoder(Decoder):
    def __init__(self):
        pass

    def decode(self, aBuffer):
        ic = ImpactPacket.ICMP(aBuffer)
        off = ic.get_header_size()
        if ic.get_icmp_type() == ImpactPacket.ICMP.ICMP_UNREACH:
            self.ip_decoder = IPDecoderForICMP()
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

class RadioTapDecoder(Decoder):
    def __init__(self):
        pass

    def decode(self, aBuffer):
        rt = ImpactPacket.RadioTap(aBuffer)
        
        header_size = rt.get_header_size()
        tail_size = rt.get_tail_size()
        
        self.do11_decoder = Dot11Decoder()
        packet = self.dot11_decoder.decode(aBuffer[header_size:-tail_size])
    
        rt.contains(packet)
        return rt

class Dot11Decoder(Decode):
    def __init__(self):
        pass
        
    def decode(self, aBuffer):
        d = ImpactPacket.Dot11(aBuffer)
        
        type = d.get_type()
        if type == ImpactPacket.Dot11.DOT11_TYPE_CONTROL:
            dot11_control_decoder = Dot11ControlDecoder()
            packet = dot11_control_decoder.decode(d.body_string)
        elif type == ImpactPacket.Dot11.DOT11_TYPE_DATA:
            if d.get_fromDS() and d.get_toDS() and d.is_QoS_frame():
                dot11_data_decoder = Dot11DataDecoderAddr4QoS()
            elif d.get_fromDS() and d.get_toDS():
                dot11_data_decoder = Dot11DataDecoderAddr4()
            elif d.is_QoS_frame():
                dot11_data_decoder = Dot11DataDecoderQoS()
            else:
                dot11_data_decoder = Dot11DataDecoder()
                
            packet = dot11_data_decoder.decode(d.body_string)
        elif type == ImpactPacket.Dot11.DOT11_TYPE_MANAGEMENT:
            dot11_management_decoder = Dot11ManagementDecoder()
            packet = dot11_mgmt_decoder.decode(d.body_string)
        else:
            data_decoder = DataDecoder()
            packet = data_decoder.decode(d.body_string)

        d.contains(packet)
        return d

class Dot11DataDecoder(Decode):
    def __init__(self):
        pass
        
    def decode(self, aBuffer):
        p = ImpactPacket.Dot11DataFrame(aBuffer)
        
        if p.get_encryption_type() == ImpactPacket.Dot11DataFrame.OPEN:
            self.llc_decoder = LLCDecoder()
            packet = self.llc_decoder.decode(p.body_string)
        elif p.get_encryption_type() == ImpactPacket.Dot11DataFrame.WEP:
            self.wep_decoder = Dot11DataWEPDecoder()
            packet = self.wep_decoder.decode(p.body_string)
        elif p.get_encryption_type() == ImpactPacket.Dot11DataFrame.WPA:
            self.wpa_decoder = Dot11DataWPADecoder()
            packet = self.wep_decoder.decode(p.body_string)
        elif p.get_encryption_type() == ImpactPacket.Dot11DataFrame.WPA2:
            self.wpa2_decoder = Dot11DataWPA2Decoder()
            packet = self.wep_decoder.decode(p.body_string)
        else:
            data_decoder = DataDecoder()
            packet = data_decoder.decode(p.body_string)

        p.contains(packet)
        return d
      
class Dot11DataWEPDecoder(Decode):
    def __init__(self):
        pass
        
    def decode(self, aBuffer):
        # TODO: the WEP decoder
        data_decoder = DataDecoder()
        return data_decoder.decode(aBuffer)

class Dot11DataWPADecoder(Decode):
    def __init__(self):
        pass
        
    def decode(self, aBuffer):
        # TODO: the WPA decoder
        data_decoder = DataDecoder()
        return data_decoder.decode(aBuffer)

class Dot11DataWPA2Decoder(Decode):
    def __init__(self):
        pass
        
    def decode(self, aBuffer):
        # TODO: the WPA2 decoder
        data_decoder = DataDecoder()
        return data_decoder.decode(aBuffer)

class LLCDecoder(Decode):
    def __init__(self):
        pass
        
    def decode(self, aBuffer):
        d = ImpactPacket.LLC(aBuffer)
        
        if d.get_DSAP()==ImpactPacket.SAPTypes.SNAP:
            if d.get_SSAP()==ImpactPacket.SAPTypes.SNAP:
                if d.get_control()==ImpactPacket.LLC.DLC_UNNUMBERED_FRAMES:
                    snap_decoder = SNAPDecoder()
                    packet = snap_decoder.decode(d.body_string)
        else:
            # Only SNAP is implemented
            data_decoder = DataDecoder()
            packet = data_decoder.decode(d.body_string)

        d.contains(packet)
        return d

class SNAPDecoder(Decode):
    def __init__(self):
        pass
        
    def decode(self, aBuffer):
        s = ImpactPacket.SNAP(aBuffer)
        
        if  d.get_OUI()!=0x000000:
            # We don't know how to handle other than OUI=0x000000 (EtherType)
            self.data_decoder = DataDecoder()
            packet = self.data_decoder.decode(s.body_string)
        elif e.get_ether_type() == ImpactPacket.IP.ethertype:
            self.ip_decoder = IPDecoder()
            packet = self.ip_decoder.decode(s.body_string)
        elif e.get_ether_type() == ImpactPacket.ARP.ethertype:
            self.arp_decoder = ARPDecoder()
            packet = self.arp_decoder.decode(s.body_string)
        else:
            self.data_decoder = DataDecoder()
            packet = self.data_decoder.decode(s.body_string)

        d.contains(packet)
        return d
    