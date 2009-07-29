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
import dot11

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
        rt = dot11.RadioTap(aBuffer)
        
        self.do11_decoder = Dot11Decoder()
        packet = self.do11_decoder.decode(rt.get_body_as_string())
    
        rt.contains(packet)
        return rt

class Dot11Decoder(Decoder):
    def __init__(self):
        pass
        
    def decode(self, aBuffer):
        d = dot11.Dot11(aBuffer)
        
        type = d.get_type()
        if type == dot11.Dot11Types.DOT11_TYPE_CONTROL:
            dot11_control_decoder = Dot11ControlDecoder()
            packet = dot11_control_decoder.decode(d.body_string)
        elif type == dot11.Dot11Types.DOT11_TYPE_DATA:
            dot11_data_decoder = Dot11DataDecoder()
            if d.get_fromDS() and d.get_toDS():
                dot11_data_decoder.set_Addr4()
            if d.is_QoS_frame():
                dot11_data_decoder.set_QoS()
            if d.get_protectedFrame():
                dot11_data_decoder.set_privateFrame()
                
            packet = dot11_data_decoder.decode(d.body_string)
        elif type == dot11.Dot11Types.DOT11_TYPE_MANAGEMENT:
            dot11_management_decoder = Dot11ManagementDecoder()
            packet = dot11_mgmt_decoder.decode(d.body_string)
        else:
            data_decoder = DataDecoder()
            packet = data_decoder.decode(d.body_string)

        d.contains(packet)
        return d

class Dot11DataDecoder(Decoder):
    def __init__(self):
        self.QoS=False
        self.Addr4=False
        self.Private=False
        
    def set_QoS(self):
        self.QoS = True
    def set_Addr4(self):
        self.Addr4 = True
    def set_privateFrame(self):
        self.Private = True
        
    def decode(self, aBuffer):
        if self.Addr4:
            if self.QoS:
                p = dot11.Dot11DataAddr4QoSFrame(aBuffer)
            else:
                p = dot11.Dot11DataAddr4Frame(aBuffer)
        elif self.QoS:
            p = dot11.Dot11DataQoSFrame(aBuffer)
        else:
            p = dot11.Dot11DataFrame(aBuffer)
        
        if self.Private is False:
            self.llc_decoder = LLCDecoder()
            packet = self.llc_decoder.decode(p.body_string)
        else:
            wep_decoder = Dot11WEPDecoder()
            packet = wep_decoder.decode(p.body_string)
            if packet is None:
                wpa_decoder = Dot11WPADecoder()
                packet = wpa_decoder.decode(p.body_string)
                if packet is None:
                    wpa2_decoder = Dot11WPA2Decoder()
                    packet = wpa2_decoder.decode(p.body_string)
                    if packet is None:
                        data_decoder = DataDecoder()
                        packet = data_decoder.decode(p.body_string)
        
        p.contains(packet)
        return p
      
class Dot11WEPDecoder(Decoder):
    def __init__(self):
        pass
        
    def decode(self, aBuffer):
        wep = dot11.Dot11WEP(aBuffer)

        if wep.is_WEP() is False:
            return None
        
        decoded_string=wep.get_decrypted_data()
        
        wep_data = Dot11WEPDataDecoder()
        packet = wep_data.decode(decoded_string)
        
        wep.contains(packet)
        
        return wep

class Dot11WEPDataDecoder(Decoder):
    def __init__(self):
        pass
        
    def decode(self, aBuffer):
        wep_data = dot11.Dot11WEPData(aBuffer)

        llc_decoder = LLCDecoder()
        packet = llc_decoder.decode(wep_data.body_string)
        
        wep_data.contains(packet)
        
        return wep_data


class Dot11WPADecoder(Decoder):
    def __init__(self):
        pass
        
    def decode(self, aBuffer):
        wpa = dot11.Dot11WPA(aBuffer)

        if wpa.is_WPA() is False:
            return None
        
        decoded_string=wpa.get_decrypted_data()
        
        wpa_data = Dot11DataWPADataDecoder()
        packet = wpa_data.decode(decoded_string)
        
        wpa.contains(packet)
        
        return wpa
    
class Dot11WPADataDecoder(Decoder):
    def __init__(self):
        pass
        
    def decode(self, aBuffer):
        wpa_data = dot11.Dot11WPAData(aBuffer)

        llc_decoder = LLCDecoder()
        packet = self.llc_decoder.decode(wpa_data.body_string)
        
        wpa_data.contains(packet)
        
        return wpa_data

class Dot11WPA2Decoder(Decoder):
    def __init__(self):
        pass
        
    def decode(self, aBuffer):
        wpa2 = dot11.Dot11WPA2(aBuffer)

        if wpa2.is_WPA2() is False:
            return None
        
        decoded_string=wpa2.get_decrypted_data()
        
        wpa2_data = Dot11DataWPA2DataDecoder()
        packet = wpa2_data.decode(decoded_string)
        
        wpa2.contains(packet)
        
        return wpa2
    
class Dot11WPA2DataDecoder(Decoder):
    def __init__(self):
        pass
        
    def decode(self, aBuffer):
        wpa2_data = dot11.Dot11WPA2Data(aBuffer)

        llc_decoder = LLCDecoder()
        packet = self.llc_decoder.decode(wpa2_data.body_string)
        
        wpa2_data.contains(packet)
        
        return wpa2_data
    
class LLCDecoder(Decoder):
    def __init__(self):
        pass
        
    def decode(self, aBuffer):
        d = dot11.LLC(aBuffer)
        
        if d.get_DSAP()==dot11.SAPTypes.SNAP:
            if d.get_SSAP()==dot11.SAPTypes.SNAP:
                if d.get_control()==dot11.LLC.DLC_UNNUMBERED_FRAMES:
                    snap_decoder = SNAPDecoder()
                    packet = snap_decoder.decode(d.body_string)
        else:
            # Only SNAP is implemented
            data_decoder = DataDecoder()
            packet = data_decoder.decode(d.body_string)

        d.contains(packet)
        return d

class SNAPDecoder(Decoder):
    def __init__(self):
        pass
        
    def decode(self, aBuffer):
        s = dot11.SNAP(aBuffer)
        
        if  s.get_OUI()!=0x000000:
            # We don't know how to handle other than OUI=0x000000 (EtherType)
            self.data_decoder = DataDecoder()
            packet = self.data_decoder.decode(s.body_string)
        elif s.get_protoID() == ImpactPacket.IP.ethertype:
            self.ip_decoder = IPDecoder()
            packet = self.ip_decoder.decode(s.body_string)
        elif s.get_protoID() == ImpactPacket.ARP.ethertype:
            self.arp_decoder = ARPDecoder()
            packet = self.arp_decoder.decode(s.body_string)
        else:
            self.data_decoder = DataDecoder()
            packet = self.data_decoder.decode(s.body_string)

        s.contains(packet)
        return s
    