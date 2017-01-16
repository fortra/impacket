# Copyright (c) 2003-2016 CORE Security Technologies
#
# This software is provided under under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Description:
#  Convenience packet unpackers for various network protocols
#  implemented in the ImpactPacket module.
#
# Author:
#  Javier Burroni (javier)
#  Bruce Leidl (brl)
#  Aureliano Calvo

import array

import ImpactPacket
import dot11
import IP6
import ICMP6
import IP6_Extension_Headers
from cdp import CDP
from Dot11Crypto import RC4
from impacket import wps, eap, dhcp
from impacket.dot11 import Dot11WEPData
from impacket import LOG


"""Classes to convert from raw packets into a hierarchy of
ImpactPacket derived objects.

The protocol of the outermost layer must be known in advance, and the
packet must be fed to the corresponding decoder. From there it will
try to decode the raw data into a hierarchy of ImpactPacket derived
objects; if a layer's protocol is unknown, all the remaining data will
be wrapped into a ImpactPacket.Data object.
"""

class Decoder:
    __decoded_protocol = None
    def decode(self, aBuffer):
        pass
        
    def set_decoded_protocol(self, protocol):
        self.__decoded_protocol = protocol
        
    def get_protocol(self, aprotocol):
        protocol = self.__decoded_protocol
        while protocol:
            if protocol.__class__ == aprotocol:
                break
            protocol=protocol.child()
        return protocol
    
    def __str__(self):
        protocol = self.__decoded_protocol
        i=0
        out=''
        while protocol:
            tabline=' '*i+'+-'+str(protocol.__class__)
            out+="%s"%tabline+'\n'
            protocol=protocol.child()
            i+=1
        return out

class EthDecoder(Decoder):
    def __init__(self):
        pass

    def decode(self, aBuffer):
        e = ImpactPacket.Ethernet(aBuffer)
        self.set_decoded_protocol( e )
        off = e.get_header_size()
        if e.get_ether_type() == ImpactPacket.IP.ethertype:
            self.ip_decoder = IPDecoder()
            packet = self.ip_decoder.decode(aBuffer[off:])
        elif e.get_ether_type() == IP6.IP6.ethertype:
            self.ip6_decoder = IP6Decoder()
            packet = self.ip6_decoder.decode(aBuffer[off:])
        elif e.get_ether_type() == ImpactPacket.ARP.ethertype:
            self.arp_decoder = ARPDecoder()
            packet = self.arp_decoder.decode(aBuffer[off:])
        elif e.get_ether_type() == eap.DOT1X_AUTHENTICATION:
            self.eapol_decoder = EAPOLDecoder()
            packet = self.eapol_decoder.decode(aBuffer[off:])
        # LLC ?
        elif e.get_ether_type() < 1500:
            self.llc_decoder = LLCDecoder()
            packet = self.llc_decoder.decode(aBuffer[off:])
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
        self.set_decoded_protocol( e )
        off = 16
        if e.get_ether_type() == ImpactPacket.IP.ethertype:
            self.ip_decoder = IPDecoder()
            packet = self.ip_decoder.decode(aBuffer[off:])
        elif e.get_ether_type() == ImpactPacket.ARP.ethertype:
            self.arp_decoder = ARPDecoder()
            packet = self.arp_decoder.decode(aBuffer[off:])
        elif e.get_ether_type() == eap.DOT1X_AUTHENTICATION:
            self.eapol_decoder = EAPOLDecoder()
            packet = self.eapol_decoder.decode(aBuffer[off:])
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
        self.set_decoded_protocol ( i )
        off = i.get_header_size()
        end = i.get_ip_len()
        # If ip_len == 0 we might be facing TCP segmentation offload, let's calculate the right len
        if end == 0:
            LOG.warning('IP len reported as 0, most probably because of TCP segmentation offload. Attempting to fix its size')
            i.set_ip_len(len(aBuffer))
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
        elif i.get_ip_p() == ImpactPacket.IGMP.protocol:
            self.igmp_decoder = IGMPDecoder()
            packet = self.igmp_decoder.decode(aBuffer[off:end])
        else:
            self.data_decoder = DataDecoder()
            packet = self.data_decoder.decode(aBuffer[off:end])
        i.contains(packet)
        return i

class IP6MultiProtocolDecoder(Decoder):
    def __init__(self, a_protocol_id):
        self.protocol_id = a_protocol_id

    def decode(self, buffer):
        if self.protocol_id == ImpactPacket.UDP.protocol:
            self.udp_decoder = UDPDecoder()
            packet = self.udp_decoder.decode(buffer)
        elif self.protocol_id == ImpactPacket.TCP.protocol:
            self.tcp_decoder = TCPDecoder()
            packet = self.tcp_decoder.decode(buffer)
        elif self.protocol_id == ICMP6.ICMP6.protocol:
            self.icmp6_decoder = ICMP6Decoder()
            packet = self.icmp6_decoder.decode(buffer)
        else:
            # IPv6 Extension Headers lookup
            extension_headers = IP6_Extension_Headers.IP6_Extension_Header.get_extension_headers()
            if buffer and self.protocol_id in extension_headers:
                extension_header_decoder_class = extension_headers[self.protocol_id].get_decoder()
                self.extension_header_decoder = extension_header_decoder_class()
                packet = self.extension_header_decoder.decode(buffer)
            else:
                self.data_decoder = DataDecoder()
                packet = self.data_decoder.decode(buffer)

        return packet

class IP6Decoder(Decoder):
    def __init__(self):
        pass

    def decode(self, buffer):
        ip6_packet = IP6.IP6(buffer)
        self.set_decoded_protocol(ip6_packet)
        start_pos = ip6_packet.get_header_size() 
        end_pos = ip6_packet.get_payload_length() + start_pos
        contained_protocol = ip6_packet.get_next_header()
        
        multi_protocol_decoder = IP6MultiProtocolDecoder(contained_protocol)
        child_packet = multi_protocol_decoder.decode(buffer[start_pos:end_pos])
        
        ip6_packet.contains(child_packet)
        return ip6_packet

class HopByHopDecoder(Decoder):
    def __init__(self):
        pass

    def decode(self, buffer):
        hop_by_hop = IP6_Extension_Headers.Hop_By_Hop(buffer)
        self.set_decoded_protocol(hop_by_hop)
        start_pos = hop_by_hop.get_header_size()
        contained_protocol = hop_by_hop.get_next_header()

        multi_protocol_decoder = IP6MultiProtocolDecoder(contained_protocol)
        child_packet = multi_protocol_decoder.decode(buffer[start_pos:])
        
        hop_by_hop.contains(child_packet)
        return hop_by_hop

class DestinationOptionsDecoder(Decoder):
    def __init__(self):
        pass

    def decode(self, buffer):
        destination_options = IP6_Extension_Headers.Destination_Options(buffer)
        self.set_decoded_protocol(destination_options)
        start_pos = destination_options.get_header_size()
        contained_protocol = destination_options.get_next_header()

        multi_protocol_decoder = IP6MultiProtocolDecoder(contained_protocol)
        child_packet = multi_protocol_decoder.decode(buffer[start_pos:])
        
        destination_options.contains(child_packet)
        return destination_options

class RoutingOptionsDecoder(Decoder):
    def __init__(self):
        pass

    def decode(self, buffer):
        routing_options = IP6_Extension_Headers.Routing_Options(buffer)
        self.set_decoded_protocol(routing_options)
        start_pos = routing_options.get_header_size()
        contained_protocol = routing_options.get_next_header()

        multi_protocol_decoder = IP6MultiProtocolDecoder(contained_protocol)
        child_packet = multi_protocol_decoder.decode(buffer[start_pos:])
        
        routing_options.contains(child_packet)
        return routing_options

class ICMP6Decoder(Decoder):
    def __init__(self):
        pass

    def decode(self, buffer):
        icmp6_packet = ICMP6.ICMP6(buffer)
        self.set_decoded_protocol(icmp6_packet)
        start_pos = icmp6_packet.get_header_size() 
                
        self.data_decoder = DataDecoder()
        child_packet = self.data_decoder.decode(buffer[start_pos:])
        icmp6_packet.contains(child_packet)
        return icmp6_packet


class ARPDecoder(Decoder):
    def __init__(self):
        pass

    def decode(self, aBuffer):
        arp = ImpactPacket.ARP(aBuffer)
        self.set_decoded_protocol( arp )
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
        self.set_decoded_protocol( u )
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
        self.set_decoded_protocol( t )
        off = t.get_header_size()
        self.data_decoder = DataDecoder()
        packet = self.data_decoder.decode(aBuffer[off:])
        t.contains(packet)
        return t

class IGMPDecoder(Decoder):
    def __init__(self):
        pass
    def decode(self, aBuffer):
        ig = ImpactPacket.IGMP(aBuffer)
        off = ig.get_header_size()
        self.data_decoder = DataDecoder()
        packet = self.data_decoder.decode(aBuffer[off:])
        ig.contains(packet)
        return ig


class IPDecoderForICMP(Decoder):
    """This class was added to parse the IP header of ICMP unreachables packets
    If you use the "standard" IPDecoder, it might crash (see bug #4870) ImpactPacket.py
    because the TCP header inside the IP header is incomplete"""    
    def __init__(self):
        pass

    def decode(self, aBuffer):
        i = ImpactPacket.IP(aBuffer)
        self.set_decoded_protocol( i )
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
        self.set_decoded_protocol( ic )
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
        self.set_decoded_protocol( d )
        return d

class BaseDot11Decoder(Decoder):
    def __init__(self, key_manager=None):
        self.set_key_manager(key_manager)
        
    def set_key_manager(self, key_manager):
        self.key_manager = key_manager
        
    def find_key(self, bssid):
        try:
            key = self.key_manager.get_key(bssid)
        except:
            return False
        return key

class RadioTapDecoder(BaseDot11Decoder):
    def __init__(self):
        BaseDot11Decoder.__init__(self)

    def decode(self, aBuffer):
        rt = dot11.RadioTap(aBuffer)
        self.set_decoded_protocol( rt )
        
        self.do11_decoder = Dot11Decoder()
        self.do11_decoder.set_key_manager(self.key_manager)
        flags=rt.get_flags()
        if flags is not None:
            fcs=flags&dot11.RadioTap.RTF_FLAGS.PROPERTY_FCS_AT_END
            self.do11_decoder.FCS_at_end(fcs)
            
        packet = self.do11_decoder.decode(rt.get_body_as_string())
    
        rt.contains(packet)
        return rt

class Dot11Decoder(BaseDot11Decoder):
    def __init__(self):
        BaseDot11Decoder.__init__(self)
        self.__FCS_at_end = True
        
    def FCS_at_end(self, fcs_at_end=True):
        self.__FCS_at_end=not not fcs_at_end 
        
    def decode(self, aBuffer):
        d = dot11.Dot11(aBuffer, self.__FCS_at_end)
        self.set_decoded_protocol( d )
        
        type = d.get_type()
        if type == dot11.Dot11Types.DOT11_TYPE_CONTROL:
            dot11_control_decoder = Dot11ControlDecoder()
            packet = dot11_control_decoder.decode(d.body_string)
        elif type == dot11.Dot11Types.DOT11_TYPE_DATA:
            dot11_data_decoder = Dot11DataDecoder(self.key_manager)
            
            dot11_data_decoder.set_dot11_hdr(d)
            
            packet = dot11_data_decoder.decode(d.body_string)
        elif type == dot11.Dot11Types.DOT11_TYPE_MANAGEMENT:
            dot11_management_decoder = Dot11ManagementDecoder()
            dot11_management_decoder.set_subtype(d.get_subtype())
            packet = dot11_management_decoder.decode(d.body_string)
        else:
            data_decoder = DataDecoder()
            packet = data_decoder.decode(d.body_string)

        d.contains(packet)
        return d

class Dot11ControlDecoder(BaseDot11Decoder):
    def __init__(self):
        BaseDot11Decoder.__init__(self)
        self.__FCS_at_end = True

    def FCS_at_end(self, fcs_at_end=True):
        self.__FCS_at_end=not not fcs_at_end 
    
    def decode(self, aBuffer):
        d = dot11.Dot11(aBuffer, self.__FCS_at_end)
        self.set_decoded_protocol(d)
        
        self.subtype = d.get_subtype()
        if self.subtype is dot11.Dot11Types.DOT11_SUBTYPE_CONTROL_CLEAR_TO_SEND:
            self.ctrl_cts_decoder = Dot11ControlFrameCTSDecoder()
            packet = self.ctrl_cts_decoder.decode(d.body_string)
        elif self.subtype is dot11.Dot11Types.DOT11_SUBTYPE_CONTROL_ACKNOWLEDGMENT:
            self.ctrl_ack_decoder = Dot11ControlFrameACKDecoder()
            packet = self.ctrl_ack_decoder.decode(d.body_string)
        elif self.subtype is dot11.Dot11Types.DOT11_SUBTYPE_CONTROL_REQUEST_TO_SEND:
            self.ctrl_rts_decoder = Dot11ControlFrameRTSDecoder()
            packet = self.ctrl_rts_decoder.decode(d.body_string)
        elif self.subtype is dot11.Dot11Types.DOT11_SUBTYPE_CONTROL_POWERSAVE_POLL:
            self.ctrl_pspoll_decoder = Dot11ControlFramePSPollDecoder()
            packet = self.ctrl_pspoll_decoder.decode(d.body_string)
        elif self.subtype is dot11.Dot11Types.DOT11_SUBTYPE_CONTROL_CF_END:
            self.ctrl_cfend_decoder = Dot11ControlFrameCFEndDecoder()
            packet = self.ctrl_cfend_decoder.decode(d.body_string)
        elif self.subtype is dot11.Dot11Types.DOT11_SUBTYPE_CONTROL_CF_END_CF_ACK:
            self.ctrl_cfendcfack_decoder = Dot11ControlFrameCFEndCFACKDecoder()
            packet = self.ctrl_cfendcfack_decoder.decode(d.body_string)
        else:
            data_decoder = DataDecoder()
            packet = data_decoder.decode(d.body_string)
        
        d.contains(packet)
        return d

class Dot11ControlFrameCTSDecoder(BaseDot11Decoder):
    def __init__(self):
        BaseDot11Decoder.__init__(self)
    
    def decode(self, aBuffer):
        p = dot11.Dot11ControlFrameCTS(aBuffer)
        self.set_decoded_protocol(p)
        return p

class Dot11ControlFrameACKDecoder(BaseDot11Decoder):
    def __init__(self):
        BaseDot11Decoder.__init__(self)
    
    def decode(self, aBuffer):
        p = dot11.Dot11ControlFrameACK(aBuffer)
        self.set_decoded_protocol(p)
        return p

class Dot11ControlFrameRTSDecoder(BaseDot11Decoder):
    def __init__(self):
        BaseDot11Decoder.__init__(self)
    
    def decode(self, aBuffer):
        p = dot11.Dot11ControlFrameRTS(aBuffer)
        self.set_decoded_protocol(p)
        return p

class Dot11ControlFramePSPollDecoder(BaseDot11Decoder):
    def __init__(self):
        BaseDot11Decoder.__init__(self)
    
    def decode(self, aBuffer):
        p = dot11.Dot11ControlFramePSPoll(aBuffer)
        self.set_decoded_protocol(p)
        return p

class Dot11ControlFrameCFEndDecoder(BaseDot11Decoder):
    def __init__(self):
        BaseDot11Decoder.__init__(self)
    
    def decode(self, aBuffer):
        p = dot11.Dot11ControlFrameCFEnd(aBuffer)
        self.set_decoded_protocol(p)
        return p
class Dot11ControlFrameCFEndCFACKDecoder(BaseDot11Decoder):
    def __init__(self):
        BaseDot11Decoder.__init__(self)
    
    def decode(self, aBuffer):
        p = dot11.Dot11ControlFrameCFEndCFACK(aBuffer)
        self.set_decoded_protocol(p)
        return p

class Dot11DataDecoder(BaseDot11Decoder):
    def __init__(self, key_manager):
        BaseDot11Decoder.__init__(self, key_manager)
        
    def set_dot11_hdr(self, dot11_obj):
        self.dot11 = dot11_obj
        
    def decode(self, aBuffer):
        if self.dot11.get_fromDS() and self.dot11.get_toDS():
            if self.dot11.is_QoS_frame():
                p = dot11.Dot11DataAddr4QoSFrame(aBuffer)
            else:
                p = dot11.Dot11DataAddr4Frame(aBuffer)
        elif self.dot11.is_QoS_frame():
            p = dot11.Dot11DataQoSFrame(aBuffer)
        else:
            p = dot11.Dot11DataFrame(aBuffer)
        self.set_decoded_protocol( p )
        
        if not self.dot11.get_protectedFrame():
            self.llc_decoder = LLCDecoder()
            packet = self.llc_decoder.decode(p.body_string)
        else:
            if not self.dot11.get_fromDS() and self.dot11.get_toDS():
                bssid = p.get_address1()
            elif self.dot11.get_fromDS() and not self.dot11.get_toDS():
                bssid = p.get_address2()
            elif not self.dot11.get_fromDS() and not self.dot11.get_toDS():
                bssid = p.get_address3()
            else:
                # WDS, this is the RA
                bssid = p.get_address1()
                
            wep_decoder = Dot11WEPDecoder(self.key_manager)
            wep_decoder.set_bssid(bssid)
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
      
class Dot11WEPDecoder(BaseDot11Decoder):
    def __init__(self, key_manager):
        BaseDot11Decoder.__init__(self, key_manager)
        self.bssid = None
        
    def set_bssid(self, bssid):
        self.bssid = bssid
        
    def decode(self, aBuffer):
        wep = dot11.Dot11WEP(aBuffer)
        self.set_decoded_protocol( wep )
        
        if wep.is_WEP() is False:
            return None
        
        key = self.find_key(self.bssid)
        if key:
            decoded_string=wep.get_decrypted_data(key)
            
            wep_data = Dot11WEPDataDecoder()
            packet = wep_data.decode(decoded_string)
        else:
            data_decoder = DataDecoder()
            packet = data_decoder.decode(wep.body_string)
        
        wep.contains(packet)
        
        return wep

    def decrypt_data(self, key_string):
        'Return \'WEP Data\' decrypted'
        
        # Needs to be at least 8 bytes of payload 
        if len(self.body_string)<8:
            return self.body_string
        
        # initialize the first bytes of the key from the IV 
        # and copy rest of the WEP key (the secret part) 
        key=self.get_iv()+key_string
        rc4=RC4(key)
        out=rc4.decrypt(data)
        dwd=Dot11WEPData(out)
        
        if False: # is ICV correct
            return dwd
        else:
            return self.body_string


class Dot11WEPDataDecoder(BaseDot11Decoder):
    def __init__(self):
        BaseDot11Decoder.__init__(self)
        
    def decode(self, aBuffer):
        wep_data = dot11.Dot11WEPData(aBuffer)
        
        if not wep_data.check_icv():
            # TODO: Do something when the icv is not correct
            pass

        self.set_decoded_protocol( wep_data )

        llc_decoder = LLCDecoder()
        packet = llc_decoder.decode(wep_data.body_string)
        
        wep_data.contains(packet)
        
        return wep_data


class Dot11WPADecoder(BaseDot11Decoder):
    def __init__(self):
        BaseDot11Decoder.__init__(self)
        
    def decode(self, aBuffer, key=None):
        wpa = dot11.Dot11WPA(aBuffer)
        self.set_decoded_protocol( wpa )

        if wpa.is_WPA() is False:
            return None
        
        if key:
            decoded_string=wpa.get_decrypted_data()
            
            wpa_data = Dot11DataWPADataDecoder()
            packet = wpa_data.decode(decoded_string)
        else:
            data_decoder = DataDecoder()
            packet = data_decoder.decode(wpa.body_string)
        
        wpa.contains(packet)
        
        return wpa
    
class Dot11WPADataDecoder(BaseDot11Decoder):
    def __init__(self):
        BaseDot11Decoder.__init__(self)
        
    def decode(self, aBuffer):
        wpa_data = dot11.Dot11WPAData(aBuffer)
        self.set_decoded_protocol( wpa_data )

        llc_decoder = LLCDecoder()
        packet = self.llc_decoder.decode(wpa_data.body_string)
        
        wpa_data.contains(packet)
        
        return wpa_data

class Dot11WPA2Decoder(BaseDot11Decoder):
    def __init__(self):
        BaseDot11Decoder.__init__(self)
        
    def decode(self, aBuffer, key=None):
        wpa2 = dot11.Dot11WPA2(aBuffer)
        self.set_decoded_protocol( wpa2 )

        if wpa2.is_WPA2() is False:
            return None
        
        if key:
            decoded_string=wpa2.get_decrypted_data()
            
            wpa2_data = Dot11WPA2DataDecoder()
            packet = wpa2_data.decode(decoded_string)
        else:
            data_decoder = DataDecoder()
            packet = data_decoder.decode(wpa2.body_string)

            wpa2.contains(packet)
            
            return wpa2
        
class Dot11WPA2DataDecoder(BaseDot11Decoder):
    def __init__(self):
        BaseDot11Decoder.__init__(self)
        
    def decode(self, aBuffer):
        wpa2_data = dot11.Dot11WPA2Data(aBuffer)
        self.set_decoded_protocol( wpa2_data )

        llc_decoder = LLCDecoder()
        packet = self.llc_decoder.decode(wpa2_data.body_string)
        
        wpa2_data.contains(packet)
        
        return wpa2_data
    
class LLCDecoder(Decoder):
    def __init__(self):
        pass
        
    def decode(self, aBuffer):
        d = dot11.LLC(aBuffer)
        self.set_decoded_protocol( d )
        
        if d.get_DSAP()==dot11.SAPTypes.SNAP:
            if d.get_SSAP()==dot11.SAPTypes.SNAP:
                if d.get_control()==dot11.LLC.DLC_UNNUMBERED_FRAMES:
                    snap_decoder = SNAPDecoder()
                    packet = snap_decoder.decode(d.body_string)
                    d.contains(packet)
                    return d
        
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
        self.set_decoded_protocol( s )
        if  s.get_OUI()==CDP.OUI and s.get_protoID()==CDP.Type:
            dec = CDPDecoder()
            packet = dec.decode(s.body_string)
        elif  s.get_OUI()!=0x000000:
            # We don't know how to handle other than OUI=0x000000 (EtherType)
            self.data_decoder = DataDecoder()
            packet = self.data_decoder.decode(s.body_string)
        elif s.get_protoID() == ImpactPacket.IP.ethertype:
            self.ip_decoder = IPDecoder()
            packet = self.ip_decoder.decode(s.body_string)
        elif s.get_protoID() == ImpactPacket.ARP.ethertype:
            self.arp_decoder = ARPDecoder()
            packet = self.arp_decoder.decode(s.body_string)
        elif s.get_protoID() == eap.DOT1X_AUTHENTICATION:
            self.eapol_decoder = EAPOLDecoder()
            packet = self.eapol_decoder.decode(s.body_string)
        else:
            self.data_decoder = DataDecoder()
            packet = self.data_decoder.decode(s.body_string)

        s.contains(packet)
        return s

class CDPDecoder(Decoder):
    
    def __init__(self):
        pass
        
    def decode(self, aBuffer):
        s = CDP(aBuffer)
        self.set_decoded_protocol( s )
        return s
            
class Dot11ManagementDecoder(BaseDot11Decoder):
    def __init__(self):
        BaseDot11Decoder.__init__(self)
        self.subtype = None
        
    def set_subtype(self, subtype):
        self.subtype=subtype
    
    def decode(self, aBuffer):
        p = dot11.Dot11ManagementFrame(aBuffer)
        self.set_decoded_protocol( p )
        
        if self.subtype is dot11.Dot11Types.DOT11_SUBTYPE_MANAGEMENT_BEACON:
            self.mgt_beacon_decoder = Dot11ManagementBeaconDecoder()
            packet = self.mgt_beacon_decoder.decode(p.body_string)
        elif self.subtype is dot11.Dot11Types.DOT11_SUBTYPE_MANAGEMENT_PROBE_REQUEST:
            self.mgt_probe_request_decoder = Dot11ManagementProbeRequestDecoder()
            packet = self.mgt_probe_request_decoder.decode(p.body_string)
        elif self.subtype is dot11.Dot11Types.DOT11_SUBTYPE_MANAGEMENT_PROBE_RESPONSE:
            self.mgt_probe_response_decoder = Dot11ManagementProbeResponseDecoder()
            packet = self.mgt_probe_response_decoder.decode(p.body_string)
        elif self.subtype is dot11.Dot11Types.DOT11_SUBTYPE_MANAGEMENT_DEAUTHENTICATION:
            self.mgt_deauthentication_decoder = Dot11ManagementDeauthenticationDecoder()
            packet = self.mgt_deauthentication_decoder.decode(p.body_string)
        elif self.subtype is dot11.Dot11Types.DOT11_SUBTYPE_MANAGEMENT_AUTHENTICATION:
            self.mgt_Authentication_decoder = Dot11ManagementAuthenticationDecoder()
            packet = self.mgt_Authentication_decoder.decode(p.body_string)
        elif self.subtype is dot11.Dot11Types.DOT11_SUBTYPE_MANAGEMENT_DISASSOCIATION:
            self.mgt_disassociation_decoder = Dot11ManagementDisassociationDecoder()
            packet = self.mgt_disassociation_decoder.decode(p.body_string)
        elif self.subtype is dot11.Dot11Types.DOT11_SUBTYPE_MANAGEMENT_ASSOCIATION_REQUEST:
            self.mgt_association_request_decoder = Dot11ManagementAssociationRequestDecoder()
            packet = self.mgt_association_request_decoder.decode(p.body_string)
        elif self.subtype is dot11.Dot11Types.DOT11_SUBTYPE_MANAGEMENT_ASSOCIATION_RESPONSE:
            self.mgt_association_response_decoder = Dot11ManagementAssociationResponseDecoder()
            packet = self.mgt_association_response_decoder.decode(p.body_string)
        elif self.subtype is dot11.Dot11Types.DOT11_SUBTYPE_MANAGEMENT_REASSOCIATION_REQUEST:
            self.mgt_reassociation_request_decoder = Dot11ManagementReassociationRequestDecoder()
            packet = self.mgt_reassociation_request_decoder.decode(p.body_string)
        elif self.subtype is dot11.Dot11Types.DOT11_SUBTYPE_MANAGEMENT_REASSOCIATION_RESPONSE:
            self.mgt_reassociation_response_decoder = Dot11ManagementReassociationResponseDecoder()
            packet = self.mgt_reassociation_response_decoder.decode(p.body_string)
        else:
            data_decoder = DataDecoder()
            packet = data_decoder.decode(p.body_string)
        
        p.contains(packet)
        return p

class Dot11ManagementBeaconDecoder(BaseDot11Decoder):
    def __init__(self):
        BaseDot11Decoder.__init__(self)
        
    def decode(self, aBuffer):
        p = dot11.Dot11ManagementBeacon(aBuffer)
        self.set_decoded_protocol( p )
        
        return p

class Dot11ManagementProbeRequestDecoder(BaseDot11Decoder):
    def __init__(self):
        BaseDot11Decoder.__init__(self)
        
    def decode(self, aBuffer):
        p = dot11.Dot11ManagementProbeRequest(aBuffer)
        self.set_decoded_protocol( p )
        
        return p

class Dot11ManagementProbeResponseDecoder(BaseDot11Decoder):
    def __init__(self):
        BaseDot11Decoder.__init__(self)
        
    def decode(self, aBuffer):
        p = dot11.Dot11ManagementProbeResponse(aBuffer)
        self.set_decoded_protocol( p )
        
        return p

class Dot11ManagementDeauthenticationDecoder(BaseDot11Decoder):
    def __init__(self):
        BaseDot11Decoder.__init__(self)

    def decode(self, aBuffer):
        p = dot11.Dot11ManagementDeauthentication(aBuffer)
        self.set_decoded_protocol( p )
        
        return p

class Dot11ManagementAuthenticationDecoder(BaseDot11Decoder):
    def __init__(self):
        BaseDot11Decoder.__init__(self)

    def decode(self, aBuffer):
        p = dot11.Dot11ManagementAuthentication(aBuffer)
        self.set_decoded_protocol(p)

        return p

class Dot11ManagementDisassociationDecoder(BaseDot11Decoder):
    def __init__(self):
        BaseDot11Decoder.__init__(self)
        
    def decode(self, aBuffer):
        p = dot11.Dot11ManagementDisassociation(aBuffer)
        self.set_decoded_protocol(p)
        
        return p

class Dot11ManagementAssociationRequestDecoder(BaseDot11Decoder):
    def __init__(self):
        BaseDot11Decoder.__init__(self)
        
    def decode(self, aBuffer):
        p = dot11.Dot11ManagementAssociationRequest(aBuffer)
        self.set_decoded_protocol(p)
        
        return p

class Dot11ManagementAssociationResponseDecoder(BaseDot11Decoder):
    def __init__(self):
        BaseDot11Decoder.__init__(self)
        
    def decode(self, aBuffer):
        p = dot11.Dot11ManagementAssociationResponse(aBuffer)
        self.set_decoded_protocol(p)
        
        return p

class Dot11ManagementReassociationRequestDecoder(BaseDot11Decoder):
    def __init__(self):
        BaseDot11Decoder.__init__(self)
        
    def decode(self, aBuffer):
        p = dot11.Dot11ManagementReassociationRequest(aBuffer)
        self.set_decoded_protocol(p)
        
        return p

class Dot11ManagementReassociationResponseDecoder(BaseDot11Decoder):
    def __init__(self):
        BaseDot11Decoder.__init__(self)
        
    def decode(self, aBuffer):
        p = dot11.Dot11ManagementReassociationResponse(aBuffer)
        self.set_decoded_protocol(p)
        
        return p

class BaseDecoder(Decoder):
    
    def decode(self, buff):
        
        packet = self.klass(buff)
        self.set_decoded_protocol(packet)
        cd = self.child_decoders.get(self.child_key(packet), DataDecoder())
        packet.contains(cd.decode(packet.get_body_as_string()))
        return packet

class SimpleConfigDecoder(BaseDecoder):

    child_decoders = {}
    klass = wps.SimpleConfig
    child_key = lambda s,p: None
    
    def decode(self, buff):
        sc = BaseDecoder.decode(self, buff)
        ary = array.array('B', sc.child().get_packet())
        sc.unlink_child()
        tlv = wps.SimpleConfig.build_tlv_container()
        tlv.from_ary(ary)
        sc.contains(tlv)
        
        return sc

class EAPExpandedDecoder(BaseDecoder):
    child_decoders = {
        (eap.EAPExpanded.WFA_SMI, eap.EAPExpanded.SIMPLE_CONFIG): SimpleConfigDecoder(),
    }
    klass = eap.EAPExpanded
    child_key = lambda s,p: (p.get_vendor_id(), p.get_vendor_type())
        
class EAPRDecoder(BaseDecoder):
    child_decoders = {
        eap.EAPR.EXPANDED:EAPExpandedDecoder()
    }
    klass = eap.EAPR
    child_key = lambda s, p: p.get_type()
        
class EAPDecoder(BaseDecoder):
    child_decoders = {
        eap.EAP.REQUEST: EAPRDecoder(),
        eap.EAP.RESPONSE: EAPRDecoder(),
    }
    klass = eap.EAP
    child_key = lambda s, p: p.get_code()
        
class EAPOLDecoder(BaseDecoder):
    child_decoders = {
        eap.EAPOL.EAP_PACKET: EAPDecoder()
    }
    klass = eap.EAPOL
    child_key = lambda s, p: p.get_packet_type()

class BootpDecoder(Decoder):
    def __init__(self):
        pass

    def decode(self, aBuffer):
        d = dhcp.BootpPacket(aBuffer)
        self.set_decoded_protocol( d )
        off = len(d.getData())
        if dhcp.DhcpPacket(aBuffer[off:])['cookie'] == dhcp.DhcpPacket.MAGIC_NUMBER:
            self.data_decoder = DHCPDecoder()
            packet = self.data_decoder.decode(aBuffer[off:])
            d.contains(packet)
        return d

class DHCPDecoder(Decoder):
    def __init__(self):
        pass

    def decode(self, aBuffer):
        d = dhcp.DhcpPacket(aBuffer)
        self.set_decoded_protocol( d )
        return d
