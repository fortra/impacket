#!/usr/bin/env python

# sorry, this is very ugly, but I'm in python 2.5
import sys
sys.path.insert(0,"../..")

from impacket.dot11 import Dot11,Dot11Types,Dot11DataFrame,Dot11WEP,Dot11WEPData
from impacket.ImpactPacket import IP,ICMP
from impacket.Dot11KeyManager import KeyManager
from impacket.ImpactDecoder import Dot11Decoder
from binascii import hexlify
import unittest

class TestDot11WEPData(unittest.TestCase):

    def setUp(self):
        # 802.11 Data Frame
        #
        self.dot11frame = '\x08\x41\x2c\x00\x00\x21\x29\x68\x33\x5d\x00\x18\xde\x7c\x37\x9f\x00\x21\x29\x68\x33\x5b\xf0\xd6\x0c\x31\x65\x00\x8d\x23\x81\xe9\x25\x1c\xb5\xaa\x83\xd2\xc7\x16\xba\x6e\xe1\x8e\x7d\x3a\x2c\x71\xc0\x0f\x6a\xb8\x2f\xbc\x54\xc4\xb0\x14\xab\x03\x11\x5e\xde\xcc\xab\x2b\x18\xeb\xeb\x25\x0f\x75\xeb\x6b\xf5\x7f\xd6\x5c\xb9\xe1\xb2\x6e\x50\xba\x4b\xb4\x8b\x9f\x34\x71\xda\x9e\xcf\x12\xcb\x8f\x36\x1b\x02\x53'
        
        d = Dot11(self.dot11frame, FCS_at_end = False)
        
        self.assertEqual(d.get_type(),Dot11Types.DOT11_TYPE_DATA)
        self.assertEqual(d.get_subtype(),Dot11Types.DOT11_SUBTYPE_DATA)
        self.assertEqual(d.get_type_n_subtype(),Dot11Types.DOT11_TYPE_DATA_SUBTYPE_DATA)
        
        data = Dot11DataFrame(d.get_body_as_string())
        d.contains(data)
        
        self.wep_header = Dot11WEP(data.body_string)
        data.contains(self.wep_header)
        
        self.wep_data = Dot11WEPData(self.wep_header.body_string)
        self.wep_header.contains(self.wep_data)
        
        self.km=KeyManager()
        self.km.add_key([0x00,0x21,0x29,0x68,0x33,0x5d],'999cbb701ca2ef030e302dcc35'.decode('hex_codec'))
        
    def test_01(self):
        'Test WEPHeader is_WEP method'
        self.assertEqual(self.wep_header.is_WEP(), True)
    
    def test_02(self):
        'Test Packet Hierarchy'
        dot11_decoder = Dot11Decoder()
        dot11_decoder.FCS_at_end(False)
        dot11_decoder.set_key_manager(self.km)
        in0=dot11_decoder.decode(self.dot11frame)
        self.assertEqual(str(in0.__class__), "impacket.dot11.Dot11")
        in1=in0.child()
        self.assertEqual(str(in1.__class__), "impacket.dot11.Dot11DataFrame")
        in2=in1.child()
        self.assertEqual(str(in2.__class__), "impacket.dot11.Dot11WEP")
        in3=in2.child()
        self.assertEqual(str(in3.__class__), "impacket.dot11.Dot11WEPData")
        in4=in3.child()
        self.assertEqual(str(in4.__class__), "impacket.dot11.LLC")
        in5=in4.child()
        self.assertEqual(str(in5.__class__), "impacket.dot11.SNAP")
        in6=in5.child()
        #self.assertEqual(str(in6.__class__), "ImpactPacket.IP")
        in7=in6.child()
        #self.assertEqual(str(in7.__class__), "ImpactPacket.ICMP")
        in8=in7.child()
        #self.assertEqual(str(in8.__class__), "ImpactPacket.Data")
        self.assertEqual(in8.get_packet(),'abcdefghijklmnopqrstuvwabcdefghi')
        
    def test_03(self):
        'Test WEPHeader IV getter and setter methods'
        self.assertEqual(self.wep_header.get_iv(), 0x0c3165)
        
        self.wep_header.set_iv(0x1e0501) # Es de 24 bit
        self.assertEqual(self.wep_header.get_iv(), 0x1e0501)

    def test_04(self):
        'Test WEPHeader keyID getter and setter methods'
        self.assertEqual(self.wep_header.get_keyid(), 0x00)
        
        self.wep_header.set_iv(0x03) # Es de 2 bits
        self.assertEqual(self.wep_header.get_iv(), 0x03)
    
    def test_05(self):
        'Test WEPData ICV getter and setter methods'
        
        dot11_decoder = Dot11Decoder()
        dot11_decoder.FCS_at_end(False)
        dot11_decoder.set_key_manager(self.km)
        dot11_decoder.decode(self.dot11frame)
        wepdata = dot11_decoder.get_protocol(Dot11WEPData)
        
        # The encrypted ICV is 0x361b0253, but it not the real,
        # we need decrypt it. The decrypted and real ICV is 0xA1F93985
        
        self.assertEqual(wepdata.get_icv(),0xA1F93985)
        
        self.assertEqual(wepdata.get_computed_icv(),0xA1F93985)
        
        self.assertEqual(wepdata.get_icv(), wepdata.get_computed_icv())
        
        wepdata.set_icv(0x11223344)
        self.assertEqual(wepdata.get_icv(), 0x11223344)
        
    def test_06(self):
        'Test WEPData body decryption'
        dot11_decoder = Dot11Decoder()
        dot11_decoder.FCS_at_end(False)
        dot11_decoder.set_key_manager(self.km)
        dot11_decoder.decode(self.dot11frame)
        wep = dot11_decoder.get_protocol(Dot11WEP)
        wepdata = dot11_decoder.get_protocol(Dot11WEPData)
        decrypted = '\xaa\xaa\x03\x00\x00\x00\x08\x00\x45\x00\x00\x3c\xa6\x07\x00\x00\x80\x01\xee\x5a\xc0\xa8\x01\x66\x40\xe9\xa3\x67\x08\x00\xc5\x56\x04\x00\x84\x05\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x61\x62\x63\x64\x65\x66\x67\x68\x69\xa1\xf9\x39\x85'
        self.assertEqual(wepdata.get_packet(), decrypted)
        self.assertEqual(wepdata.check_icv(), True)
        
        ip = dot11_decoder.get_protocol(IP)
        self.assertEqual(ip.get_ip_src(),'192.168.1.102')
        self.assertEqual(ip.get_ip_dst(),'64.233.163.103')
        
        icmp = dot11_decoder.get_protocol(ICMP)
        self.assertEqual(icmp.get_icmp_type(),icmp.ICMP_ECHO)
        self.assertEqual(icmp.get_icmp_id(),0x0400)

suite = unittest.TestLoader().loadTestsFromTestCase(TestDot11WEPData)
unittest.TextTestRunner(verbosity=1).run(suite)
