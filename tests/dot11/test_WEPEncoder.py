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
from binascii import unhexlify
import impacket.dot11
import impacket.ImpactPacket
from impacket.Dot11KeyManager import KeyManager


class TestDot11WEPData(unittest.TestCase):

    def setUp(self):
        self.dot11 = impacket.dot11.Dot11(FCS_at_end = False)
        
        # dot11.fc
        self.dot11.set_version(0)
        self.dot11.set_type_n_subtype(impacket.dot11.Dot11Types.DOT11_TYPE_DATA_SUBTYPE_DATA)

        # dot11.fc.flags
        self.dot11.set_fromDS(0)
        self.dot11.set_toDS(1)
        self.dot11.set_moreFrag(0)
        self.dot11.set_retry(0)
        self.dot11.set_powerManagement(0)
        self.dot11.set_moreData(0)
        self.dot11.set_protectedFrame(1)
        self.dot11.set_order(0)
        
        # dot11.Data
        self.dot11data = impacket.dot11.Dot11DataFrame()
        self.dot11data.set_duration(44)
        self.dot11data.set_address1([0x00,0x21,0x29,0x68,0x33,0x5d]) # Bssid
        self.dot11data.set_address2([0x00,0x18,0xde,0x7c,0x37,0x9f]) # Source
        self.dot11data.set_address3([0x00,0x21,0x29,0x68,0x33,0x5d]) # Destination
        self.dot11data.set_fragment_number(0)
        self.dot11data.set_sequence_number(3439)
        
        # WEP
        self.wep = impacket.dot11.Dot11WEP()
        self.wep.set_iv(0x0c3165)
        self.wep.set_keyid(0)
        
        # WEPData
        self.wepdata = impacket.dot11.Dot11WEPData()
        
        # LLC
        self.llc = impacket.dot11.LLC()
        self.llc.set_DSAP(0xaa)
        self.llc.set_SSAP(0xaa)
        self.llc.set_control(0x03)
        
        # SNAP
        self.snap = impacket.dot11.SNAP()
        self.snap.set_OUI(0x000000)
        self.snap.set_protoID(0x0800)
        
        # IP
        self.ip = impacket.ImpactPacket.IP()
        self.ip.set_ip_v(0x04)
        self.ip.set_ip_tos(0x00)
        self.ip.set_ip_id(0xa607)
        # IP.flags
        self.ip.set_ip_rf(0)
        self.ip.set_ip_df(0)
        self.ip.set_ip_mf(0)
        #
        self.ip.set_ip_off(0)
        self.ip.set_ip_ttl(128)
        self.ip.set_ip_p(0x01) # ICMP
        self.ip.set_ip_src('192.168.1.102')
        self.ip.set_ip_dst('64.233.163.103')
        
        # ICMP
        self.icmp = impacket.ImpactPacket.ICMP()
        self.icmp.set_icmp_type(self.icmp.ICMP_ECHO)
        self.icmp.set_icmp_code(0x00)
        self.icmp.set_icmp_id(0x0400)
        self.icmp.set_icmp_seq(0x8405)
        
        # Data
        datastring = b'abcdefghijklmnopqrstuvwabcdefghi'
        self.data = impacket.ImpactPacket.Data( datastring )
        
        # Build the protocol stack
        self.dot11.contains(self.dot11data)
        self.dot11data.contains(self.wep)
        self.wep.contains(self.wepdata)
        self.wepdata.contains(self.llc)
        self.llc.contains(self.snap)
        self.snap.contains(self.ip)
        self.ip.contains(self.icmp)
        self.icmp.contains(self.data)
        
        # Instantiated the Key Manager
        self.km=KeyManager()
        self.km.add_key([0x00,0x21,0x29,0x68,0x33,0x5b],unhexlify('999cbb701ca2ef030e302dcc35'))
        
    def test_02(self):
        'Test ICV methods'
        self.assertEqual(self.wepdata.get_icv(),0x00000000)
        self.assertEqual(self.wepdata.get_computed_icv(),0xA1F93985)
        self.wepdata.set_icv(0xA1F93985)
        self.assertEqual(self.wepdata.get_icv(), self.wepdata.get_computed_icv())
        self.wepdata.set_icv(0x01020304)
        self.assertEqual(self.wepdata.get_icv(),0x01020304)
        
    def test_03(self):
        'Test WEPData creation from scratch with encryption'
        
        #print "\nWEP Data Decrypted [%s]"%hexlify(self.wepdata.get_packet())
        self.wepdata.set_icv(0xA1F93985)
        wep_enc=self.wep.get_encrypted_data(unhexlify('999cbb701ca2ef030e302dcc35'))
        #print "\nWEP Data Encrypted [%s]"%hexlify(wep_enc)
        self.assertEqual(wep_enc,unhexlify('8d2381e9251cb5aa83d2c716ba6ee18e7d3a2c71c00f6ab82fbc54c4b014ab03115edeccab2b18ebeb250f75eb6bf57fd65cb9e1b26e50ba4bb48b9f3471da9ecf12cb8f361b0253'))
        
        #print "\nDot11 decrypted [%s]"%hexlify(self.dot11.get_packet())
        self.wep.encrypt_frame(unhexlify('999cbb701ca2ef030e302dcc35'))
        #print "\nDot11 encrypted [%s]"%hexlify(self.dot11.get_packet())


if __name__ == '__main__':
    unittest.main(verbosity=1)
