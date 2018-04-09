#!/usr/bin/env python

#Impact test version
try:
    from impacket.ImpactDecoder import EthDecoder
    from impacket.ImpactPacket import TCP
except:
    pass

#Standalone test version
try:
    import sys
    sys.path.insert(0,"../..")
    from ImpactDecoder import EthDecoder
    from ImpactPacket import TCP
except:
    pass

from binascii import hexlify
import unittest

class TestTCP(unittest.TestCase):

    def setUp(self):
        # TCP - sport: 60655, dport: 80, sec: 0, HLen: 40, Flags: 0x02, win_size: 5840
        #  cksum: 0x64cb, Options: 0x20
        self.frame = '\xec\xef\x00\x50\xa8\xbd\xea\x4c\x00\x00\x00\x00\xa0\x02\x16\xd0' \
                     '\x64\xcb\x00\x00\x02\x04\x05\xb4\x04\x02\x08\x0a\x00\xdc\xd6\x12' \
                     '\x00\x00\x00\x00\x01\x03\x03\x06'

        self.tcp = TCP(self.frame)
        
    def test_01(self):
        'Test TCP get_packet'
        self.assertEqual(self.tcp.get_packet(), self.frame)

    def test_02(self):
        'Test TCP getters'
        self.assertEqual(self.tcp.get_th_sport(), 60655)
        self.assertEqual(self.tcp.get_th_dport(), 80)
        self.assertEqual(self.tcp.get_th_off()*4, 40) # *4 because are words
        self.assertEqual(self.tcp.get_th_flags(), 0x02)
        self.assertEqual(self.tcp.get_th_win(), 5840)
        self.assertEqual(self.tcp.get_th_sum(), 0x64cb)
        self.assertEqual(self.tcp.get_SYN(), 1)
        self.assertEqual(self.tcp.get_RST(), 0)

    def test_03(self):
        'Test TCP port setters'
        self.tcp.set_th_sport(54321)
        self.assertEqual(self.tcp.get_th_sport(), 54321)

        self.tcp.set_th_dport(81)
        self.assertEqual(self.tcp.get_th_dport(), 81)

    def test_04(self):
        'Test TCP offset setters'
        # test that set_th_off doesn't affect to flags
        flags = int('10101010',2)
        self.tcp.set_th_flags( flags )
        self.assertEqual(self.tcp.get_th_flags(), flags) 

        self.tcp.set_th_off(4)
        self.assertEqual(self.tcp.get_th_off(), 4)
        self.assertEqual(self.tcp.get_th_flags(), flags) 

    def test_05(self):
        'Test TCP win setters'

        self.tcp.set_th_win(12345)
        self.assertEqual(self.tcp.get_th_win(), 12345)

    def test_06(self):
        'Test TCP checksum setters'
        self.tcp.set_th_sum(0xFEFE)
        self.assertEqual(self.tcp.get_th_sum(), 0xFEFE)


    def test_07(self):
        'Test TCP flags setters'
        self.tcp.set_th_flags(0x03) # SYN+FIN
        self.assertEqual(self.tcp.get_th_flags(), 0x03) 
 
        self.tcp.set_ACK()
        self.assertEqual(self.tcp.get_ACK(), 1)
        self.assertEqual(self.tcp.get_SYN(), 1)
        self.assertEqual(self.tcp.get_FIN(), 1)
        self.assertEqual(self.tcp.get_RST(), 0)
        self.assertEqual(self.tcp.get_th_flags(), 19)

    def test_08(self):
        'Test TCP reset_flags'
        # Test 1
        self.tcp.set_th_flags(19) # ACK+SYN+FIN
        self.assertEqual(self.tcp.get_th_flags(), 19) 
        self.assertEqual(self.tcp.get_ACK(), 1)
        self.assertEqual(self.tcp.get_SYN(), 1)
        self.assertEqual(self.tcp.get_FIN(), 1)
        self.assertEqual(self.tcp.get_RST(), 0)

        self.tcp.reset_flags(0x02)

        self.assertEqual(self.tcp.get_th_flags(), 17) 

        # Test 2
        flags = int('10011', 2) # 19 = ACK+SYN+FIN
        self.tcp.set_th_flags(flags) 
        self.assertEqual(self.tcp.get_th_flags(), 19) 

        # 010011
        # 000010
        # ------
        # 010001 = 17
        self.tcp.reset_flags(int('000010',2))

        self.assertEqual(self.tcp.get_th_flags(), 17) 

        # Test 3
        flags = int('10011', 2) # 19 = ACK+SYN+FIN
        self.tcp.set_th_flags(flags) 
        self.assertEqual(self.tcp.get_th_flags(), 19) 

        # 010011
        # 010001
        # ------
        # 000010 = 2
        self.tcp.reset_flags(int('010001',2))

        self.assertEqual(self.tcp.get_th_flags(), 2) 
 
    def test_09(self):
        'Test TCP set_flags'
        flags = int('10101010',2) # 0xAA
        self.tcp.set_flags(flags) 
        self.assertEqual(self.tcp.get_FIN(), 0)
        self.assertEqual(self.tcp.get_SYN(), 1)
        self.assertEqual(self.tcp.get_RST(), 0)
        self.assertEqual(self.tcp.get_PSH(), 1)
        self.assertEqual(self.tcp.get_ACK(), 0)
        self.assertEqual(self.tcp.get_URG(), 1)
        self.assertEqual(self.tcp.get_ECE(), 0)
        self.assertEqual(self.tcp.get_CWR(), 1)
        self.assertEqual(self.tcp.get_th_flags(), 0xAA )

suite = unittest.TestLoader().loadTestsFromTestCase(TestTCP)
unittest.TextTestRunner(verbosity=1).run(suite)

