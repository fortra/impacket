#!/usr/bin/env python

# sorry, this is very ugly, but I'm in python 2.5
import sys
sys.path.insert(0,"../..")

from ImpactPacket import TCP, ImpactPacketException
from binascii import hexlify
import unittest
from threading import Thread

class TestTCP(unittest.TestCase):

    def setUp(self):
	# Dummy TCP header with "Maximum Segment Size" Option and zero length
	self.frame = '\x12\x34\x00\x50\x00\x00\x00\x01\x00\x00\x00\x00\x60\x00\x00\x00\x8d\x5c\x00\x00\x02\x00\x00\x00'
        
    def test_01(self):
        'Test TCP options parsing hangs'
	class it_hangs(Thread):
		def __init__(self):
			Thread.__init__(self)
		def run(self):
			try:
				frame = '\x12\x34\x00\x50\x00\x00\x00\x01\x00\x00\x00\x00' \
					'\x60\x00\x00\x00\x8d\x5c\x00\x00\x02\x00\x00\x00'
				tcp = TCP(frame)
			#except Exception,e:
			#	print "aaaaaaaaaaaaaaa"
			#	print e
			#except Exception,e:
			except ImpactPacketException,e:
				if str(e) != "'TCP Option length is too low'":
					raise e
			except:
				pass

	thread_hangs = it_hangs()
	thread_hangs.setDaemon(True)
	thread_hangs.start()
        thread_hangs.join(1.0) # 1 seconds timeout
       	self.assertEqual(thread_hangs.isAlive(), False)
	#if thread_hang.isAlive():


suite = unittest.TestLoader().loadTestsFromTestCase(TestTCP)
unittest.TextTestRunner(verbosity=2).run(suite)

