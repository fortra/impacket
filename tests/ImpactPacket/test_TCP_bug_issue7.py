#!/usr/bin/env python
# Impacket - Collection of Python classes for working with network protocols.
#
# SECUREAUTH LABS. Copyright (C) 2022 SecureAuth Corporation. All rights reserved.
#
# This software is provided under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
import unittest
from threading import Thread
from impacket.ImpactPacket import TCP, ImpactPacketException


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
                    TCP(frame)
                except ImpactPacketException as e:
                    if str(e) != "'TCP Option length is too low'":
                        raise e
                except Exception:
                    pass

        thread_hangs = it_hangs()
        thread_hangs.daemon = True
        thread_hangs.start()

        thread_hangs.join(1.0)  # 1 seconds timeout
        self.assertEqual(thread_hangs.is_alive(), False)


if __name__ == '__main__':
    unittest.main(verbosity=1)
