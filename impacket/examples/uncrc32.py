# based on:
#
#              Reversing CRC - Theory and Practice.
#                   HU Berlin Public Report
#                       SAR-PR-2006-05
#                         May 2006
#                         Authors:
# Martin Stigge, Henryk Plotz, Wolf Muller, Jens-Peter Redlich

FINALXOR = 0xffffffffL
INITXOR  = 0xffffffffL
CRCPOLY  = 0xEDB88320L
CRCINV   = 0x5B358FD3L

from binascii import crc32
from struct import pack

def tableAt(byte):
    return crc32(chr(byte ^ 0xff)) & 0xffffffff ^ FINALXOR ^ (INITXOR >> 8)

def compensate(buf, wanted):
    wanted ^= FINALXOR

    newBits = 0
    for i in range(32):
        if newBits & 1:
           newBits >>= 1
           newBits ^= CRCPOLY
        else:
           newBits >>= 1

        if wanted & 1:
           newBits ^= CRCINV

        wanted >>= 1

    newBits ^= crc32(buf) ^ FINALXOR
    return pack('<L', newBits)

def main():
    str = 'HOLA'
    t = 0x12345678
    print crc32(str + compensate(str, t)) == t
