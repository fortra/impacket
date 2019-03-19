import argparse
import struct
from impacket.krb5.ccache import CCache


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('input_file')
    parser.add_argument('output_file')
    return parser.parse_args()


def main():
    args = parse_args()

    if is_kirbi_file(args.input_file):
        print 'Kirbi file Found, Converting to ccache'
        convert_kirbi_to_ccache(args.input_file, args.output_file)
    elif is_ccache_file(args.input_file):
        print 'CCache file Found, Converting to kirbi'
        convert_ccache_to_kirbi(args.input_file, args.output_file)
    else:
        print 'Unknown File Type'


def is_kirbi_file(filename):
    with open(filename, 'rb') as fi:
        fileid = struct.unpack(">B", fi.read(1))[0]
    return fileid == 0x76


def is_ccache_file(filename):
    with open(filename, 'rb') as fi:
        fileid = struct.unpack(">B", fi.read(1))[0]
    return fileid == 0x5


def convert_kirbi_to_ccache(input_filename, output_filename):
    ccache = CCache.loadKirbiFile(input_filename)
    ccache.saveFile(output_filename)


def convert_ccache_to_kirbi(input_filename, output_filename):
    ccache = CCache.loadFile(input_filename)
    ccache.saveKirbiFile(output_filename)


if __name__ == '__main__':
    main()
