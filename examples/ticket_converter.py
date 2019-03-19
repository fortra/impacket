import argparse
import struct
import datetime

from pyasn1.codec.der import decoder, encoder

from pyasn1.type.univ import noValue
from impacket.krb5.asn1 import KRB_CRED, EncKrbCredPart, Ticket, seq_set, seq_set_iter, KrbCredInfo, EncryptionKey
from impacket.krb5.ccache import CCache, Header, Principal, Credential, KeyBlock, Times, CountedOctetString
from impacket.krb5 import types
from impacket.krb5.types import KerberosTime


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

    principal = ccache.principal
    credential = ccache.credentials[0]

    krb_cred_info = KrbCredInfo()

    krb_cred_info['key'] = noValue
    krb_cred_info['key']['keytype'] = credential['key']['keytype']
    krb_cred_info['key']['keyvalue'] = credential['key']['keyvalue']

    krb_cred_info['prealm'] = principal.realm.fields['data']

    krb_cred_info['pname'] = noValue
    krb_cred_info['pname']['name-type'] = principal.header['name_type']
    seq_set_iter(krb_cred_info['pname'], 'name-string', (principal.components[0].fields['data'],))

    krb_cred_info['flags'] = credential['tktflags']

    # krb_cred_info['authtime'] = KerberosTime.to_asn1(datetime.datetime.fromtimestamp(credential['time']['authtime']))
    krb_cred_info['starttime'] = KerberosTime.to_asn1(datetime.datetime.utcfromtimestamp(credential['time']['starttime']))
    krb_cred_info['endtime'] = KerberosTime.to_asn1(datetime.datetime.utcfromtimestamp(credential['time']['endtime']))
    krb_cred_info['renew-till'] = KerberosTime.to_asn1(datetime.datetime.utcfromtimestamp(credential['time']['renew_till']))

    krb_cred_info['srealm'] = credential['server'].realm.fields['data']

    krb_cred_info['sname'] = noValue
    krb_cred_info['sname']['name-type'] = credential['server'].header['name_type']
    seq_set_iter(krb_cred_info['sname'], 'name-string', (credential['server'].components[0].fields['data'], credential['server'].realm.fields['data']))

    enc_krb_cred_part = EncKrbCredPart()
    seq_set_iter(enc_krb_cred_part, 'ticket-info', (krb_cred_info,))

    encoder.encode(krb_cred_info)

    krb_cred = KRB_CRED()
    krb_cred['pvno'] = 5
    krb_cred['msg-type'] = 22

    krb_cred['enc-part'] = noValue
    krb_cred['enc-part']['etype'] = 0
    krb_cred['enc-part']['cipher'] = encoder.encode(enc_krb_cred_part)

    ticket = decoder.decode(credential.ticket['data'], asn1Spec=Ticket())[0]
    seq_set_iter(krb_cred, 'tickets', (ticket,))

    with open(output_filename, 'wb') as fo:
        fo.write(encoder.encode(krb_cred))


if __name__ == '__main__':
    main()
