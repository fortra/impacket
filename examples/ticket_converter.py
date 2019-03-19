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
    with open(input_filename, 'rb') as fi:
        krb_cred = decoder.decode(fi.read(), asn1Spec=KRB_CRED())[0]
        enc_krb_cred_part = decoder.decode(krb_cred['enc-part']['cipher'], asn1Spec=EncKrbCredPart())[0]

    ccache = CCache()

    ccache.headers = []
    header = Header()
    header['tag'] = 1
    header['taglen'] = 8
    header['tagdata'] = '\xff\xff\xff\xff\x00\x00\x00\x00'
    ccache.headers.append(header)

    krb_cred_info = enc_krb_cred_part['ticket-info'][0]

    tmpPrincipal = types.Principal()
    tmpPrincipal.from_asn1(krb_cred_info, 'prealm', 'pname')
    ccache.principal = Principal()
    ccache.principal.fromPrincipal(tmpPrincipal)

    credential = Credential()
    server = types.Principal()
    server.from_asn1(krb_cred_info, 'srealm', 'sname')
    tmpServer = Principal()
    tmpServer.fromPrincipal(server)

    credential['client'] = ccache.principal
    credential['server'] = tmpServer
    credential['is_skey'] = 0

    credential['key'] = KeyBlock()
    credential['key']['keytype'] = int(krb_cred_info['key']['keytype'])
    credential['key']['keyvalue'] = str(krb_cred_info['key']['keyvalue'])
    credential['key']['keylen'] = len(credential['key']['keyvalue'])

    credential['time'] = Times()
    # credential['time']['authtime'] = ccache.toTimeStamp(types.KerberosTime.from_asn1(krb_cred_info['authtime']))
    credential['time']['starttime'] = ccache.toTimeStamp(types.KerberosTime.from_asn1(krb_cred_info['starttime']))
    credential['time']['endtime'] = ccache.toTimeStamp(types.KerberosTime.from_asn1(krb_cred_info['endtime']))
    credential['time']['renew_till'] = ccache.toTimeStamp(types.KerberosTime.from_asn1(krb_cred_info['renew-till']))

    flags = ccache.reverseFlags(krb_cred_info['flags'])
    credential['tktflags'] = flags

    credential['num_address'] = 0
    credential.ticket = CountedOctetString()
    credential.ticket['data'] = encoder.encode(krb_cred['tickets'][0].clone(tagSet=Ticket.tagSet, cloneValueFlag=True))
    credential.ticket['length'] = len(credential.ticket['data'])
    credential.secondTicket = CountedOctetString()
    credential.secondTicket['data'] = ''
    credential.secondTicket['length'] = 0
    ccache.credentials.append(credential)

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
