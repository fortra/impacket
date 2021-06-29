#!/usr/bin/python3
# 
# Extract encripted DPAPI RSA and export into a PEM file
# 
# 20200531  -   Initial Release

from binascii import unhexlify, hexlify
from hashlib import pbkdf2_hmac

from Cryptodome.Cipher import AES, PKCS1_v1_5
from Cryptodome.Hash import HMAC, SHA1, MD4

from impacket.dpapi import *
import argparse
import sys, os

DEBUG=False
class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

# Masterkey decryption function, mostly copy pasted from impacket
def master(master_key,sid,password):

    #master_key
    fp = open(master_key, 'rb')
    data = fp.read()
    mkf= MasterKeyFile(data)
    if DEBUG:
        mkf.dump()

    fp.close()
    data = data[len(mkf):]
    mk = MasterKey(data[:mkf['MasterKeyLen']])

    # Will generate two keys, one with SHA1 and another with MD4
    key1 = HMAC.new(SHA1.new(password.encode('utf-16le')).digest(), (sid + '\0').encode('utf-16le'), SHA1).digest()
    key2 = HMAC.new(MD4.new(password.encode('utf-16le')).digest(), (sid + '\0').encode('utf-16le'), SHA1).digest()
    # For Protected users
    tmpKey = pbkdf2_hmac('sha256', MD4.new(password.encode('utf-16le')).digest(), sid.encode('utf-16le'), 10000)
    tmpKey2 = pbkdf2_hmac('sha256', tmpKey, sid.encode('utf-16le'), 1)[:16]
    key3 = HMAC.new(tmpKey2, (sid + '\0').encode('utf-16le'), SHA1).digest()[:20]

    #/key1, key2, key3 = self.deriveKeysFromUser(self.options.sid, password)

    # if mkf['flags'] & 4 ? SHA1 : MD4
    decryptedKey = mk.decrypt(key3)
    if decryptedKey:
        print('Decrypted key with User Key (MD4 protected)')
        print('Decrypted key: 0x%s' % hexlify(decryptedKey).decode('latin-1'))
        return decryptedKey

    decryptedKey = mk.decrypt(key2)
    if decryptedKey:
        print('Decrypted key with User Key (MD4)')
        print('Decrypted key: 0x%s' % hexlify(decryptedKey).decode('latin-1'))
        return decryptedKey

    decryptedKey = mk.decrypt(key1)
    if decryptedKey:
        print('Decrypted key with User Key (SHA1)')
        print('Decrypted key: 0x%s' % hexlify(decryptedKey).decode('latin-1'))
        return decryptedKey

#MAIN
# arguments

parser = argparse.ArgumentParser()
parser.add_argument("--file","-f", help="blob file name")
parser.add_argument("--masterkey", "-m", help="set masterkey file")
parser.add_argument("--sid", "-s", help="set SID(optional)")
parser.add_argument("--password", "-p", help="user password")
parser.add_argument("--nopass","-n",dest="nopass",action='store_true',help="no password")
parser.set_defaults(nopass=False)
args = parser.parse_args()

just_mk = False
if (os.path.isfile(args.file)):
    print(bcolors.OKGREEN +" * "+ bcolors.ENDC + "File: " + args.file )
else:
    print(bcolors.FAIL +" X "+ bcolors.ENDC + "No File" )
if (args.masterkey):
    if(os.path.isfile(args.masterkey)):
        print(bcolors.OKGREEN +" * "+ bcolors.ENDC + "Masterkey File: " + args.masterkey )
    else:
        print(bcolors.FAIL +" X "+ bcolors.ENDC + "Masterkey is not a file " )
else:
    print(bcolors.FAIL +" X "+ bcolors.ENDC + "No Masterkey file " )
if (args.password):
    print(bcolors.OKGREEN +" * "+ bcolors.ENDC + "Password in" )
elif (args.nopass):
    args.password= ''
    print(bcolors.OKGREEN +" * "+ bcolors.ENDC + "Will try with no password" )
else:
    print(bcolors.FAIL +" X "+ bcolors.ENDC + "You need to supply password of use the --nopass " )
if (args.sid):
    print(bcolors.OKGREEN +" * "+ bcolors.ENDC + "User SID : " + args.sid )
else:
    print(bcolors.FAIL +" X "+ bcolors.ENDC + "Need user SID (S-1...) " )
if args.file and not args.sid and not (args.password or args.nopass) and not args.masterkey:
    just_mk = True
elif not args.file or not args.sid or not (args.password or args.nopass) or not args.masterkey:
    print("Need masterkey file name, SID and password")
    sys.exit(2)

#data_blob
fp = open(args.file,'rb')
data = fp.read()
# Read the blob and see if it uses the SIG values or not
blob= PVKHeader(data)
if blob['SigHeadLen'] > 0:
    if DEBUG:
        print ("SIG")
    fp.seek(0)
    data=fp.read()
    blob=PVKFile_SIG(data)

else:
    if DEBUG:
        print("NO SIG")
    fp.seek(0)
    data=fp.read()
    blob=PVKFile(data)

fp.close()

if DEBUG:
    blob.dump()

if (just_mk):
    print("MasterKey needed: ", end="")
    print(bin_to_string(blob['Blob']['GuidMasterKey']).lower())
    sys.exit(2)

#else go for the decrypt
key = master( args.masterkey , args.sid , args.password)

if DEBUG:
    print(hexlify(key).decode('latin-1'))

if (key):
    #According to the code on the mis-team/dpapick github the Export Flag is decoded using this hardcoded value as entropy
    entropy_pvk = blob['ExportFlag'].decrypt(key, b'Hj1diQ6kpUx7VC4m\0')
    print(bcolors.OKGREEN +" * "+ bcolors.ENDC + "RSAFlag Decrypted")
    # the resulting decoded text have to be used as entropy for the decryption of the key, but if I use it, it will not decrypt
    # More testing is needed (should be: 
    # decrypted = blob['Blob'].decrypt(key, entropy_pvk 

    decrypted = blob['Blob'].decrypt(key)
    
    if decrypted is not None:
        print()
        print(bcolors.OKGREEN +" * "+ bcolors.ENDC + "# # Blob Content decrypted # #")
        print()
        try:
            print(decrypted.decode('utf-16-le'))
        except:
            pass
        if DEBUG:
            f = open('decrypted.bin','wb')
            f.write(decrypted)
            f.close()
        #create the RSA decripted structure
        rsa_temp = PRIVATE_KEY_RSA(decrypted)
        if DEBUG:
            rsa_temp.dump()
        print(bcolors.OKGREEN +" * "+ bcolors.ENDC + "# # RSA Structure created # #")

        #call the function that will convert that structure to a Cryptodome RsaKey Object
        rsa_file = pvkblob_to_pkcs1(rsa_temp)
        print(bcolors.OKGREEN +" * "+ bcolors.ENDC + "# # RsaKey created # #")

        f = open('rsa_file.pem','wb')
        #export it
        f.write(rsa_file.export_key('PEM'))
        f.close()
        print(bcolors.OKGREEN +" * "+ bcolors.ENDC + "# # PEM Cert exported to rsa_file.pem # #")
         
else:
    # Just print the data
    blob.dump()

