'''
this is a simple script for quick checking all your computers in your network to find out if the ms17-010 patch is installed on them.
you need to supply as parm a folder for the output and a file with a list of your ips.
for example:
CheckMS17-010.py c:\temp ips-list.txt
the file ips-list.txt shuold be in the folder c:\temp.
the script will create a file in the folder "c:\temp\logs" for each ip thats found as vulnerabile with a content of the os of the comp and if DP backdoor is installed.
enjoy!
'''
import subprocess
from ctypes import *
import socket
import struct
import ctypes
import logging
import sys
import impacket
import os.path
from impacket.smbconnection import *
import Crypto
import Crypto.Hash
import impacket.smb
__author__ = 'kazabubu21'


logging.basicConfig(level=logging.INFO, format="%(message)s")
log = logging.getLogger(__file__)


def mysend_trans(parmsmb, tid, setup, name, param, data, noAnswer=0):
    smbp = smb.NewSMBPacket()
    smbp['Tid'] = tid

    transCommand = smb.SMBCommand(smb.SMB.SMB_COM_TRANSACTION)
    transCommand['Parameters'] = smb.SMBTransaction_Parameters()
    transCommand['Data'] = smb.SMBTransaction_Data()

    transCommand['Parameters']['Setup'] = setup
    transCommand['Parameters']['TotalParameterCount'] = len(param)
    transCommand['Parameters']['TotalDataCount'] = len(data)

    transCommand['Parameters']['MaxParameterCount'] = 65535
    transCommand['Parameters']['MaxDataCount'] = 65535

    transCommand['Parameters']['ParameterCount'] = len(param)
    transCommand['Parameters']['ParameterOffset'] = 32 + 3 + 28 + len(setup) + len(name)

    transCommand['Parameters']['DataCount'] = len(data)
    transCommand['Parameters']['DataOffset'] = transCommand['Parameters']['ParameterOffset'] + len(param)

    transCommand['Data']['Name'] = name
    transCommand['Data']['Trans_Parameters'] = param
    transCommand['Data']['Trans_Data'] = data

    if noAnswer:
        transCommand['Parameters']['Flags'] = smb.SMB.TRANS_NO_RESPONSE

    smbp.addCommand(transCommand)
    smbp["Flags2"] = 0
    parmsmb.set_flags( flags2=smb.SMB.FLAGS2_EXTENDED_SECURITY + smb.SMB.FLAGS2_LONG_NAMES+ smb.SMB.FLAGS2_PAGING_IO)

    parmsmb.sendSMB(smbp)



def mysend_trans2(tid, setup, name, param, data,parmsmb):
    smbp = smb.NewSMBPacket()
    smbp['Tid']  = tid
    smbp['Mid']  = 65

    command = struct.pack('<H', setup)

    transCommand = smb.SMBCommand(smb.SMB.SMB_COM_TRANSACTION2)
    transCommand['Parameters'] = smb.SMBTransaction2_Parameters()

    transCommand['Parameters']['MaxParameterCount'] = 1
    transCommand['Parameters']['MaxDataCount'] = 0
    transCommand['Parameters']['TotalParameterCount'] = 12
    transCommand['Parameters']['ParameterCount'] = 12
    transCommand['Parameters']['ParameterOffset'] = 66
    transCommand['Parameters']['DataOffset'] = 78
    transCommand['Parameters']['SetupCount'] = 1
    transCommand['Parameters']['DataCount'] = 0
    transCommand['Parameters']['Timeout'] = 0x00a4d9a6
    transCommand['Parameters']['TotalParameterCount'] = 12
    transCommand['Parameters']['TotalDataCount'] = 0


    parmsmb.set_flags( flags1=0, flags2=0)
    smbp['Flags1'] = 0x18
    smbp['Flags2'] = 0xc007

    transCommand['Data'] = smb.SMBTransaction2_Data()

    transCommand['Parameters']['Setup'] = command

    transCommand['Data']['Pad1'] = ''
    padLen = 0

    transCommand['Data']['Pad2'] = ''
    pad2Len = 0

    #transCommand['Parameters']['DataCount'] = len(data)
    #transCommand['Parameters']['DataOffset'] = transCommand['Parameters']['ParameterOffset'] + len(param) + pad2Len

    transCommand['Data']['Name'] = name
    transCommand['Data']['Trans_Parameters'] = param
    transCommand['Data']['Trans_Data'] = data
    smbp.addCommand(transCommand)

    parmsmb.sendSMB(smbp)

def GetSubnetMask():
    proc = subprocess.Popen('ipconfig',stdout=subprocess.PIPE)
    while True:
        line = proc.stdout.readline()
        if ip.encode() in line:
            break
    mask = proc.stdout.readline().rstrip().split(b':')[-1].replace(b' ',b'').decode()
    cidr = sum([bin(int(x)).count('1') for x in mask.split(".")])
    cidr = int(cidr)
    return cidr

def check(ip, port=445):
    output = ""
    cheked = 0
    """Check if MS17_010 SMB Vulnerability exists.
    """
    try:
        # 0xC0000205 - STATUS_INSUFF_SERVER_RESOURCES - vulnerable
        # 0xC0000008 - STATUS_INVALID_HANDLE
        # 0xC0000022 - STATUS_ACCESS_DENIED

        smbc = SMBConnection(ip,ip,sess_port=445,preferredDialect=SMB_DIALECT, timeout=3)
        smbc.login("","",".")
        smbs = smbc.getSMBServer()
        tid = smbs.tree_connect_andx("ipc$")
        native_os =  smbc.getServerOS()
        mysend_trans(smbs,tid,"\x23\x00\x00\x00","\\PIPE\\\x00","","")
        p = smbs.recvSMB()
        nt_status = p.rawData[5:9]

        if nt_status == '\x05\x02\x00\xc0':
            output +="({}),".format(native_os)
            cheked = 8
            mysend_trans2(tid,0x000e,"","\x0c\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00","",smbs)
            p = smbs.recvSMB()
            multiplex_id = p.rawData[30:32]
            if multiplex_id == "\x51\x00":
                signature = p.rawData[14:22]
                #key = calculate_doublepulsar_xor_key(long((signature).encode('hex'),16))
                output +="{}".format((signature).encode('hex'))
                cheked = 9
            else:
                output +="1"

        elif nt_status in ('\x08\x00\x00\xc0', '\x22\x00\x00\xc0'):
            #output +="[-] [{}] does NOT appear vulnerable\r\n".format(ip)
            cheked = 5
        else:
            #print nt_status.encode('hex')
            #output +="[-] [{}] Unable to detect if this host is vulnerable\r\n".format(ip)
            cheked = 6

    except Exception as err:
        #if not ("did not properly respond after a period of time" in str(err)):
         #   if not ("timed out" in str(err)):
          #      if not ("actively refused it" in str(err)):
        output +="[-] [{}] Exception: {}\r\n".format(ip, err)
        cheked = 7
        return (cheked,output)
        #cheked=6

    return (cheked,output)

if __name__ == '__main__':
    if len(sys.argv) != 3:
        print("{} <folder path for resault without \\ at the end> <file with list of ips in the path of the resault >".format(sys.argv[0]))
        sys.exit(1)
    else:
        base_path = sys.argv[1]
        iplistfile = sys.argv[2]
    if not os.path.exists(base_path+"\\logs"):
        os.makedirs(base_path+"\\logs")

    #stop_file_path = base_path  + "\\stop"

    # ip = socket.gethostbyname(socket.gethostname())
    # print (socket.gethostbyname(socket.gethostname()))
    # print (socket.gethostname())
    with open(base_path+"\\"+iplistfile) as f:
        for line in f:
            ip = line.strip("\n")
            # hosts_bits = 32 - 24 #GetSubnetMask()
            # i = struct.unpack('>I',socket.inet_aton(ip))[0]
            # start = (i >> hosts_bits) << hosts_bits
            # end = i | ((1<< hosts_bits) - 1)
            # print start+1
            # print end -4
            # # (cheked, ret) = check("192.168.43.94")
            # print (ret + "\r\n")
            # if cheked >= 8:
            #     f = open(base_path  + "\\"  +"192.168.43.94", 'w')
            #     f.write(ret)
            #     f.close()
            # for i in range(start+1,end-3):
            print ip
            cip = ip
            print (cip + " cheking...\r\n")
            cipfilepath = base_path  + "\\logs\\"  + cip
            # if (os.path.isfile(stop_file_path)) == True:
            #     exit()
            # if (os.path.isfile(cipfilepath)) == False:
            (cheked,ret) = check(cip)
            print (ret + "\r\n")
            if cheked >= 7:
                f =open (cipfilepath,'w')
                f.write(ret)
                f.close()



