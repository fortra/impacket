from impacket.dcerpc.v5 import nrpc, epm
from impacket.dcerpc.v5.dtypes import NULL
from impacket.dcerpc.v5 import transport
from impacket import crypto
from binascii import hexlify, unhexlify
from subprocess import check_call
from datetime import datetime
from struct import pack, unpack
from platform import python_version

import hmac, hashlib, struct, sys, socket, time, itertools, uuid, binascii, time, random

class userlog:
    def __init__(self, dc_name, computer_name, account_name, account_password, dc_ip):
        self.dc_name = dc_name
        self.computer_name = computer_name
        self.account_name = account_name
        self.account_password = account_password
        self.dc_ip = dc_ip

def ConnectRPCServer(dc_ip):
    rpc_con = None
    try :
        binding = epm.hept_map(dc_ip, nrpc.MSRPC_UUID_NRPC, protocol='ncacn_ip_tcp')
        rpc_con = transport.DCERPCTransportFactory(binding).get_dce_rpc()
        rpc_con.connect()
        rpc_con.bind(nrpc.MSRPC_UUID_NRPC)
    except:
        print("Unexpected error:", sys.exc_info()[0])
        raise
    return rpc_con

def authenticate(rpc_con, user):
    Client_Challenge = bytes(random.getrandbits(8) for i in range(8))
    status = nrpc.hNetrServerReqChallenge(rpc_con, NULL, user.computer_name + '\x00', Client_Challenge)
    if (status == None or status['ErrorCode'] != 0):
        print('Error NetrServerReqChallenge')
    else:
        Server_Challenge = status['ServerChallenge']
        print("Client_Challenge : ", Client_Challenge)
        print("Server_Challenge : ", Server_Challenge)
    SessionKey = nrpc.ComputeSessionKeyAES(user.account_password, Client_Challenge, Server_Challenge, bytearray.fromhex(user.account_password))
    print("Session_Key : ", SessionKey)
    Credential = nrpc.ComputeNetlogonCredentialAES(Client_Challenge, SessionKey)
    print("Credential : ", Credential)
    negotiateFlags = 0x612fffff
    try:
        resp = nrpc.hNetrServerAuthenticate3(rpc_con, user.dc_name + '\x00', user.account_name  + '\x00',
        nrpc.NETLOGON_SECURE_CHANNEL_TYPE.WorkstationSecureChannel, user.computer_name + '\x00', Credential, negotiateFlags)
        Authenticator = nrpc.ComputeNetlogonAuthenticator(Credential, SessionKey)
        resp = nrpc.hNetrLogonGetCapabilities(rpc_con, user.dc_name, user.computer_name, Authenticator)
        print("Secure Channel is UP !")
    except Exception as e:
        print('Unexpected error code from DC')

def InitiateSecureChannel(user):
    rpc_con = ConnectRPCServer(user.dc_ip)
    try :
        authenticate(rpc_con, user)
    except nrpc.DCERPCSessionError as ex:
        # Failure should be due to a STATUS_ACCESS_DENIED error.
        if ex.get_error_code() == 0xc0000022:
            pass
        else:
            print('Unexpected error code from DC')
    except BaseException as ex:
            print('Unexpected error')



def main():
    if (len(sys.argv) != 5):
        print('Usage: nrpcClient.py <dc-name> <computer_account_name> <account_password_hash> <dc-ip>\n')
        print('Note: dc-name should be the (NetBIOS) computer name of the domain controller.')
        sys.exit(1)
    else:
        print("\n \n         __Starting Client__")
        [_, dc_name, account_name, account_password, dc_ip] = sys.argv
        computer_name = socket.gethostname()
        dc_name = "\\\\" + dc_name
        print("DC Name : ", dc_name)
        print("DC IP : ", dc_ip)
        print("Computer Name : ", computer_name)
        print("Account Name : ", account_name)
        print("Account Password : ", account_password)
        print("Initiate Secure Channel ...")
        user = userlog(dc_name, computer_name, account_name, account_password, dc_ip)
        InitiateSecureChannel(user)

if __name__ == '__main__':
    main()