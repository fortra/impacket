from impacket.dcerpc.v5 import dcomrt
from impacket.dcerpc.v5 import rpcrt
import pdb

'''
# next create a socket object
s = socket.socket()
print("Socket successfully created")

# reserve a port on your computer in our
# case it is 12345 but it can be anything
port = 135

# Next bind to the port
# we have not typed any ip in the ip field
# instead we have inputted an empty string
# this makes the server listen to requests
# coming from other computers on the network
s.bind(('', port))
print("socket binded to %s" % (port))

# put the socket into listening mode
s.listen(5)
print("socket is listening")

# a forever loop until we interrupt it or
# an error occurs
while True:
    # Establish connection with client.
    c, addr = s.accept()
    print('Got connection from', addr)

    data = c.recv(4096)
    rpc_bind = rpcrt.MSRPCBind().fromString(data)
    resp = dcomrt.ResolveOxidResponse()

    # send a thank you message to the client. encoding to send byte type.
    c.send('Thank you for connecting'.encode())


    # Close the connection with the client
    c.close()

    # Breaking once connection closed
    break
'''
server = rpcrt.DCERPCServer()
server.setListenPort(135)
server.setListenAddress("192.168.161.130")
server._sock.listen(10)
server._clientSock, address = server._sock.accept()
data = server.recv()
packet = rpcrt.MSRPCHeader(data)
if packet['type'] == rpcrt.MSRPC_BIND:
    bind   = rpcrt.MSRPCBind(packet['pduData'])


ctx_items_data = bind["ctx_items"]

resp = rpcrt.MSRPCBindAck()

server._clientSock.close()
#data2 = server.processRequest(data)
print("hello")