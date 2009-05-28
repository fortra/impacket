from impacket.dcerpc import transport
from impacket import uuid, smb
import random

class DCERPCExploit:
    params = {
	# general options
	'host': '192.168.1.1',
	'pipe': 'browser',
	'port': 139,
	'proto': 1,           # 0 UDP, 1 SMB

	# SMB options
	'tree_connect': 0,    # 0 = tree_connect, 1 = tree_connect_andx
	'open': 0,            # 0 = open, 1 = open_andx, 2 = nt_create_andx
	'read': 0,            # 0 = read, 1 = read_andx, 2 = read_raw, 3 = read_cycling
	'write': 0,           # 0 = write, 1 = write_andx, 2 = write_raw, 3 = write_cycling
	'transport_frag': -1, # -1 = don't fragment, use TransactNamedPipe.
	'random_offsets': 0,  # randomize offset in write and read requests (when cycling)
	'smb_user': '',
	'smb_passwd': '',
	'smb_lmhash': '',     # lm_hash, first part of pwdump3 output, On of the hashes is enough
	'smb_nthash': '',     # nt_hash, second part of pwdump3 output

	# DCERPC options
	'idempotent': 0,      # 
	'dcerpc_frag': -1,    # -1 - don't fragment
	'alter_ctx': 0,       # use alter_ctx instead of bind(). Will issue a bogus bind first
	'bogus_binds': 0,     # number of bogus UUIDs in bind() request
	'bogus_alter': 0,     # number of bogus UUIDs in alter_ctx(), implies alter_ctx
	'endianness': '<',    # < for little endian, > for big endian
	                      # When switching to big endian you also need to change the
			      # endianness of the parameters to the function (in dce.call())
			      # Structure does not currently have decent support for this,
			      # specially for the 'w' fields.
    }

    UUID = ('01010101-2323-4545-6767-898989898989','1.0')
    BOGUS_UUID = ('12341234-5678-5678-5678-1234567890ab','1.0')

    def __init__(self, argv):
	for arg in argv:
	    args = arg.split('=',2)
	    if len(args) != 2:
	        self.usage()
		raise Exception, "Error parsing argument %r" % arg

	    if len(args) == 1:
		continue
	    self.params[args[0]] = args[1]
	
	self.WRITE_TYPE = 0
	self.READ_TYPE  = 0

    protocols = (
	    'ncadg_ip_udp:%(host)s[%(port)d]',
	    'ncacn_np:%(host)s[\\pipe\\%(pipe)s]',
    )

    def run(self):
        self.setupConnection()
	self.attackRun()
        
    def open(self, *args):
	args = list(args)
	args[1] = r'\\pipe%s' % args[1]
	args.append(smb.SMB_O_CREAT)
	args.append(smb.SMB_ACCESS_WRITE | smb.SMB_ACCESS_READ)
	return self.smb.open(*args)[0]
	
    def open_andx(self, *args):
	args = list(args)
	args[1] = r'\\pipe%s' % args[1]
	args.append(smb.SMB_O_CREAT)
	args.append(smb.SMB_ACCESS_WRITE | smb.SMB_ACCESS_READ)
	return self.smb.open_andx(*args)[0]
	
    def write_cycling(self, *args, **kargs):
	w = (self.smb.write, self.smb.original_write_andx, self.smb.write_raw)[self.WRITE_TYPE]
	self.WRITE_TYPE += 1
	self.WRITE_TYPE %= 3
	if int(self.params['random_offsets']):
	    kargs['offset'] = random.randint(0,65535)
	return w(*args, **kargs)

    def read_cycling(self, *args, **kargs):
	w = (self.smb.read, self.smb.original_read_andx, self.smb.read_raw)[self.READ_TYPE]
	self.READ_TYPE += 1
	self.READ_TYPE %= 3
	if int(self.params['random_offsets']):
	    kargs['offset'] = random.randint(0,65535)
	return w(*args, **kargs)

    def setupConnection(self):
	proto = int(self.params['proto'])
	self.params['port'] = int(self.params['port'])
	
	stringbinding  = self.protocols[proto]
	stringbinding %= self.params

	print "Using stringbinding: %r" % stringbinding

	self.trans = transport.DCERPCTransportFactory(stringbinding)
	self.trans.set_max_fragment_size(int(self.params['transport_frag']))
	self.trans.set_dport(int(self.params['port']))

	try:
	    # SMB parameters handling
	    self.trans.setup_smb_server()

	    # force building the SMB object so we can change its methods
	    self.smb = self.trans.get_smb_server()

	    # select the right tree_connect
	    arg = int(self.params['tree_connect'])
	    if   arg == 0: self.smb.tree_connect_andx = self.smb.tree_connect
	    if   arg == 1: self.smb.tree_connect_andx = self.smb.tree_connect_andx

	    # open selection
	    arg = int(self.params['open'])
	    if   arg == 0: self.smb.nt_create_andx = self.open
	    elif arg == 1: self.smb.nt_create_andx = self.open_andx

	    # read selection
	    arg = int(self.params['read'])
	    if   arg == 0: self.smb.read_andx = self.smb.read
	    elif arg == 1: self.smb.read_andx = self.smb.read_andx
	    elif arg == 2: self.smb.read_andx = self.smb.read_raw
	    elif arg == 3:
	    	self.smb.original_read_andx = self.smb.read_andx
		self.smb.read_andx = self.read_cycling

	    # write selection
	    arg = int(self.params['write'])
	    if   arg == 0: self.smb.write_andx = self.smb.write
	    elif arg == 1: self.smb.write_andx = self.smb.write_andx
	    elif arg == 2: self.smb.write_andx = self.smb.write_raw
	    elif arg == 3: 
	    	self.smb.original_write_andx = self.smb.write_andx
	    	self.smb.write_andx = self.write_cycling

	    # smb credentials
	    self.trans.set_credentials(
		self.params['smb_user'],
		self.params['smb_passwd'],
		lm_hash = self.params['smb_lmhash'],
		nt_hash = self.params['smb_nthash'])

	except Exception, e:
	    pass

	self.trans.connect()

	self.dce = self.trans.DCERPC_class(self.trans)
	self.dce.endianness = self.params['endianness']

	# DCERPC parameters handling
	self.dce.set_max_fragment_size(int(self.params['dcerpc_frag']))
	self.dce.set_idempotent(int(self.params['idempotent']))

	# alter_ctx
	alter = int(self.params['alter_ctx']) or int(self.params['bogus_alter'])
	if alter:
	    _uuid = self.BOGUS_UUID
	else:
	    _uuid = self.UUID
	
	# bogus_binds
	self.dce.bind(uuid.uuidtup_to_bin(_uuid), bogus_binds = int(self.params['bogus_binds']))

	if proto and alter:
	    self.dce = self.dce.alter_ctx(uuid.uuidtup_to_bin(self.UUID), bogus_binds = int(self.params['bogus_alter']))

    def usage(self):
        print "Use: python example.py param1=value param2=value2 ..."
	print "see exploit.py to see al available parameters"
	print "for example:\n"
	print "$ python example.py host=192.168.1.1 transport_frag=10"

    def attackRun(self):
        pass
