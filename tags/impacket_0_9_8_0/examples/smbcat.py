import sys
sys.path.append('..')
from impacket import smb

if len(sys.argv) < 4:
	print "Use: %s <host> <share> <file> [user] [password]" % sys.argv[0]
	sys.exit(1)

host = sys.argv[1]
shre = sys.argv[2]
file = sys.argv[3]
user = ''
passwd = ''
try:
	user = sys.argv[4]
	passwd = sys.argv[5]
except:
	pass

s = smb.SMB('*SMBSERVER',host)
s.login(user, passwd)
tid = s.tree_connect_andx(r"\\*SMBSERVER\%s" % shre)
fid = s.open_file(tid, file, smb.SMB_O_OPEN, smb.SMB_ACCESS_READ)[0]
offset = 0
while 1:
	data = s.read_andx(tid, fid, offset, 40000)
	sys.stdout.write(data)
	if len(data) == 0: break
	offset += len(data)

s.close_file(tid, fid)

