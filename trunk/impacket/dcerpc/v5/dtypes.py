from impacket.dcerpc.v5 import ndr

DWORD = ndr.NDRLONG
ULONGLONG = ndr.NDRHYPER
BOOL = ndr.NDRLONG

class GUID(ndr.NDR):
    structure = (
        ('Data','16s=""'),
    )

class PGUID(ndr.NDRPointer):
    referent = (
        ('Data', GUID),
    )

class PBOOL(ndr.NDRPointer):
    referent = (
        ('Data', BOOL),
    )

class LPBYTE(ndr.NDRPointer):
    align = 4
    align64 = 8
    referent = (
        ('Data', ndr.NDRUniConformantArray),
    )
PBYTE = LPBYTE

class LPWSTR(ndr.NDRPointer):
    referent = (
        ('Data', ndr.RPC_UNICODE_STRING),
    )

class LPDWORD(ndr.NDRPointer):
    align = 4
    align64 = 8
    referent = (
        ('Data', ndr.NDRUniConformantArray),
    )
    def __init__(self, data = None,isNDR64 = False, isNDRCall = False):
        ndr.NDRPointer.__init__(self, None, isNDR64, isNDRCall)
        # ToDo: change this so it is DWORD instead of <H
        self.fields['Data'].item = '<L'
        if data is not None:
            self.fromString(data)

