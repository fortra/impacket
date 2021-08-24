# Impacket - Collection of Python classes for working with network protocols.
#
# SECUREAUTH LABS. Copyright (C) 2018 SecureAuth Corporation. All rights reserved.
#
# This software is provided under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Description:
#   Protocol Client Base Class definition
#   Defines a base class for all clients + loads all available modules
#
# Author:
#   Alberto Solino (@agsolino)
#
import os, sys, pkg_resources
from impacket import LOG

PROTOCOL_CLIENTS = {}

# Base class for Protocol Clients for different protocols (SMB, MSSQL, etc)
# Besides using this base class you need to define one global variable when
# writing a plugin for protocol clients:
# PROTOCOL_CLIENT_CLASS = "<name of the class for the plugin>"
# PLUGIN_NAME must be the protocol name that will be matched later with the relay targets (e.g. SMB, LDAP, etc)
class ProtocolClient:
    PLUGIN_NAME = 'PROTOCOL'
    def __init__(self, serverConfig, target, targetPort, extendedSecurity=True):
        self.serverConfig = serverConfig
        self.targetHost = target.hostname
        # A default target port is specified by the subclass
        if target.port is not None:
            # We override it by the one specified in the target
            self.targetPort = target.port
        else:
            self.targetPort = targetPort
        self.target = target
        self.extendedSecurity = extendedSecurity
        self.session = None
        self.sessionData = {}

    def initConnection(self):
        raise RuntimeError('Virtual Function')

    def killConnection(self):
        raise RuntimeError('Virtual Function')

    def sendNegotiate(self, negotiateMessage):
        """
        Charged of sending the type 1 NTLM Message

        :param bytes negotiateMessage:
        :return:
        """
        raise RuntimeError('Virtual Function')

    def sendAuth(self, authenticateMessageBlob, serverChallenge=None):
        """
        Charged of sending the type 3 NTLM Message to the Target

        :param bytes authenticateMessageBlob:
        :param bytes serverChallenge:
        :return:
        """
        raise RuntimeError('Virtual Function')

    def sendStandardSecurityAuth(self, sessionSetupData):
        # Handle the situation When FLAGS2_EXTENDED_SECURITY is not set
        raise RuntimeError('Virtual Function')

    def getSession(self):
        # Should return the active session for the relayed connection
        raise RuntimeError('Virtual Function')

    def getSessionData(self):
        # Should return any extra data that could be useful for the SOCKS proxy to work (e.g. some of the
        # answers from the original server)
        return self.sessionData

    def getStandardSecurityChallenge(self):
        # Should return the Challenge returned by the server when Extended Security is not set
        # This should only happen with against old Servers. By default we return None
        return None

    def keepAlive(self):
        # Charged of keeping connection alive
        raise RuntimeError('Virtual Function')

    def isAdmin(self):
        # Should return whether or not the user is admin in the form of a string (e.g. "TRUE", "FALSE")
        # Depending on the protocol, different techniques should be used.
        # By default, raise exception
        raise RuntimeError('Virtual Function')

for file in pkg_resources.resource_listdir('impacket.examples.ntlmrelayx', 'clients'):
    if file.find('__') >= 0 or file.endswith('.py') is False:
        continue
    # This seems to be None in some case (py3 only)
    # __spec__ is py3 only though, but I haven't seen this being None on py2
    # so it should cover all cases.
    try:
        package = __spec__.name  # Python 3
    except NameError:
        package = __package__    # Python 2
    __import__(package + '.' + os.path.splitext(file)[0])
    module = sys.modules[package + '.' + os.path.splitext(file)[0]]
    try:
        pluginClasses = set()
        try:
            if hasattr(module,'PROTOCOL_CLIENT_CLASSES'):
                for pluginClass in module.PROTOCOL_CLIENT_CLASSES:
                    pluginClasses.add(getattr(module, pluginClass))
            else:
                pluginClasses.add(getattr(module, getattr(module, 'PROTOCOL_CLIENT_CLASS')))
        except Exception as e:
            LOG.debug(e)
            pass

        for pluginClass in pluginClasses:
            LOG.info('Protocol Client %s loaded..' % pluginClass.PLUGIN_NAME)
            PROTOCOL_CLIENTS[pluginClass.PLUGIN_NAME] = pluginClass
    except Exception as e:
        LOG.debug(str(e))
