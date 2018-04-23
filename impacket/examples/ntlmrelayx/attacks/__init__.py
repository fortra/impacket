# Copyright (c) 2013-2017 CORE Security Technologies
#
# This software is provided under under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Protocol Attack Base Class definition
#
# Authors:
#  Alberto Solino (@agsolino)
#  Dirk-jan Mollema (@_dirkjan) / Fox-IT (https://www.fox-it.com)
#
# Description:
#  Defines a base class for all attacks + loads all available modules
#
# ToDo:
#
import os, sys
import pkg_resources
from impacket import LOG
from threading import Thread

PROTOCOL_ATTACKS = {}

# Base class for Protocol Attacks for different protocols (SMB, MSSQL, etc)
# Besides using this base class you need to define one global variable when
# writing a plugin for protocol clients:
#     PROTOCOL_ATTACK_CLASS = "<name of the class for the plugin>"
# or (to support multiple classes in one file)
#     PROTOCOL_ATTACK_CLASSES = ["<name of the class for the plugin>", "<another class>"]
# These classes must have the attribute PLUGIN_NAMES which is a list of protocol names
# that will be matched later with the relay targets (e.g. SMB, LDAP, etc)
class ProtocolAttack(Thread):
    PLUGIN_NAMES = ['PROTOCOL']
    def __init__(self, config, client, username):
        Thread.__init__(self)
        # Set threads as daemon
        self.daemon = True
        self.config = config
        self.client = client
        # By default we only use the username and remove the domain
        self.username = username.split('/')[1]

    def run(self):
        raise RuntimeError('Virtual Function')

for file in pkg_resources.resource_listdir('impacket.examples.ntlmrelayx', 'attacks'):
    if file.find('__') >=0 or os.path.splitext(file)[1] == '.pyc':
        continue
    __import__(__package__ + '.' + os.path.splitext(file)[0])
    module = sys.modules[__package__ + '.' + os.path.splitext(file)[0]]
    try:
        pluginClasses = set()
        try:
            if hasattr(module,'PROTOCOL_ATTACK_CLASSES'):
                # Multiple classes
                for pluginClass in module.PROTOCOL_ATTACK_CLASSES:
                    pluginClasses.add(getattr(module, pluginClass))
            else:
                # Single class
                pluginClasses.add(getattr(module, getattr(module, 'PROTOCOL_ATTACK_CLASS')))
        except Exception, e:
            LOG.debug(e)
            pass

        for pluginClass in pluginClasses:
            for pluginName in pluginClass.PLUGIN_NAMES:
                LOG.debug('Protocol Attack %s loaded..' % pluginName)
                PROTOCOL_ATTACKS[pluginName] = pluginClass
    except Exception, e:
        LOG.debug(str(e))

