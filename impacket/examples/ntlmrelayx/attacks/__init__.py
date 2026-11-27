# Impacket - Collection of Python classes for working with network protocols.
#
# Copyright Fortra, LLC and its affiliated companies 
#
# All rights reserved.
#
# This software is provided under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Description:
#   Protocol Attack Base Class definition
#   Defines a base class for all attacks + loads all available modules
#
# Author:
#  Alberto Solino (@agsolino)
#  Dirk-jan Mollema (@_dirkjan) / Fox-IT (https://www.fox-it.com)
#
import sys
import importlib
import pkgutil
from impacket import LOG
from threading import Thread

from impacket.examples.ntlmrelayx.utils.identity_log import identity_context

PROTOCOL_ATTACKS = {}

# Base class for Protocol Attacks for different protocols (SMB, MSSQL, etc)
# Besides using this base class you need to define one global variable when
# writing a plugin for protocol clients:
#     PROTOCOL_ATTACK_CLASS = "<name of the class for the plugin>"
# or (to support multiple classes in one file)
#     PROTOCOL_ATTACK_CLASSES = ["<name of the class for the plugin>", "<another class>"]
# These classes must have the attribute PLUGIN_NAMES which is a list of protocol names
# that will be matched later with the relay targets (e.g. SMB, LDAP, etc)

def _wrap_run_with_identity(run_func):
    def _wrapped(self, *a, **k):
        if self.target is not None and self.relay_client is not None:
            connection_identifier = '%s://%s/%s@%s [%s]' % (self.target.scheme, self.domain, self.username, self.target.hostname, self.relay_client.client_id)
            with identity_context(connection_identifier):
                return run_func(self, *a, **k)
        else:
            return run_func(self, *a, **k)
    return _wrapped

class ProtocolAttack(Thread):
    PLUGIN_NAMES = ['PROTOCOL']

    def __init_subclass__(cls, **kwargs):
        super().__init_subclass__(**kwargs)
        # If subclass defines its own run(), wrap it
        if 'run' in cls.__dict__:
            cls.run = _wrap_run_with_identity(cls.run)

    def __init__(self, config, client, username, target=None, relay_client=None):
        Thread.__init__(self)
        # Set threads as daemon
        self.daemon = True
        self.config = config
        self.client = client
        # By default we only use the username and remove the domain
        self.username = username.split('/')[1]
        # But we also store the domain for later use
        self.domain = username.split('/')[0]
        # -- 
        self.target = target 
        self.relay_client = relay_client

    def run(self):
        raise RuntimeError('Virtual Function')

# Load all available attack plugins. We enumerate submodules with
# pkgutil.iter_modules instead of walking the directory on disk so this keeps
# working when impacket is bundled into a frozen executable (e.g. PyInstaller),
# where submodules live inside an archive rather than as .py files on disk.
for _, module_name, _ in pkgutil.iter_modules(__path__, __name__ + '.'):
    if '__' in module_name.rsplit('.', 1)[-1]:
        continue
    importlib.import_module(module_name)
    module = sys.modules[module_name]
    try:
        pluginClasses = set()
        try:
            if hasattr(module, 'PROTOCOL_ATTACK_CLASSES'):
                # Multiple classes
                for pluginClass in module.PROTOCOL_ATTACK_CLASSES:
                    pluginClasses.add(getattr(module, pluginClass))
            else:
                # Single class
                pluginClasses.add(getattr(module, getattr(module, 'PROTOCOL_ATTACK_CLASS')))
        except Exception as e:
            LOG.debug(e)
            pass

        for pluginClass in pluginClasses:
            for pluginName in pluginClass.PLUGIN_NAMES:
                LOG.debug('Protocol Attack %s loaded..' % pluginName)
                PROTOCOL_ATTACKS[pluginName] = pluginClass
    except Exception as e:
        LOG.debug(str(e))
