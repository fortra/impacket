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
import os, sys
from importlib.resources import files
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

attacks_path = files('impacket.examples.ntlmrelayx').joinpath('attacks')
for file in [f.name for f in attacks_path.iterdir() if f.is_file()]:
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
