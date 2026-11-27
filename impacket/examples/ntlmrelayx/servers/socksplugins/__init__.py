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
import sys
import importlib
import pkgutil

SOCKS_RELAYS = set()

# Load all available SOCKS relay plugins. We enumerate submodules with
# pkgutil.iter_modules instead of walking the directory on disk so this keeps
# working when impacket is bundled into a frozen executable (e.g. PyInstaller),
# where submodules live inside an archive rather than as .py files on disk.
for _, module_name, _ in pkgutil.iter_modules(__path__, __name__ + '.'):
    if '__' in module_name.rsplit('.', 1)[-1]:
        continue
    importlib.import_module(module_name)
    module = sys.modules[module_name]
    pluginClass = getattr(module, getattr(module, 'PLUGIN_CLASS'))
    SOCKS_RELAYS.add(pluginClass)
