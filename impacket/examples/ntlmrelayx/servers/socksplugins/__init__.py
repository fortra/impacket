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
import os
import sys
from importlib.resources import files

SOCKS_RELAYS = set()

socksplugins_path = files('impacket.examples.ntlmrelayx.servers').joinpath('socksplugins')
for file in [f.name for f in socksplugins_path.iterdir() if f.is_file()]:
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
    pluginClass = getattr(module, getattr(module, 'PLUGIN_CLASS'))
    SOCKS_RELAYS.add(pluginClass)
