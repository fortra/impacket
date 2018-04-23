import os
import sys
import pkg_resources

SOCKS_RELAYS = set()

for file in pkg_resources.resource_listdir('impacket.examples.ntlmrelayx.servers', 'socksplugins'):
    if file.find('__') >=0 or os.path.splitext(file)[1] == '.pyc':
        continue

    __import__(__package__ + '.' + os.path.splitext(file)[0])
    module = sys.modules[__package__ + '.' + os.path.splitext(file)[0]]
    pluginClass = getattr(module, getattr(module, 'PLUGIN_CLASS'))
    SOCKS_RELAYS.add(pluginClass)
