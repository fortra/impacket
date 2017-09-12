import os
import sys

SOCKS_RELAYS = set()

for file in os.listdir(__path__[0]):
    if file.find('__') >=0 or os.path.splitext(file)[1] == '.pyc':
        continue

    __import__(__package__ + '.' + os.path.splitext(file)[0])
    module = sys.modules[__package__ + '.' + os.path.splitext(file)[0]]
    pluginClass = getattr(module, getattr(module, 'PLUGIN_CLASS'))
    SOCKS_RELAYS.add(pluginClass)
