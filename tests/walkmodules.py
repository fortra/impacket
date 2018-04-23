#!/usr/bin/env python
# From https://stackoverflow.com/questions/1707709/list-all-the-modules-that-are-part-of-a-python-package
import pkgutil
import impacket
package=impacket
for importer, modname, ispkg in pkgutil.walk_packages(path=package.__path__,
                                                      prefix=package.__name__+'.',
                                                      onerror=lambda x: None):
    try:
        __import__(modname)
    except Exception as e:
        import traceback
        traceback.print_exc()
        print str(e)
        pass
