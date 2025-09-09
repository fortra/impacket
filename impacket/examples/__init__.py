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

import ssl
def _insecure_create_default_context(purpose=ssl.Purpose.SERVER_AUTH, *, cafile=None, capath=None, cadata=None):
    context = ssl._create_default_context(purpose=purpose, cafile=cafile, capath=capath, cadata=cadata)
    context.minimum_version = ssl.TLSVersion.MINIMUM_SUPPORTED
    context.set_ciphers("ALL:@SECLEVEL=0")
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context

def monkeypatch_ssl_create_default_context():
    if ssl.create_default_context != _insecure_create_default_context:
        ssl._create_default_context = ssl.create_default_context
        ssl.create_default_context = _insecure_create_default_context

        from impacket import LOG
        LOG.debug('Monkeypatch [ssl.create_default_context] to allow connections to insecurely configured servers')
        LOG.debug('  minimum_version = ssl.TLSVersion.MINIMUM_SUPPORTED')
        LOG.debug('  set_ciphers("ALL:@SECLEVEL=0")')
        LOG.debug('  verify_mode = ssl.CERT_NONE')

# -----

import readline
def monkeypatch_readline_backend():
    if not hasattr(readline, 'backend'):
        readline.backend = "readline"

        from impacket import LOG
        LOG.debug('Monkeypatch [readline.backend] defining property and setting it to "readline"')
        LOG.debug('  readline.backend = "readline"')

# -----

monkeypatch_ssl_create_default_context()
monkeypatch_readline_backend()