# impacket/examples/ntlmrelayx/utils/identity_log.py
import logging
import threading
from contextlib import contextmanager

# Thread-local storage for current identity
_tlocal = threading.local()

def _get_identity():
    return getattr(_tlocal, "identity", None)

def set_identity(identity):
    setattr(_tlocal, "identity", identity)

@contextmanager
def identity_context(identity):
    prev = _get_identity()
    try:
        set_identity(identity)
        yield
    finally:
        # Restore whatever was there before (safer for nested calls)
        set_identity(prev)

class IdentityFilter(logging.Filter):
    """Injects .identity into every LogRecord so %(identity)s works in formatters."""
    def filter(self, record):
        # Will be "" if not set
        identity = _get_identity()
        record.identity = "%s -> " % identity if identity else ''
        return True
