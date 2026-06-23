# Windows FILETIME <-> POSIX timestamp conversions.
#
# FILETIME is a 64-bit value representing the number of 100-nanosecond
# intervals since January 1, 1601 (UTC).  POSIX time counts seconds since
# January 1, 1970 (UTC).  The difference is exactly 116444736000000000
# 100-ns ticks (= 11644473600 seconds).

_FILETIME_EPOCH_DELTA = 116444736000000000  # 100-ns ticks between 1601 and 1970


def filetime_to_posix(t):
    """Convert a Windows FILETIME value to a POSIX timestamp (seconds).

    Returns 0 for uninitialised or pre-Unix-epoch FILETIME values (e.g. t=0)
    to avoid negative timestamps that crash datetime.fromtimestamp() on
    Windows (see https://github.com/fortra/impacket/issues/1374).

    :param int t: FILETIME timestamp (100-ns ticks since 1601-01-01).
    :return int: POSIX timestamp (seconds since 1970-01-01), or 0.
    """
    if t < _FILETIME_EPOCH_DELTA:
        return 0
    return int((t - _FILETIME_EPOCH_DELTA) // 10_000_000)


def posix_to_filetime(t):
    """Convert a POSIX timestamp (seconds) to a Windows FILETIME value.

    :param int t: POSIX timestamp (seconds since 1970-01-01).
    :return int: FILETIME timestamp (100-ns ticks since 1601-01-01).
    """
    return int(t * 10_000_000 + _FILETIME_EPOCH_DELTA)


