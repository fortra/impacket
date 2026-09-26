# Windows FILETIME <-> POSIX timestamp conversions.

from datetime import datetime, timedelta

# The FILETIME epoch starts on January 1, 1601 (UTC); POSIX on January 1, 1970 (UTC).
# 10_000_000 = 100-nanosecond ticks per second; 11_644_473_600 = seconds between the two epochs.
_FILETIME_EPOCH_DELTA = 10_000_000 * 11_644_473_600
_FILETIME_EPOCH = datetime(1601, 1, 1)


def filetime_to_datetime(t):
    """Convert a Windows FILETIME value to a naive UTC datetime.

    Returns datetime(1601, 1, 1) for t=0 (uninitialised/never-set fields).

    :param int t: FILETIME timestamp (100-nanosecond ticks since 1601-01-01 UTC).
    :return datetime: naive UTC datetime.
    """
    return _FILETIME_EPOCH + timedelta(microseconds=t // 10)


def filetime_to_posix(t):
    """
    Converts a Windows FILETIME value to a POSIX timestamp.

    Returns 0 for uninitialised or pre-Unix-epoch FILETIME values to avoid
    negative timestamps that crash datetime.fromtimestamp() on Windows.

    :param int t: FILETIME timestamp (100-nanosecond ticks since 1601-01-01).

    :return int: POSIX timestamp (seconds since 1970-01-01), or 0.
    """
    if t < _FILETIME_EPOCH_DELTA:
        return 0
    return int((t - _FILETIME_EPOCH_DELTA) // 10_000_000)


def posix_to_filetime(t):
    """
    Converts a POSIX timestamp to a Windows FILETIME value.

    :param int t: POSIX timestamp (seconds since 1970-01-01).

    :return int: FILETIME timestamp (100-nanosecond ticks since 1601-01-01).
    """
    return int(t * 10_000_000 + _FILETIME_EPOCH_DELTA)


