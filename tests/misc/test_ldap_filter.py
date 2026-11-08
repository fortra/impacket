import pytest

from impacket.ldap.ldap import LDAPConnection


def parse_value(filter_str: str) -> bytes:
    connection = LDAPConnection.__new__(LDAPConnection)
    search_filter = connection._parseFilter(filter_str)
    return bytes(search_filter["equalityMatch"]["assertionValue"])


def test_binary_escapes():
    """RFC 4515 escapes are octets, not Unicode code points."""
    assert parse_value(r"(objectGUID=\a1\00\ff)") == b"\xa1\x00\xff"


def test_escaped_utf8():
    """Escaped UTF-8 bytes must reach the wire unchanged."""
    assert parse_value(r"(cn=Jos\c3\a9)") == b"Jos\xc3\xa9"


def test_unescaped_utf8():
    """Unescaped non-ASCII text is still encoded as UTF-8."""
    assert parse_value("(cn=José)") == b"Jos\xc3\xa9"


@pytest.mark.parametrize(
    "filter_str,expected",
    [
        (r"(cn=\28paren\29)", b"(paren)"),
        (r"(cn=a\2ab)", b"a*b"),
        (r"(cn=a\5cb)", b"a\\b"),
    ],
)
def test_reserved_characters(filter_str, expected):
    assert parse_value(filter_str) == expected


def test_substring_escapes():
    connection = LDAPConnection.__new__(LDAPConnection)
    search_filter = connection._parseFilter(r"(cn=Jos\c3\a9*admin)")
    substrings = search_filter["substrings"]["substrings"]
    assert [
        (component.getName(), bytes(component.getComponent()))
        for component in substrings
    ] == [("initial", b"Jos\xc3\xa9"), ("final", b"admin")]


def test_extensible_match_escapes():
    connection = LDAPConnection.__new__(LDAPConnection)
    search_filter = connection._parseFilter(r"(cn:caseExactMatch:=Jos\c3\a9)")
    assert bytes(search_filter["extensibleMatch"]["matchValue"]) == b"Jos\xc3\xa9"
