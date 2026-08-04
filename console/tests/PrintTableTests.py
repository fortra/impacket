import pytest
from rich.table import Table

from console import PrintTable

def test_single_module_creates_correct_table(single_module):
    table = PrintTable.createTable(single_module)

    assert isinstance(table, Table)
    assert table.row_count == 1
    assert [c.header for c in table.columns] == ["#", "Module Name", "Module Description"]


def test_multiple_modules_creates_correct_table(multiple_modules):
    table = PrintTable.createTable(multiple_modules)

    assert isinstance(table, Table)
    assert table.row_count == len(multiple_modules)


def test_empty_modules_creates_table_with_no_rows(empty_modules):
    table = PrintTable.createTable(empty_modules)

    assert isinstance(table, Table)
    assert table.row_count == 0


def test_none_modules_returns_none():
    assert PrintTable.createTable(None) is None


def test_module_missing_key_raises_key_error(module_missing_key):
    with pytest.raises(KeyError):
        PrintTable.createTable(module_missing_key)


def test_module_with_non_string_values_raises_error(module_with_non_string_values):
    with pytest.raises(Exception):
        PrintTable.createTable(module_with_non_string_values)