"""ADAConsole unit/functional testing"""
""" Put reusable fixtures here so that all tests can use them"""

import pytest



""" TABLE TEST FIXTURES"""

@pytest.fixture
def single_module():
    """A list containing exactly one row."""
    return [
        {"id": "1", "name": "One", "description": "A single row"},
    ]


@pytest.fixture
def multiple_modules():
    """A list of several rows"""
    return [
        {"id": "1", "name": "One", "description": "First Row"},
        {"id": "2", "name": "Two", "description": "Second Row"},
        {"id": "3", "name": "Three", "description": "Third Row"},
    ]


@pytest.fixture
def empty_modules():
    """An empty list of modules."""
    return []


@pytest.fixture
def module_missing_key():
    """A row missing the required 'description' key."""
    return [
        {"id": "1", "name": "First Row"},
    ]


@pytest.fixture
def module_with_non_string_values():
    """A row whose values are not strings (e.g. int id)."""
    return [
        {"id": 1, "name": "Row", "description": "Row with integer id"},
    ]
