import pytest

from verify.versions import compare, direction, normalize_name


@pytest.mark.parametrize("a,b,expected", [
    ("1.2.3", "1.2.4", -1),
    ("1.2.4", "1.2.3", 1),
    ("1.2.3", "1.2.3", 0),
    ("1.2.3-beta.1", "1.2.3", -1),
    ("1.2.3", "1.2.3-rc.1", 1),
    ("1.2.3-beta.2", "1.2.3-beta.10", -1),
    ("v2.0.0", "1.99.99", 1),
])
def test_npm_compare(a, b, expected):
    assert compare("npm", a, b) == expected


@pytest.mark.parametrize("a,b,expected", [
    ("2.30.0", "2.31.0", -1),
    ("2.31.0", "2.31.0.post1", -1),
    ("1.0.0rc1", "1.0.0", -1),
    ("1.0", "1.0.0", 0),
])
def test_pypi_compare(a, b, expected):
    assert compare("PyPI", a, b) == expected


def test_direction():
    assert direction("npm", "1.2.3", "1.2.4") == "upgrade"
    assert direction("npm", "1.2.4", "1.2.3") == "downgrade"
    assert direction("npm", None, "1.2.3") == "unknown"


def test_invalid_raises():
    with pytest.raises(ValueError):
        compare("npm", "latest", "1.0.0")


def test_normalize():
    assert normalize_name("PyPI", "Foo_Bar.baz") == "foo-bar-baz"
    assert normalize_name("npm", "@scope/Name") == "@scope/Name"
