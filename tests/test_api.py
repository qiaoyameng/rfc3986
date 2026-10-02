import pytest

from rfc3986.api import URIReference
from rfc3986.api import is_valid_uri
from rfc3986.api import normalize_uri
from rfc3986.api import strict_uri_reference
from rfc3986.api import uri_reference
from rfc3986.exceptions import RFC3986Exception


def test_uri_reference():
    assert isinstance(uri_reference("http://example.com"), URIReference)


def test_is_valid_uri():
    assert is_valid_uri("http://example.com") is True


def test_normalize_uri():
    assert normalize_uri("HTTP://EXAMPLE.COM") == "http://example.com"


def test_strict_uri_reference_accepts_valid_input():
    assert isinstance(
        strict_uri_reference("http://example.com/a%20b"), URIReference
    )


def test_strict_uri_reference_raises_with_component_ranges():
    with pytest.raises(RFC3986Exception) as excinfo:
        strict_uri_reference("http://example.com:bad/%")
    errors = excinfo.value.errors
    assert errors[0].component == "port"
    assert all(i.start >= 0 and i.end > i.start for i in errors)
