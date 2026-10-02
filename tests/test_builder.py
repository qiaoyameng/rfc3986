# Copyright (c) 2017 Ian Stapleton Cordasco
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Module containing the tests for the URIBuilder object."""

try:
    from urllib.parse import parse_qs
except ImportError:
    from urlparse import parse_qs

from urllib.parse import unquote

import pytest

from rfc3986 import builder
from rfc3986 import uri_reference


def test_builder_default():
    """Verify the default values."""
    uribuilder = builder.URIBuilder()
    assert uribuilder.scheme is None
    assert uribuilder.userinfo is None
    assert uribuilder.host is None
    assert uribuilder.port is None
    assert uribuilder.path is None
    assert uribuilder.query is None
    assert uribuilder.fragment is None


def test_from_uri_reference():
    uri = uri_reference("http://foo.bar:1234/baz")
    uribuilder = builder.URIBuilder().from_uri(uri)
    assert uribuilder.scheme == "http"
    assert uribuilder.userinfo is None
    assert uribuilder.host == "foo.bar"
    assert uribuilder.port == "1234"
    assert uribuilder.path == "/baz"
    assert uribuilder.query is None
    assert uribuilder.fragment is None


def test_from_uri_string():
    uribuilder = builder.URIBuilder().from_uri("https://bar.foo:4321/boom")
    assert uribuilder.scheme == "https"
    assert uribuilder.userinfo is None
    assert uribuilder.host == "bar.foo"
    assert uribuilder.port == "4321"
    assert uribuilder.path == "/boom"
    assert uribuilder.query is None
    assert uribuilder.fragment is None


def test_repr():
    """Verify our repr looks like our class."""
    uribuilder = builder.URIBuilder()
    assert repr(uribuilder).startswith("URIBuilder(scheme=None")


@pytest.mark.parametrize(
    "scheme",
    [
        "https",
        "hTTps",
        "Https",
        "HtTpS",
        "HTTPS",
    ],
)
def test_add_scheme(scheme):
    """Verify schemes are normalized when added."""
    uribuilder = builder.URIBuilder().add_scheme(scheme)
    assert uribuilder.scheme == "https"


@pytest.mark.parametrize(
    "username, password, userinfo",
    [
        ("user", "pass", "user:pass"),
        ("user", None, "user"),
        ("user@domain.com", "password", "user%40domain.com:password"),
        ("user", "pass:word", "user:pass%3Aword"),
    ],
)
def test_add_credentials(username, password, userinfo):
    """Verify we normalize usernames and passwords."""
    uribuilder = builder.URIBuilder().add_credentials(username, password)
    assert uribuilder.userinfo == userinfo


def test_add_credentials_requires_username():
    """Verify one needs a username to add credentials."""
    with pytest.raises(ValueError):
        builder.URIBuilder().add_credentials(None, None)


@pytest.mark.parametrize(
    ["hostname", "expected_hostname"],
    [
        ("google.com", "google.com"),
        ("GOOGLE.COM", "google.com"),
        ("gOOgLe.COM", "google.com"),
        ("goOgLE.com", "google.com"),
        ("[::ff%etH0]", "[::ff%25etH0]"),
        ("[::ff%25etH0]", "[::ff%25etH0]"),
        ("[::FF%etH0]", "[::ff%25etH0]"),
    ],
)
def test_add_host(hostname, expected_hostname):
    """Verify we normalize hostnames in add_host."""
    uribuilder = builder.URIBuilder().add_host(hostname)
    assert uribuilder.host == expected_hostname


@pytest.mark.parametrize(
    "port",
    [
        -100,
        "-100",
        -1,
        "-1",
        65536,
        "65536",
        1000000,
        "1000000",
        "",
        "abc",
        "0b10",
    ],
)
def test_add_invalid_port(port):
    """Verify we raise a ValueError for invalid ports."""
    with pytest.raises(ValueError):
        builder.URIBuilder().add_port(port)


@pytest.mark.parametrize(
    "port, expected",
    [
        (0, "0"),
        ("0", "0"),
        (1, "1"),
        ("1", "1"),
        (22, "22"),
        ("22", "22"),
        (80, "80"),
        ("80", "80"),
        (443, "443"),
        ("443", "443"),
        (65535, "65535"),
        ("65535", "65535"),
    ],
)
def test_add_port(port, expected):
    """Verify we normalize our port."""
    uribuilder = builder.URIBuilder().add_port(port)
    assert uribuilder.port == expected


@pytest.mark.parametrize(
    "path",
    [
        "sigmavirus24/rfc3986",
        "/sigmavirus24/rfc3986",
    ],
)
def test_add_path(path):
    """Verify we normalize our path value."""
    uribuilder = builder.URIBuilder().add_path(path)
    assert uribuilder.path == "/sigmavirus24/rfc3986"


@pytest.mark.parametrize(
    "query_items, expected",
    [
        ({"a": "b c"}, "a=b+c"),
        ({"a": "b+c"}, "a=b%2Bc"),
        ([("a", "b c")], "a=b+c"),
        ([("a", "b+c")], "a=b%2Bc"),
        ([("a", "b"), ("c", "d")], "a=b&c=d"),
        ([("a", "b"), ("username", "@d")], "a=b&username=%40d"),
        ([("percent", "%")], "percent=%25"),
    ],
)
def test_add_query_from(query_items, expected):
    """Verify the behaviour of add_query_from."""
    uribuilder = builder.URIBuilder().add_query_from(query_items)
    assert uribuilder.query == expected


def test_add_query():
    """Verify we do not modify the provided query string."""
    uribuilder = builder.URIBuilder().add_query("username=@foo")
    assert uribuilder.query == "username=@foo"


def test_add_fragment():
    """Verify our handling of fragments."""
    uribuilder = builder.URIBuilder().add_fragment("section-2.5.1")
    assert uribuilder.fragment == "section-2.5.1"


@pytest.mark.parametrize(
    "uri, extend_with, expected_path",
    [
        ("https://api.github.com", "/users", "/users"),
        ("https://api.github.com", "/users/", "/users/"),
        ("https://api.github.com", "users", "/users"),
        ("https://api.github.com", "users/", "/users/"),
        ("", "users/", "/users/"),
        ("", "users", "/users"),
        ("?foo=bar", "users", "/users"),
        (
            "https://api.github.com/users/",
            "sigmavirus24",
            "/users/sigmavirus24",
        ),
        (
            "https://api.github.com/users",
            "sigmavirus24",
            "/users/sigmavirus24",
        ),
        (
            "https://api.github.com/users",
            "/sigmavirus24",
            "/users/sigmavirus24",
        ),
    ],
)
def test_extend_path(uri, extend_with, expected_path):
    """Verify the behaviour of extend_path."""
    uribuilder = (
        builder.URIBuilder()
        .from_uri(uri_reference(uri))
        .extend_path(extend_with)
    )
    assert uribuilder.path == expected_path


@pytest.mark.parametrize(
    "uri, extend_with, expected_query",
    [
        (
            "https://github.com",
            [("a", "b c"), ("d", "e&f")],
            {"a": ["b c"], "d": ["e&f"]},
        ),
        (
            "https://github.com?a=0",
            [("a", "b c"), ("d", "e&f")],
            {"a": ["0", "b c"], "d": ["e&f"]},
        ),
        (
            "https://github.com?a=0&e=f",
            [("a", "b c"), ("d", "e&f")],
            {"a": ["0", "b c"], "e": ["f"], "d": ["e&f"]},
        ),
        (
            "https://github.com",
            {"a": "b c", "d": "e&f"},
            {"a": ["b c"], "d": ["e&f"]},
        ),
        (
            "https://github.com?a=0",
            {"a": "b c", "d": "e&f"},
            {"a": ["0", "b c"], "d": ["e&f"]},
        ),
        (
            "https://github.com?a=0&e=f",
            {"a": "b c", "d": "e&f"},
            {"a": ["0", "b c"], "e": ["f"], "d": ["e&f"]},
        ),
    ],
)
def test_extend_query_with(uri, extend_with, expected_query):
    """Verify the behaviour of extend_query_with."""
    uribuilder = (
        builder.URIBuilder()
        .from_uri(uri_reference(uri))
        .extend_query_with(extend_with)
    )
    assert parse_qs(uribuilder.query) == expected_query


def test_finalize():
    """Verify the whole thing."""
    uri = (
        builder.URIBuilder()
        .add_scheme("https")
        .add_credentials("sigmavirus24", "not-my-re@l-password")
        .add_host("github.com")
        .add_path("sigmavirus24/rfc3986")
        .finalize()
        .unsplit()
    )
    expected = (
        "https://sigmavirus24:not-my-re%40l-password@github.com/"
        "sigmavirus24/rfc3986"
    )
    assert expected == uri


def test_geturl():
    """Verify the short-cut to the URL."""
    uri = (
        builder.URIBuilder()
        .add_scheme("https")
        .add_credentials("sigmavirus24", "not-my-re@l-password")
        .add_host("github.com")
        .add_path("sigmavirus24/rfc3986")
        .geturl()
    )
    expected = (
        "https://sigmavirus24:not-my-re%40l-password@github.com/"
        "sigmavirus24/rfc3986"
    )
    assert expected == uri


@pytest.mark.parametrize(
    "segment, expected_path",
    [
        ("simple", "/objects/simple"),
        ("a/b/c", "/objects/a%2Fb%2Fc"),
        ("a?b#c", "/objects/a%3Fb%23c"),
        ("100%", "/objects/100%25"),
        ("%2F", "/objects/%252F"),
        (".", "/objects/%2E"),
        ("..", "/objects/%2E%2E"),
        ("", "/objects/"),
        ("sp ace&+", "/objects/sp%20ace%26%2B"),
    ],
)
def test_add_path_segment_encodes_raw_data(segment, expected_path):
    """Verify segments are encoded as raw data, one segment each."""
    uribuilder = builder.URIBuilder(path="/objects").add_path_segment(segment)
    assert uribuilder.path == expected_path


@pytest.mark.parametrize(
    "segment",
    [
        "simple",
        "a/b/c",
        "a?b#c",
        "100%",
        "%2F",
        ".",
        "..",
        "sp ace&+",
        "café/donné",
    ],
)
def test_add_path_segment_round_trips(segment):
    """Verify decoding the appended segment restores the original data."""
    uribuilder = builder.URIBuilder(path="/objects").add_path_segment(segment)
    appended = uribuilder.path.rsplit("/", 1)[-1]
    assert unquote(appended) == segment


def test_add_path_segment_appends_a_single_segment():
    """Verify a key containing slashes stays a single segment."""
    uribuilder = builder.URIBuilder(path="/objects").add_path_segment("a/b")
    assert uribuilder.path == "/objects/a%2Fb"
    assert len(uribuilder.path.split("/")) == 3


def test_add_path_segment_to_empty_path():
    """Verify a segment added to an empty path gets a leading slash."""
    uribuilder = builder.URIBuilder().add_path_segment("segment")
    assert uribuilder.path == "/segment"


def test_add_path_segment_to_root_path():
    """Verify a segment added to the root path is not doubled up."""
    uribuilder = builder.URIBuilder(path="/").add_path_segment("segment")
    assert uribuilder.path == "/segment"


def test_add_path_segment_strips_trailing_slash():
    """Verify segments are not separated by duplicate slashes."""
    uribuilder = builder.URIBuilder(path="/objects/").add_path_segment("key")
    assert uribuilder.path == "/objects/key"


def test_add_path_segment_empty_segment_adds_trailing_slash():
    """Verify an empty segment produces a trailing slash."""
    uribuilder = (
        builder.URIBuilder(path="/objects")
        .add_path_segment("key")
        .add_path_segment("")
    )
    assert uribuilder.path == "/objects/key/"


def test_add_path_segment_preserves_other_components():
    """Verify authority, query, and fragment are preserved as-is."""
    uribuilder = (
        builder.URIBuilder()
        .from_uri("https://user@example.com:8443/objects?q=%2f#frag%2F")
        .add_path_segment("a/b")
    )
    assert uribuilder.host == "example.com"
    assert uribuilder.port == "8443"
    assert uribuilder.userinfo == "user"
    assert uribuilder.query == "q=%2f"
    assert uribuilder.fragment == "frag%2F"
    assert uribuilder.path == "/objects/a%2Fb"
    assert (
        uribuilder.geturl()
        == "https://user@example.com:8443/objects/a%2Fb?q=%2f#frag%2F"
    )


def test_add_path_segment_dot_segments_survive_normalization():
    """Verify '.' and '..' are kept as data after normalization."""
    uribuilder = (
        builder.URIBuilder(path="/objects")
        .add_path_segment("..")
        .add_path_segment(".")
    )
    assert uribuilder.path == "/objects/%2E%2E/%2E"
    finalized = uribuilder.finalize().normalize()
    assert finalized.path == "/objects/%2E%2E/%2E"


def test_add_encoded_path_segment_keeps_encoding():
    """Verify pre-encoded segments are kept as-is."""
    uribuilder = builder.URIBuilder(path="/objects").add_encoded_path_segment(
        "a%2Fb%3Fc%23d"
    )
    assert uribuilder.path == "/objects/a%2Fb%3Fc%23d"


def test_add_encoded_path_segment_normalizes_percent_case():
    """Verify valid percent sequences are upper-cased."""
    uribuilder = builder.URIBuilder(path="/objects").add_encoded_path_segment(
        "a%2fb"
    )
    assert uribuilder.path == "/objects/a%2Fb"


def test_add_encoded_path_segment_allows_empty_segment():
    """Verify an empty encoded segment produces a trailing slash."""
    uribuilder = builder.URIBuilder(path="/objects").add_encoded_path_segment(
        ""
    )
    assert uribuilder.path == "/objects/"


@pytest.mark.parametrize(
    "segment",
    [
        "%",
        "%2",
        "%zz",
        "100%",
        "a%2",
        "a%xF",
    ],
)
def test_add_encoded_path_segment_rejects_invalid_percents(segment):
    """Verify malformed percent sequences are rejected."""
    with pytest.raises(ValueError):
        builder.URIBuilder(path="/objects").add_encoded_path_segment(segment)


@pytest.mark.parametrize("delimiter", ["/", "?", "#"])
def test_add_encoded_path_segment_rejects_raw_delimiters(delimiter):
    """Verify raw delimiters are rejected in encoded segments."""
    with pytest.raises(ValueError):
        builder.URIBuilder(path="/objects").add_encoded_path_segment(
            "a{}b".format(delimiter)
        )


@pytest.mark.parametrize("segment", [".", ".."])
def test_add_encoded_path_segment_rejects_dot_segments(segment):
    """Verify raw dot segments are rejected in encoded segments."""
    with pytest.raises(ValueError):
        builder.URIBuilder(path="/objects").add_encoded_path_segment(segment)


def test_add_encoded_path_segment_preserves_other_components():
    """Verify authority, query, and fragment are preserved as-is."""
    uribuilder = (
        builder.URIBuilder()
        .from_uri("https://user@example.com:8443/objects?q=1#frag")
        .add_encoded_path_segment("a%2Fb")
    )
    assert (
        uribuilder.geturl()
        == "https://user@example.com:8443/objects/a%2Fb?q=1#frag"
    )
