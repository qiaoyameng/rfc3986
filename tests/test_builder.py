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


# ---------------------------------------------------------------------------
# Segment-based path building
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "segment, expected",
    [
        ("sigmavirus24", "/sigmavirus24"),
        ("photos/2017", "/photos%2F2017"),
        ("a?b", "/a%3Fb"),
        ("a#b", "/a%23b"),
        ("a/b?c#d", "/a%2Fb%3Fc%23d"),
        ("100%", "/100%25"),
        ("a=b+c", "/a=b+c"),
        ("café", "/caf%C3%A9"),
        (".", "/."),
        ("..", "/.."),
        ("", "/"),
    ],
)
def test_add_path_segment_encodes_raw_data(segment, expected):
    """add_path_segment treats its argument as opaque data."""
    uribuilder = builder.URIBuilder().add_path_segment(segment)
    assert uribuilder.path == expected


def test_add_path_segment_appends_to_existing_path():
    """Segments are joined with a single slash."""
    uribuilder = builder.URIBuilder(path="/buckets").add_path_segment(
        "photos/2017"
    )
    assert uribuilder.path == "/buckets/photos%2F2017"


def test_add_path_segment_object_key_round_trip():
    """Object keys with slashes and a literal percent survive a round trip."""
    from urllib.parse import unquote

    segments = ["my/bucket", "photos/2017", "100%.jpg", "a?b#c"]
    uribuilder = (
        builder.URIBuilder()
        .add_scheme("https")
        .add_host("storage.example.com")
        .add_path_segments(segments)
    )
    path = uribuilder.finalize().path
    decoded = [unquote(part) for part in path.lstrip("/").split("/")]
    assert decoded == segments


def test_add_path_segments_variadic():
    """Segments may be passed as positional arguments too."""
    uribuilder = builder.URIBuilder(path="/b").add_path_segments("a/b", "c")
    assert uribuilder.path == "/b/a%2Fb/c"


def test_add_path_segment_empty_and_trailing_slash():
    """Empty segments add slashes without collapsing existing ones."""
    uribuilder = builder.URIBuilder(path="/a").add_path_segment("")
    assert uribuilder.path == "/a/"

    uribuilder = (
        builder.URIBuilder(path="/a").add_path_segment("").add_path_segment("")
    )
    assert uribuilder.path == "/a//"


def test_add_path_segment_keeps_dot_segments():
    """'.' and '..' are data; they are not resolved or removed."""
    uribuilder = builder.URIBuilder(path="/a").add_path_segments(
        ["..", ".", "x"]
    )
    assert uribuilder.path == "/a/.././x"


def test_add_path_segment_preserves_query_fragment_and_authority():
    """The base URI's authority, query and fragment stay untouched."""
    uribuilder = builder.URIBuilder.from_uri(
        "https://user:pw@host.example:8080/base?q=1#frag"
    ).add_path_segment("a/b")
    assert uribuilder.userinfo == "user:pw"
    assert uribuilder.host == "host.example"
    assert uribuilder.port == "8080"
    assert uribuilder.query == "q=1"
    assert uribuilder.fragment == "frag"
    assert uribuilder.path == "/base/a%2Fb"
    assert uribuilder.geturl() == (
        "https://user:pw@host.example:8080/base/a%2Fb?q=1#frag"
    )


def test_add_path_segment_does_not_normalize_path():
    """Segment building is not relative-reference resolution."""
    uribuilder = builder.URIBuilder(path="/a").add_path_segment("../b")
    assert uribuilder.path == "/a/..%2Fb"


@pytest.mark.parametrize(
    "segment",
    [
        "photos%2F2017",
        "100%25.jpg",
        "a%2fb%C3%A9",
        "plain",
        "",
    ],
)
def test_add_encoded_path_segment_is_not_encoded_again(segment):
    """Already encoded text is appended verbatim."""
    uribuilder = builder.URIBuilder(path="/b").add_encoded_path_segment(
        segment
    )
    assert uribuilder.path == "/b/" + segment


@pytest.mark.parametrize(
    "segment",
    ["%", "%2", "%zz", "%2g", "100%.jpg", "a%2F%"],
)
def test_add_encoded_path_segment_validates_percent_sequences(segment):
    """Bare '%' or malformed triplets raise a ValueError."""
    with pytest.raises(ValueError):
        builder.URIBuilder(path="/b").add_encoded_path_segment(segment)


def test_add_encoded_path_segments_iterable_and_varargs():
    """The plural form accepts an iterable or positional arguments."""
    uribuilder = builder.URIBuilder(path="/b").add_encoded_path_segments(
        ["a%2Fb", "c"]
    )
    assert uribuilder.path == "/b/a%2Fb/c"

    uribuilder = builder.URIBuilder(path="/b").add_encoded_path_segments(
        "a%2Fb", "c"
    )
    assert uribuilder.path == "/b/a%2Fb/c"


def test_add_encoded_path_segments_reject_mixing_forms():
    """An iterable and positional arguments cannot be combined."""
    with pytest.raises(TypeError):
        builder.URIBuilder(path="/b").add_path_segments(["a"], "b")
    with pytest.raises(TypeError):
        builder.URIBuilder(path="/b").add_encoded_path_segments(["a"], "b")


def test_segment_builders_are_immutable():
    """Adding a segment returns a new builder, leaving the original intact."""
    original = builder.URIBuilder(path="/a")
    extended = original.add_path_segment("b")
    assert original.path == "/a"
    assert extended.path == "/a/b"
