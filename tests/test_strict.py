import pytest

import rfc3986
from rfc3986 import exceptions


def strict_errors(uri, encoding="utf-8"):
    with pytest.raises(exceptions.InvalidURIError) as exc_info:
        rfc3986.strict_uri_reference(uri, encoding=encoding)
    return exc_info.value.errors


def test_strict_uri_locates_chinese_bad_port_and_lone_percent():
    uri = "http://example.com:bad/path?x=你好#tail%"

    errors = strict_errors(uri)

    assert errors == (
        exceptions.URIErrorDetail(
            "port", "invalid port", 19, 22, "characters", "bad"
        ),
        exceptions.URIErrorDetail(
            "query", "invalid character", 30, 32, "characters", "你好"
        ),
        exceptions.URIErrorDetail(
            "fragment", "invalid percent escape", 37, 38, "characters", "%"
        ),
    )


def test_strict_bytes_errors_are_reported_in_byte_units():
    uri = (
        b"http://example.com:bad/path?x="
        + "你好".encode("utf-8")
        + b"#tail%"
    )

    errors = strict_errors(uri)

    assert errors == (
        exceptions.URIErrorDetail(
            "port", "invalid port", 19, 22, "bytes", "bad"
        ),
        exceptions.URIErrorDetail(
            "query", "invalid character", 30, 36, "bytes", "你好"
        ),
        exceptions.URIErrorDetail(
            "fragment", "invalid percent escape", 41, 42, "bytes", "%"
        ),
    )


def test_invalid_byte_sequence_has_byte_span():
    errors = strict_errors(b"http://example.com/path?x=\xff")

    assert errors == (
        exceptions.URIErrorDetail(
            "query",
            "encoding error",
            26,
            27,
            "bytes",
            "\ufffd",
        ),
    )


@pytest.mark.parametrize(
    "uri",
    [
        "http://example.com/a%2Fb?c=%E4%BD%A0%26d#f%3A",
        "http://example.com/path?reserved=%2F%3F%23%5B%5D",
        "http://[::1%25eth0]/path",
    ],
)
def test_valid_percent_encoded_reserved_characters_are_accepted(uri):
    reference = rfc3986.strict_uri_reference(uri)

    assert reference.unsplit() == uri


def test_control_characters_are_reported_before_encoding():
    errors = strict_errors("http://example.com/a\x00b%20")

    assert errors == (
        exceptions.URIErrorDetail(
            "path",
            "control character",
            20,
            21,
            "characters",
            "\x00",
        ),
    )


def test_empty_and_missing_components_remain_distinguishable():
    uri = rfc3986.strict_uri_reference("http://example.com/path?#")

    assert uri.path == "/path"
    assert uri.query == ""
    assert uri.fragment == ""


def test_lenient_uri_reference_still_auto_encodes_original_text():
    uri = rfc3986.uri_reference("http://example.com/path?x=你好%2F")

    assert uri.query == "x=%E4%BD%A0%E5%A5%BD%2F"


def test_strict_keyword_matches_dedicated_entry_point():
    uri = rfc3986.uri_reference(
        "http://example.com/path%2F?x=1", strict=True
    )

    assert uri.path == "/path%2F"


def test_authority_collects_independent_errors():
    errors = strict_errors("http://bad user@999.0.0.1:99999/path")

    assert [error.component for error in errors] == [
        "userinfo",
        "host",
        "port",
    ]


def test_relative_path_colon_error_points_to_colon():
    errors = strict_errors("1relative:path")

    assert errors == (
        exceptions.URIErrorDetail(
            "path", "invalid path", 9, 10, "characters", ":"
        ),
    )


def test_adjacent_bad_percent_escapes_do_not_overlap():
    errors = strict_errors("http://example.com/a%2%2G")

    assert [(error.start, error.end) for error in errors] == [
        (20, 21),
        (22, 24),
    ]
