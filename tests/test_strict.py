"""Tests for the strict URI reference parsing entry point."""

import pytest

import rfc3986
from rfc3986 import strict
from rfc3986.strict import ParseIssue


def _find(issues, component, reason):
    matches = [
        issue
        for issue in issues
        if issue.component == component and issue.reason == reason
    ]
    assert matches, f"no {reason} in {component!r}: {issues!r}"
    return matches[0]


def test_strict_accepts_valid_reference():
    ref = strict.strict_uri_reference("http://example.com/path?q=1#f")
    assert isinstance(ref, rfc3986.URIReference)
    assert strict.parse_uri_reference("http://example.com/") == []


def test_locates_chinese_bad_port_and_stray_percent():
    uri = "http://example.com:99bad/%\u4e2d#%"
    issues = strict.parse_uri_reference(uri)

    port = _find(issues, "port", strict.INVALID_PORT)
    assert uri[port.start:port.end] == "99bad"
    assert port.unit == "character"

    percent = [
        issue
        for issue in issues
        if issue.reason == strict.INVALID_PERCENT_ENCODING
    ]
    assert {uri[i.start:i.end] for i in percent} == {"%\u4e2d", "%"}
    assert all(i.unit == "character" for i in percent)

    chinese = _find(issues, "path", strict.NON_ASCII_CHARACTER)
    assert uri[chinese.start:chinese.end] == "\u4e2d"

    with pytest.raises(strict.StrictParseError) as exc_info:
        strict.strict_uri_reference(uri)
    assert exc_info.value.errors == issues


def test_valid_percent_encoded_reserved_chars_are_not_flagged():
    uri = "http://user%3Aname@example.com/a%2Fb?c=%3A%26d#f%23g"
    assert strict.parse_uri_reference(uri) == []
    # Lower-cased hex digits are legal too.
    assert strict.parse_uri_reference("http://example.com/a%2fb") == []


def test_control_characters_are_reported():
    uri = "http://example.com/a\tb\x01c"
    issues = strict.parse_uri_reference(uri)
    assert len(issues) == 2
    assert all(i.reason == strict.CONTROL_CHARACTER for i in issues)
    assert {uri[i.start:i.end] for i in issues} == {"\t", "\x01"}


def test_illegal_ascii_character_is_reported():
    uri = "/a^b c"
    issues = strict.parse_uri_reference(uri)
    assert {i.reason for i in issues} == {strict.INVALID_CHARACTER}
    assert {uri[i.start:i.end] for i in issues} == {"^", " "}


def test_empty_port_is_reported():
    uri = "http://example.com:/"
    issue = _find(strict.parse_uri_reference(uri), "port", strict.INVALID_PORT)
    assert uri[issue.start:issue.end] == ":"


def test_invalid_authority_is_reported():
    issues = strict.parse_uri_reference("http://[::1:broken/")
    issue = _find(issues, "host", strict.INVALID_HOST)
    assert issue.start == 7
    assert issue.value == "[::1:broken"

    assert (
        strict.parse_uri_reference("http://[2001:db8::1]:8080/") == []
    )
    assert strict.parse_uri_reference("http://[fe80::1%25eth0]/") == []
    assert (
        _find(
            strict.parse_uri_reference("http://999.1.1.1/"),
            "host",
            strict.INVALID_HOST,
        ).value
        == "999.1.1.1"
    )


def test_bytes_decoding_error_uses_byte_units():
    issues = strict.parse_uri_reference(
        b"http://example.com/a\xff/b", encoding="utf-8"
    )
    assert len(issues) == 1
    issue = issues[0]
    assert issue.reason == strict.ENCODING_ERROR
    assert issue.component == "uri"
    assert issue.unit == "byte"
    assert (issue.start, issue.end) == (20, 21)

    valid = strict.parse_uri_reference(
        b"http://example.com/a%E4%B8%AD", encoding="utf-8"
    )
    assert valid == []


def test_empty_component_is_distinct_from_missing():
    with_empty_query = strict.parse_uri_reference("http://example.com?")
    with_missing_query = strict.parse_uri_reference("http://example.com")
    assert with_empty_query == with_missing_query == []

    parsed = rfc3986.uri_reference("http://example.com?")
    assert parsed.query == ""
    assert rfc3986.uri_reference("http://example.com").query is None

    with_empty_fragment = rfc3986.uri_reference("http://example.com#")
    assert with_empty_fragment.fragment == ""


def test_positions_refer_to_original_input_after_normalization():
    uri = "HTTP://EXAMPLE.COM/%zz"
    issues = strict.parse_uri_reference(uri)
    issue = _find(issues, "path", strict.INVALID_PERCENT_ENCODING)
    # Even though normalization lower-cases the host, the range points at the
    # bytes of the original input.
    assert uri[issue.start:issue.end] == "%zz"


def test_errors_are_collected_in_stable_order():
    uri = "http://%ZZ:aa@host:%/a%ZZ?q%ZZ#f%ZZ"
    issues = strict.parse_uri_reference(uri)
    assert [i.start for i in issues] == sorted(
        i.start for i in issues
    )
    # Running the parser repeatedly yields identical results.
    assert strict.parse_uri_reference(uri) == issues
    components = [i.component for i in issues]
    assert components == [
        "userinfo",
        "port",
        "path",
        "query",
        "fragment",
    ]


def test_lenient_uri_reference_still_auto_encodes():
    # The legacy interface is unchanged: no global switch disables this.
    ref = rfc3986.uri_reference("http://example.com/a b")
    assert ref.path == "/a%20b"
    ref = rfc3986.uri_reference("http://example.com/%")
    assert ref.path == "/%25"


def test_parse_issue_records_original_slice():
    issue = ParseIssue(
        component="path",
        reason=strict.INVALID_PERCENT_ENCODING,
        start=0,
        end=2,
        value="%z",
    )
    assert str(issue) == (
        "invalid-percent-encoding in path[0:2] (characters): '%z'"
    )
    # An issue without a raw value renders without the value suffix.
    valueless = ParseIssue(
        component="path",
        reason=strict.INVALID_CHARACTER,
        start=0,
        end=1,
    )
    assert str(valueless) == (
        "invalid-character in path[0:1] (characters)"
    )


def test_malformed_percent_escape_rescans_continuation():
    # A bad second hex digit is one invalid escape, and scanning resumes so
    # the following non-ASCII character is still located independently.
    uri = "http://example.com/%z\u4e2d"
    reasons = {
        (i.component, i.reason, i.value)
        for i in strict.parse_uri_reference(uri)
    }
    assert ("path", strict.INVALID_PERCENT_ENCODING, "%z\u4e2d") in reasons
    assert ("path", strict.NON_ASCII_CHARACTER, "\u4e2d") in reasons

    # A trailing two-character escape is a single issue spanning both.
    trailing = strict.parse_uri_reference("http://example.com/%G")
    assert [(i.reason, i.value) for i in trailing] == [
        (strict.INVALID_PERCENT_ENCODING, "%G")
    ]


def test_port_with_ascii_nondigit_characters():
    issue = _find(
        strict.parse_uri_reference("http://example.com:80a/"),
        "port",
        strict.INVALID_PORT,
    )
    assert issue.value == "80a"


def test_ip_literal_with_trailing_non_port_data():
    issue = _find(
        strict.parse_uri_reference("http://[::1]extra/"),
        "host",
        strict.INVALID_HOST,
    )
    assert issue.value == "[::1]"


def test_ip_literal_that_is_grammatically_invalid():
    # A closed IP-literal that contains no individually-illegal character
    # but still fails the literal grammar is reported as a host error.
    issue = _find(
        strict.parse_uri_reference("http://[vX]/"),
        "host",
        strict.INVALID_HOST,
    )
    assert issue.value == "[vX]"
    assert strict.parse_uri_reference("http://[999.1.1.1:80]/")


def test_api_entry_points_are_available():
    assert rfc3986.strict_uri_reference is rfc3986.api.strict_uri_reference
    with pytest.raises(rfc3986.StrictParseError):
        rfc3986.strict_uri_reference("http://example.com/%")


def test_uri_reference_from_strict_string():
    ref = rfc3986.URIReference.from_strict_string(
        "http://example.com/a%2Fb"
    )
    assert ref.path == "/a%2Fb"
    with pytest.raises(rfc3986.StrictParseError):
        rfc3986.URIReference.from_strict_string("http://example.com/%")
