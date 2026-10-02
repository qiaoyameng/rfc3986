import dataclasses

import pytest

import rfc3986
from rfc3986.normalization import NormalizationProfile
from rfc3986.normalization import NormalizationTransformation


def test_default_normalize_remains_unchanged():
    uri = rfc3986.uri_reference(
        "HTTP://EXAMPLE.COM:80/a%7eb/./c?b=2&a=1&a=0&q=x+y%2fz#f%61"
    )

    assert uri.normalize().unsplit() == (
        "http://example.com:80/a%7Eb/c?b=2&a=1&a=0&q=x+y%2Fz#f%61"
    )


def test_default_profile_performs_no_normalization():
    uri = rfc3986.uri_reference(
        "HTTP://EXAMPLE.COM:80/a%7eb/./c?b=2&a=1&a=0&q=x+y%2f"
    )

    result = uri.normalize_with(NormalizationProfile())

    assert result.reference == uri
    assert result.uri == uri.unsplit()
    assert result.transformations == ()


def test_profile_normalizes_selected_components_only():
    uri = rfc3986.uri_reference(
        "HTTP://EXAMPLE.COM/path%2fseg%61/./end?b=2&a=1%2f&a=0#frag%6d"
    )

    result = NormalizationProfile(authority=True).apply(uri)

    assert result.reference.scheme == "HTTP"
    assert result.reference.authority == "example.com"
    assert result.reference.path == "/path%2fseg%61/./end"
    assert result.reference.query == "b=2&a=1%2f&a=0"
    assert result.reference.fragment == "frag%6d"
    assert result.transformations
    assert all(
        transformation.component in {"host", "authority"}
        for transformation in result.transformations
    )


def test_percent_case_profile_preserves_query_order_and_plus():
    uri = rfc3986.uri_reference(
        "http://example.com/path?z=1&a=%2f&a=%7e&b=2+3"
    )

    result = NormalizationProfile(percent_case=True).apply(uri)

    assert result.reference.query == "z=1&a=%2F&a=%7E&b=2+3"
    assert NormalizationTransformation(
        rule="percent_case",
        component="query",
        before="z=1&a=%2f&a=%7e&b=2+3",
        after="z=1&a=%2F&a=%7E&b=2+3",
    ) in result.transformations


def test_decode_unreserved_profile_leaves_reserved_escapes_encoded():
    uri = rfc3986.uri_reference(
        "http://example.com/a%7eb%2fc?x=%7e%2f%26%3D&y=1"
    )

    result = NormalizationProfile(decode_unreserved=True).apply(uri)

    assert result.reference.path == "/a~b%2fc"
    assert result.reference.query == "x=~%2f%26%3D&y=1"


def test_reserved_representations_are_not_unified():
    slash = rfc3986.uri_reference("http://example.com/a/b")
    encoded_slash = rfc3986.uri_reference("http://example.com/a%2Fb")
    profile = NormalizationProfile(percent_case=True, decode_unreserved=True)

    slash_result = profile.apply(slash)
    encoded_slash_result = profile.apply(encoded_slash)

    assert slash_result.uri == "http://example.com/a/b"
    assert encoded_slash_result.uri == "http://example.com/a%2Fb"
    assert slash_result.uri != encoded_slash_result.uri
    encoded_slash_again = profile.apply(encoded_slash_result.reference)
    assert encoded_slash_again.reference == encoded_slash_result.reference
    assert encoded_slash_again.transformations == ()


def test_encoded_unreserved_host_is_decoded_before_case_normalization():
    encoded_host = rfc3986.uri_reference("http://%41EXAMPLE.COM/")
    literal_host = rfc3986.uri_reference("http://aexample.com/")
    profile = NormalizationProfile(
        authority=True, decode_unreserved=True
    )

    encoded_result = profile.apply(encoded_host)
    literal_result = profile.apply(literal_host)

    assert encoded_result.uri == "http://aexample.com/"
    assert literal_result.uri == "http://aexample.com/"
    assert encoded_result.uri == literal_result.uri


def test_duplicate_query_keys_remain_distinct_and_ordered():
    uri = rfc3986.uri_reference("http://example.com?a=2&a=1&a=2&A=0")

    profile = NormalizationProfile(scheme=True, authority=True)
    result = profile.apply(uri)

    assert result.reference.query == "a=2&a=1&a=2&A=0"
    assert result.uri == "http://example.com?a=2&a=1&a=2&A=0"
    again = profile.apply(result.reference)
    assert again.reference == result.reference
    assert again.transformations == ()


def test_default_ports_are_not_removed():
    with_port = rfc3986.uri_reference("http://example.com:80/")
    without_port = rfc3986.uri_reference("http://example.com/")
    profile = NormalizationProfile(scheme=True, authority=True)

    with_result = profile.apply(with_port)
    without_result = profile.apply(without_port)

    assert with_result.uri == "http://example.com:80/"
    assert without_result.uri == "http://example.com/"
    assert with_result.uri != without_result.uri
    with_again = profile.apply(with_result.reference)
    without_again = profile.apply(without_result.reference)
    assert with_again.reference == with_result.reference
    assert without_again.reference == without_result.reference
    assert with_again.transformations == ()
    assert without_again.transformations == ()


def test_profile_is_reusable_and_stateless():
    profile = NormalizationProfile(scheme=True, authority=True)
    first_uri = rfc3986.uri_reference("HTTP://FIRST.Example")
    second_uri = rfc3986.uri_reference("HTTPS://SECOND.Example")

    first_result = profile.apply(first_uri)
    second_result = profile.apply(second_uri)

    assert first_result.uri == "http://first.example"
    assert second_result.uri == "https://second.example"


def test_second_application_is_idempotent():
    uri = rfc3986.uri_reference(
        "HTTP://USER%2fNAME@EXAMPLE.COM/a/./b%2f%7e?a=1&A=2#F%6f"
    )
    profile = NormalizationProfile(
        scheme=True,
        authority=True,
        remove_dot_segments=True,
        percent_case=True,
    )

    first = profile.apply(uri)
    second = profile.apply(first.reference)

    assert second.reference == first.reference
    assert second.uri == first.uri
    assert second.transformations == ()


def test_conflicting_profile_is_rejected_when_created():
    with pytest.raises(ValueError, match="cannot be combined"):
        NormalizationProfile(
            remove_dot_segments=True, decode_unreserved=True
        )


def test_result_and_profile_are_immutable():
    profile = NormalizationProfile(scheme=True)
    result = profile.apply(rfc3986.uri_reference("HTTP://example.com"))

    with pytest.raises(dataclasses.FrozenInstanceError):
        profile.scheme = False  # type: ignore[misc]
    with pytest.raises(dataclasses.FrozenInstanceError):
        result.reference = result.reference  # type: ignore[misc]
    with pytest.raises(dataclasses.FrozenInstanceError):
        result.transformations = ()  # type: ignore[misc]
