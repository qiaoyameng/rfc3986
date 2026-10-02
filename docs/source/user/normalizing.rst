=======================
 Normalization Profiles
=======================

:meth:`rfc3986.uri.URIReference.normalize` keeps its historical behavior.
When another backend needs a smaller or different set of transformations,
create an explicit :class:`rfc3986.NormalizationProfile`.

Every rule is opt-in:

- ``scheme`` lower-cases the scheme.
- ``authority`` lower-cases the host and applies RFC 6874 handling to IPv6
  zone identifiers.
- ``remove_dot_segments`` removes ``.`` and ``..`` path segments.
- ``percent_case`` upper-cases hexadecimal digits in percent escapes.
- ``decode_unreserved`` decodes percent escapes for unreserved characters.

Profiles are immutable and reusable. They do not retain the previous URI or
any intermediate state.

.. code-block:: python

    from rfc3986 import NormalizationProfile, uri_reference

    signature_profile = NormalizationProfile(scheme=True, authority=True)

    uri = uri_reference(
        "HTTPS://EXAMPLE.COM/Path/./next?b=2&a=1&a=0&A=3&q=x+y"
    )
    result = signature_profile.apply(uri)

    print(result.uri)
    # https://example.com/Path/./next?b=2&a=1&a=0&A=3&q=x+y

    for change in result.transformations:
        print(change.rule, change.component, change.before, change.after)
    # scheme scheme HTTPS https
    # authority host EXAMPLE.COM example.com
    # authority authority EXAMPLE.COM example.com

The query is never sorted, repeated query keys keep their order and
repetition, and ``+`` is never decoded to a space.

Reserved Characters
===================

Unreserved escapes can be decoded, but reserved escapes remain distinct from
the literal character.

.. code-block:: python

    profile = NormalizationProfile(
        percent_case=True, decode_unreserved=True
    )

    profile.apply(uri_reference("http://example.com/a%7eb")).uri
    # 'http://example.com/a~b'

    profile.apply(uri_reference("http://example.com/a%2Fb")).uri
    # 'http://example.com/a%2Fb'

Thus ``http://example.com/a~b`` and ``http://example.com/a%7Eb`` become the
same representation, but ``http://example.com/a/b`` and
``http://example.com/a%2Fb`` remain different. The second application returns
the same URI and an empty transformation record.

Repeated Query Keys and Default Ports
=====================================

.. code-block:: python

    profile = NormalizationProfile(scheme=True, authority=True)

    profile.apply(
        uri_reference("HTTP://EXAMPLE.COM?a=2&a=1&a=2&A=0")
    ).uri
    # 'http://example.com?a=2&a=1&a=2&A=0'

    profile.apply(uri_reference("http://example.com:80/")).uri
    # 'http://example.com:80/'

Consequently, ``?a=2&a=1&a=2`` is not reordered or deduplicated, uppercase
``A`` is not folded into lowercase ``a``, and ``http://example.com:80/`` is
not equated with ``http://example.com/``.

Idempotence
===========

Applying a valid profile a second time cannot make another change:

.. code-block:: python

    once = profile.apply(uri)
    twice = profile.apply(once.reference)

    assert twice.reference == once.reference
    assert twice.transformations == ()

If rules can give different results depending on their order, the profile is
rejected when it is created. For example, decoding unreserved characters and
then removing dot segments would decode ``%2E`` into a removable dot segment,
so ``NormalizationProfile(remove_dot_segments=True,
decode_unreserved=True)`` raises ``ValueError``.
