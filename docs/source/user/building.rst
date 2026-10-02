===============
 Building URIs
===============

Constructing URLs often seems simple. There are some problems with
concatenating strings to build a URL:

- Certain parts of the URL disallow certain characters

- Formatting some parts of the URL is tricky and doing it manually isn't fun

To make the experience better |rfc3986| provides the
:class:`~rfc3986.builder.URIBuilder` class to generate valid
:class:`~rfc3986.uri.URIReference` instances. The
:class:`~rfc3986.builder.URIBuilder` class will handle ensuring that each
component is normalized and safe for real world use.


Example Usage
=============

.. note::

    All of the methods on a :class:`~rfc3986.builder.URIBuilder` are
    chainable (except :meth:`~rfc3986.builder.URIBuilder.finalize` and
    :meth:`~rfc3986.builder.URIBuilder.geturl` as neither returns a
    :class:`~rfc3986.builder.URIBuilder`).

Building From Scratch
---------------------

Let's build a basic URL with just a scheme and host. First we create an
instance of :class:`~rfc3986.builder.URIBuilder`. Then we call
:meth:`~rfc3986.builder.URIBuilder.add_scheme` and
:meth:`~rfc3986.builder.URIBuilder.add_host` with the scheme and host
we want to include in the URL. Then we convert our builder object into
a :class:`~rfc3986.uri.URIReference` and call
:meth:`~rfc3986.uri.URIReference.unsplit`.

.. doctest::

    >>> from rfc3986 import builder
    >>> print(builder.URIBuilder().add_scheme(
    ...     'https'
    ... ).add_host(
    ...     'github.com'
    ... ).finalize().unsplit())
    https://github.com


Replacing Components of a URI
-----------------------------

It is possible to update an existing URI by constructing a builder from an
instance of :class:`~rfc3986.uri.URIReference` or a textual representation:

.. doctest::

    >>> from rfc3986 import builder
    >>> print(builder.URIBuilder.from_uri("http://github.com").add_scheme(
    ...     'https'
    ... ).finalize().unsplit())
    https://github.com

The Builder is Immutable
------------------------

Each time you invoke a method, you get a new instance of a
:class:`~rfc3986.builder.URIBuilder` class so you can build several different
URLs from one base instance.

.. doctest::

    >>> from rfc3986 import builder
    >>> github_builder = builder.URIBuilder().add_scheme(
    ...     'https'
    ... ).add_host(
    ...     'api.github.com'
    ... )
    >>> print(github_builder.add_path(
    ...     '/users/sigmavirus24'
    ... ).finalize().unsplit())
    https://api.github.com/users/sigmavirus24
    >>> print(github_builder.add_path(
    ...     '/repos/sigmavirus24/rfc3986'
    ... ).finalize().unsplit())
    https://api.github.com/repos/sigmavirus24/rfc3986

Convenient Path Management
--------------------------

Because our builder is immutable, one could use the
:class:`~rfc3986.builder.URIBuilder` class to build a class to make HTTP
Requests that used the provided path to extend the original one.

.. doctest::

    >>> from rfc3986 import builder
    >>> github_builder = builder.URIBuilder().add_scheme(
    ...     'https'
    ... ).add_host(
    ...     'api.github.com'
    ... ).add_path(
    ...     '/users'
    ... )
    >>> print(github_builder.extend_path("sigmavirus24").geturl())
    https://api.github.com/users/sigmavirus24
>>> print(github_builder.extend_path("lukasa").geturl())
https://api.github.com/users/lukasa

Adding Data as Path Segments
----------------------------

Object keys and other data frequently contain characters that are special
in a URI path, namely ``/``, ``?`` and ``#``. Concatenating such a value
onto a base URI changes the structure of the address (e.g. the part after
``#`` would be interpreted as a fragment).

:meth:`~rfc3986.builder.URIBuilder.add_path_segment` and
:meth:`~rfc3986.builder.URIBuilder.add_path_segments` build the path one
segment at a time and treat their arguments as raw data: every character
that is not allowed unencoded in a path segment is percent-encoded, so
``/``, ``?`` and ``#`` within the data can never alter the URI.

.. doctest::

    >>> from rfc3986 import builder
    >>> print(builder.URIBuilder.from_uri(
    ...     'https://storage.example.com/buckets'
    ... ).add_path_segment('photos/2017?size=large#top').geturl())
    https://storage.example.com/buckets/photos%2F2017%3Fsize=large%23top

Multiple segments may be supplied as an iterable or as positional
arguments:

.. doctest::

    >>> from urllib.parse import unquote
    >>> keys = ['my/bucket', 'photos/2017', '100%.jpg']
    >>> built = builder.URIBuilder.from_uri(
    ...     'https://storage.example.com'
    ... ).add_path_segments(keys)
    >>> print(built.geturl())
    https://storage.example.com/my%2Fbucket/photos%2F2017/100%25.jpg
    >>> [unquote(part) for part in built.path.lstrip('/').split('/')]
    ['my/bucket', 'photos/2017', '100%.jpg']

Empty segments add slashes: an empty segment appends a trailing slash and
empty segments are never collapsed. The literal segments ``.`` and ``..``
are appended verbatim -- they are data, not dot segments, and no
relative-reference resolution is performed. Segment building is thus
distinct from :meth:`~rfc3986.builder.URIBuilder.add_path` and
:meth:`~rfc3986.builder.URIBuilder.extend_path`, which work with whole
path strings.

.. doctest::

    >>> print(builder.URIBuilder(path='/a').add_path_segment('').geturl())
    /a/
    >>> print(builder.URIBuilder(path='/a').add_path_segments(
    ...     ['..', '.', 'x']
    ... ).geturl())
    /a/.././x

Appending Already-Encoded Text
-------------------------------

If a segment was already percent-encoded by another component, use
:meth:`~rfc3986.builder.URIBuilder.add_encoded_path_segment` (or
:meth:`~rfc3986.builder.URIBuilder.add_encoded_path_segments`) instead.
These methods do not encode the text again, so double encoding is avoided,
but validate that every ``%`` begins a valid percent-encoded triplet.
Malformed sequences, such as a bare ``%`` or ``%2``, raise a
:class:`ValueError`.

.. doctest::

    >>> print(builder.URIBuilder(path='/b').add_encoded_path_segment(
    ...     'photos%2F2017'
    ... ).geturl())
    /b/photos%2F2017

In every case the base URI's authority, query and fragment are preserved
exactly as they were.


Convenient Credential Handling
------------------------------

|rfc3986| makes adding authentication credentials convenient. It takes care of
making the credentials URL safe. There are some characters someone might want
to include in a URL that are not safe for the authority component of a URL.

.. doctest::

    >>> from rfc3986 import builder
    >>> print(builder.URIBuilder().add_scheme(
    ...     'https'
    ... ).add_host(
    ...     'api.github.com'
    ... ).add_credentials(
    ...     username='us3r',
    ...     password='p@ssw0rd',
    ... ).finalize().unsplit())
    https://us3r:p%40ssw0rd@api.github.com

Managing Query String Parameters
--------------------------------

Further, |rfc3986| attempts to simplify the process of adding query parameters
to a URL. For example, if we were using Elasticsearch, we might do something
like:

.. doctest::

    >>> from rfc3986 import builder
    >>> print(builder.URIBuilder().add_scheme(
    ...     'https'
    ... ).add_host(
    ...     'search.example.com'
    ... ).add_path(
    ...     '_search'
    ... ).add_query_from(
    ...     [('q', 'repo:sigmavirus24/rfc3986'), ('sort', 'created_at:asc')]
    ... ).finalize().unsplit())
    https://search.example.com/_search?q=repo%3Asigmavirus24%2Frfc3986&sort=created_at%3Aasc

If one also had an existing URL with query string that we merely wanted to
append to, we can also do that with |rfc3986|.

.. doctest::

    >>> from rfc3986 import builder
    >>> print(builder.URIBuilder().from_uri(
    ...    'https://search.example.com/_search?q=repo%3Asigmavirus24%2Frfc3986'
    ... ).extend_query_with(
    ...     [('sort', 'created_at:asc')]
    ... ).finalize().unsplit())
    https://search.example.com/_search?q=repo%3Asigmavirus24%2Frfc3986&sort=created_at%3Aasc

Adding Fragments
----------------

Finally, we provide a way to add a fragment to a URL. Let's build up a URL to
view the section of the RFC that refers to fragments:

.. doctest::

    >>> from rfc3986 import builder
    >>> print(builder.URIBuilder().add_scheme(
    ...     'https'
    ... ).add_host(
    ...     'tools.ietf.org'
    ... ).add_path(
    ...     '/html/rfc3986'
    ... ).add_fragment(
    ...     'section-3.5'
    ... ).finalize().unsplit())
    https://tools.ietf.org/html/rfc3986#section-3.5
