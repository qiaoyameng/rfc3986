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
"""Module containing the logic for the URIBuilder object."""

import typing as t
from urllib.parse import parse_qsl
from urllib.parse import urlencode

from . import normalizers
from . import uri
from . import uri_reference
from ._typing_compat import Self as _Self

# Modified from urllib.parse in typeshed.
_QueryType = t.Union[
    t.Mapping[t.Any, t.Any],
    t.Mapping[t.Any, t.Sequence[t.Any]],
    # Substituting List for Sequence since one of the add/extend methods
    # below has a runtime isinstance check for list.
    t.List[t.Tuple[t.Any, t.Any]],
    t.List[t.Tuple[t.Any, t.Sequence[t.Any]]],
]


class URIBuilder:
    """Object to aid in building up a URI Reference from parts.

    .. note::

        This object should be instantiated by the user, but it's recommended
        that it is not provided with arguments. Instead, use the available
        method to populate the fields.

    """

    def __init__(
        self,
        scheme: t.Optional[str] = None,
        userinfo: t.Optional[str] = None,
        host: t.Optional[str] = None,
        port: t.Optional[t.Union[int, str]] = None,
        path: t.Optional[str] = None,
        query: t.Optional[str] = None,
        fragment: t.Optional[str] = None,
    ):
        """Initialize our URI builder.

        :param str scheme:
            (optional)
        :param str userinfo:
            (optional)
        :param str host:
            (optional)
        :param int | str port:
            (optional)
        :param str path:
            (optional)
        :param str query:
            (optional)
        :param str fragment:
            (optional)
        """
        self.scheme = scheme
        self.userinfo = userinfo
        self.host = host
        self.port = str(port) if port is not None else port
        self.path = path
        self.query = query
        self.fragment = fragment

    def __repr__(self):
        """Provide a convenient view of our builder object."""
        formatstr = (
            "URIBuilder(scheme={b.scheme}, userinfo={b.userinfo}, "
            "host={b.host}, port={b.port}, path={b.path}, "
            "query={b.query}, fragment={b.fragment})"
        )
        return formatstr.format(b=self)

    @classmethod
    def from_uri(cls, reference: t.Union["uri.URIReference", str]) -> _Self:
        """Initialize the URI builder from another URI.

        Takes the given URI reference and creates a new URI builder instance
        populated with the values from the reference. If given a string it will
        try to convert it to a reference before constructing the builder.
        """
        if not isinstance(reference, uri.URIReference):
            reference = uri_reference(reference)
        return cls(
            scheme=reference.scheme,
            userinfo=reference.userinfo,
            host=reference.host,
            port=reference.port,
            path=reference.path,
            query=reference.query,
            fragment=reference.fragment,
        )

    def add_scheme(self, scheme: str) -> "URIBuilder":
        """Add a scheme to our builder object.

        After normalizing, this will generate a new URIBuilder instance with
        the specified scheme and all other attributes the same.

        .. code-block:: python

            >>> URIBuilder().add_scheme('HTTPS')
            URIBuilder(scheme='https', userinfo=None, host=None, port=None,
                    path=None, query=None, fragment=None)

        """
        scheme = normalizers.normalize_scheme(scheme)
        return URIBuilder(
            scheme=scheme,
            userinfo=self.userinfo,
            host=self.host,
            port=self.port,
            path=self.path,
            query=self.query,
            fragment=self.fragment,
        )

    def add_credentials(
        self,
        username: str,
        password: t.Optional[str],
    ) -> "URIBuilder":
        """Add credentials as the userinfo portion of the URI.

        .. code-block:: python

            >>> URIBuilder().add_credentials('root', 's3crete')
            URIBuilder(scheme=None, userinfo='root:s3crete', host=None,
                    port=None, path=None, query=None, fragment=None)

            >>> URIBuilder().add_credentials('root', None)
            URIBuilder(scheme=None, userinfo='root', host=None,
                    port=None, path=None, query=None, fragment=None)
        """
        if username is None:
            raise ValueError("Username cannot be None")
        userinfo = normalizers.normalize_username(username)

        if password is not None:
            userinfo = "{}:{}".format(
                userinfo,
                normalizers.normalize_password(password),
            )

        return URIBuilder(
            scheme=self.scheme,
            userinfo=userinfo,
            host=self.host,
            port=self.port,
            path=self.path,
            query=self.query,
            fragment=self.fragment,
        )

    def add_host(self, host: str) -> "URIBuilder":
        """Add hostname to the URI.

        .. code-block:: python

            >>> URIBuilder().add_host('google.com')
            URIBuilder(scheme=None, userinfo=None, host='google.com',
                    port=None, path=None, query=None, fragment=None)

        """
        return URIBuilder(
            scheme=self.scheme,
            userinfo=self.userinfo,
            host=normalizers.normalize_host(host),
            port=self.port,
            path=self.path,
            query=self.query,
            fragment=self.fragment,
        )

    def add_port(self, port: t.Union[int, str]) -> "URIBuilder":
        """Add port to the URI.

        .. code-block:: python

            >>> URIBuilder().add_port(80)
            URIBuilder(scheme=None, userinfo=None, host=None, port='80',
                    path=None, query=None, fragment=None)

            >>> URIBuilder().add_port(443)
            URIBuilder(scheme=None, userinfo=None, host=None, port='443',
                    path=None, query=None, fragment=None)

        """
        port_int = int(port)
        if port_int < 0:
            raise ValueError(
                "ports are not allowed to be negative. You provided {}".format(
                    port_int,
                )
            )
        if port_int > 65535:
            raise ValueError(
                "ports are not allowed to be larger than 65535. "
                "You provided {}".format(
                    port_int,
                )
            )

        return URIBuilder(
            scheme=self.scheme,
            userinfo=self.userinfo,
            host=self.host,
            port=f"{port_int}",
            path=self.path,
            query=self.query,
            fragment=self.fragment,
        )

    def add_path(self, path: str) -> "URIBuilder":
        """Add a path to the URI.

        .. code-block:: python

            >>> URIBuilder().add_path('sigmavirus24/rfc3985')
            URIBuilder(scheme=None, userinfo=None, host=None, port=None,
                    path='/sigmavirus24/rfc3986', query=None, fragment=None)

            >>> URIBuilder().add_path('/checkout.php')
            URIBuilder(scheme=None, userinfo=None, host=None, port=None,
                    path='/checkout.php', query=None, fragment=None)

        """
        if not path.startswith("/"):
            path = f"/{path}"

        return URIBuilder(
            scheme=self.scheme,
            userinfo=self.userinfo,
            host=self.host,
            port=self.port,
            path=normalizers.normalize_path(path),
            query=self.query,
            fragment=self.fragment,
        )

    def extend_path(self, path: str) -> "URIBuilder":
        """Extend the existing path value with the provided value.

        .. versionadded:: 1.5.0

        .. code-block:: python

            >>> URIBuilder(path="/users").extend_path("/sigmavirus24")
            URIBuilder(scheme=None, userinfo=None, host=None, port=None,
                    path='/users/sigmavirus24', query=None, fragment=None)

            >>> URIBuilder(path="/users/").extend_path("/sigmavirus24")
            URIBuilder(scheme=None, userinfo=None, host=None, port=None,
                    path='/users/sigmavirus24', query=None, fragment=None)

            >>> URIBuilder(path="/users/").extend_path("sigmavirus24")
            URIBuilder(scheme=None, userinfo=None, host=None, port=None,
                    path='/users/sigmavirus24', query=None, fragment=None)

            >>> URIBuilder(path="/users").extend_path("sigmavirus24")
            URIBuilder(scheme=None, userinfo=None, host=None, port=None,
                    path='/users/sigmavirus24', query=None, fragment=None)

        """
        existing_path = self.path or ""
        path = "{}/{}".format(existing_path.rstrip("/"), path.lstrip("/"))

        return self.add_path(path)

    def _append_path_segments(
        self,
        encoded_segments: t.List[str],
    ) -> "URIBuilder":
        """Append already-encoded path segments without resolving them.

        Segments are joined with single slashes. Empty segments produce
        slashes (trailing or otherwise), and ``.`` as well as ``..`` are
        kept verbatim; no dot-segment removal or relative-path resolution is
        performed.
        """
        path = self.path
        for segment in encoded_segments:
            if path is None:
                path = "/" + segment
            else:
                path = path + "/" + segment

        return URIBuilder(
            scheme=self.scheme,
            userinfo=self.userinfo,
            host=self.host,
            port=self.port,
            path=path,
            query=self.query,
            fragment=self.fragment,
        )

    def add_path_segment(self, segment: str) -> "URIBuilder":
        """Append a single raw path segment.

        The segment is treated as opaque data and percent-encoded. In
        particular, ``/``, ``?`` and ``#`` inside the segment are encoded so
        they cannot alter the structure of the URI. This makes the method
        safe for object keys and other arbitrary data.

        .. code-block:: python

            >>> URIBuilder(path='/buckets').add_path_segment(
            ...     'photos/2017?a=1#frag'
            ... ).path
            '/buckets/photos%2F2017%3Fa=1%23frag'

        An empty segment adds a trailing slash:

        .. code-block:: python

            >>> URIBuilder(path='/buckets').add_path_segment('').path
            '/buckets/'

        The literal segments ``.`` and ``..`` are appended verbatim; they are
        neither removed nor resolved (this is not relative-reference
        resolution).
        """
        return self._append_path_segments(
            [normalizers.encode_path_segment(segment)]
        )

    def add_path_segments(
        self,
        segments: t.Union[str, t.Iterable[str]],
        *more_segments: str,
    ) -> "URIBuilder":
        """Append multiple raw path segments.

        Each segment is percent-encoded independently, as described in
        :meth:`add_path_segment`. Segments may be passed as a single
        iterable or as positional arguments.

        .. code-block:: python

            >>> URIBuilder(path='/b').add_path_segments(
            ...     ['photos/2017', '100%.jpg']
            ... ).path
            '/b/photos%2F2017/100%25.jpg'
        """
        if isinstance(segments, str):
            segment_list = [segments]
            segment_list.extend(more_segments)
        else:
            if more_segments:
                raise TypeError(
                    "segments may be an iterable or positional arguments, "
                    "but not both"
                )
            segment_list = list(segments)

        return self._append_path_segments(
            [
                normalizers.encode_path_segment(segment)
                for segment in segment_list
            ]
        )

    def add_encoded_path_segment(self, segment: str) -> "URIBuilder":
        """Append a single already percent-encoded path segment.

        Unlike :meth:`add_path_segment`, the input is not encoded again.
        Instead its percent-encoded triplets are validated so that text
        produced by an encoder can be preserved verbatim without double
        encoding.

        :raises ValueError: if the segment contains a ``%`` that is not
            followed by two hexadecimal digits.

        .. code-block:: python

            >>> URIBuilder(path='/b').add_encoded_path_segment(
            ...     'photos%2F2017'
            ... ).path
            '/b/photos%2F2017'
        """
        return self._append_path_segments(
            [normalizers.validate_percent_encodings(segment)]
        )

    def add_encoded_path_segments(
        self,
        segments: t.Union[str, t.Iterable[str]],
        *more_segments: str,
    ) -> "URIBuilder":
        """Append multiple already percent-encoded path segments.

        See :meth:`add_encoded_path_segment`. Each segment is validated and
        appended verbatim without being encoded again.

        :raises ValueError: if a segment contains an invalid percent
            sequence.
        """
        if isinstance(segments, str):
            segment_list = [segments]
            segment_list.extend(more_segments)
        else:
            if more_segments:
                raise TypeError(
                    "segments may be an iterable or positional arguments, "
                    "but not both"
                )
            segment_list = list(segments)

        return self._append_path_segments(
            [
                normalizers.validate_percent_encodings(segment)
                for segment in segment_list
            ]
        )

    def add_query_from(self, query_items: _QueryType) -> "URIBuilder":
        """Generate and add a query a dictionary or list of tuples.

        .. code-block:: python

            >>> URIBuilder().add_query_from({'a': 'b c'})
            URIBuilder(scheme=None, userinfo=None, host=None, port=None,
                    path=None, query='a=b+c', fragment=None)

            >>> URIBuilder().add_query_from([('a', 'b c')])
            URIBuilder(scheme=None, userinfo=None, host=None, port=None,
                    path=None, query='a=b+c', fragment=None)

        """
        query = normalizers.normalize_query(urlencode(query_items))

        return URIBuilder(
            scheme=self.scheme,
            userinfo=self.userinfo,
            host=self.host,
            port=self.port,
            path=self.path,
            query=query,
            fragment=self.fragment,
        )

    def extend_query_with(self, query_items: _QueryType) -> "URIBuilder":
        """Extend the existing query string with the new query items.

        .. versionadded:: 1.5.0

        .. code-block:: python

            >>> URIBuilder(query='a=b+c').extend_query_with({'a': 'b c'})
            URIBuilder(scheme=None, userinfo=None, host=None, port=None,
                    path=None, query='a=b+c&a=b+c', fragment=None)

            >>> URIBuilder(query='a=b+c').extend_query_with([('a', 'b c')])
            URIBuilder(scheme=None, userinfo=None, host=None, port=None,
                    path=None, query='a=b+c&a=b+c', fragment=None)
        """
        original_query_items = parse_qsl(self.query or "")
        if not isinstance(query_items, list):
            query_items = list(query_items.items())

        return self.add_query_from(original_query_items + query_items)

    def add_query(self, query: str) -> "URIBuilder":
        """Add a pre-formated query string to the URI.

        .. code-block:: python

            >>> URIBuilder().add_query('a=b&c=d')
            URIBuilder(scheme=None, userinfo=None, host=None, port=None,
                    path=None, query='a=b&c=d', fragment=None)

        """
        return URIBuilder(
            scheme=self.scheme,
            userinfo=self.userinfo,
            host=self.host,
            port=self.port,
            path=self.path,
            query=normalizers.normalize_query(query),
            fragment=self.fragment,
        )

    def add_fragment(self, fragment: str) -> "URIBuilder":
        """Add a fragment to the URI.

        .. code-block:: python

            >>> URIBuilder().add_fragment('section-2.6.1')
            URIBuilder(scheme=None, userinfo=None, host=None, port=None,
                    path=None, query=None, fragment='section-2.6.1')

        """
        return URIBuilder(
            scheme=self.scheme,
            userinfo=self.userinfo,
            host=self.host,
            port=self.port,
            path=self.path,
            query=self.query,
            fragment=normalizers.normalize_fragment(fragment),
        )

    def finalize(self) -> "uri.URIReference":
        """Create a URIReference from our builder.

        .. code-block:: python

            >>> URIBuilder().add_scheme('https').add_host('github.com'
            ...     ).add_path('sigmavirus24/rfc3986').finalize().unsplit()
            'https://github.com/sigmavirus24/rfc3986'

            >>> URIBuilder().add_scheme('https').add_host('github.com'
            ...     ).add_path('sigmavirus24/rfc3986').add_credentials(
            ...     'sigmavirus24', 'not-re@l').finalize().unsplit()
            'https://sigmavirus24:not-re%40l@github.com/sigmavirus24/rfc3986'

        """
        return uri.URIReference(
            self.scheme,
            normalizers.normalize_authority(
                (self.userinfo, self.host, self.port)
            ),
            self.path,
            self.query,
            self.fragment,
        )

    def geturl(self) -> str:
        """Generate the URL from this builder.

        .. versionadded:: 1.5.0

        This is an alternative to calling :meth:`finalize` and keeping the
        :class:`rfc3986.uri.URIReference` around.
        """
        return self.finalize().unsplit()
