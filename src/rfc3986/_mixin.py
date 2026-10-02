"""Module containing the implementation of the URIMixin class."""

import typing as t
import warnings

from . import exceptions as exc
from . import misc
from . import normalizers
from . import uri
from . import validators
from ._typing_compat import Self as _Self


class _AuthorityInfo(t.TypedDict):
    """A typed dict for the authority info triple: userinfo, host, and port."""

    userinfo: t.Optional[str]
    host: t.Optional[str]
    port: t.Optional[str]


class URIMixin:
    """Mixin with all shared methods for URIs and IRIs."""

    if t.TYPE_CHECKING:
        scheme: t.Optional[str]
        authority: t.Optional[str]
        path: t.Optional[str]
        query: t.Optional[str]
        fragment: t.Optional[str]
        encoding: str

    def authority_info(self) -> _AuthorityInfo:
        """Return a dictionary with the ``userinfo``, ``host``, and ``port``.

        If the authority is not valid, it will raise a
        :class:`~rfc3986.exceptions.InvalidAuthority` Exception.

        :returns:
            ``{'userinfo': 'username:password', 'host': 'www.example.com',
            'port': '80'}``
        :rtype: dict
        :raises rfc3986.exceptions.InvalidAuthority:
            If the authority is not ``None`` and can not be parsed.
        """
        if not self.authority:
            return {"userinfo": None, "host": None, "port": None}

        match = self._match_subauthority()

        if match is None:
            # In this case, we have an authority that was parsed from the URI
            # Reference, but it cannot be further parsed by our
            # misc.SUBAUTHORITY_MATCHER. In this case it must not be a valid
            # authority.
            raise exc.InvalidAuthority(self.authority.encode(self.encoding))

        # We had a match, now let's ensure that it is actually a valid host
        # address if it is IPv4
        matches = match.groupdict()
        host = matches.get("host")

        if (
            host
            and misc.IPv4_MATCHER.match(host)
            and not validators.valid_ipv4_host_address(host)
        ):
            # If we have a host, it appears to be IPv4 and it does not have
            # valid bytes, it is an InvalidAuthority.
            raise exc.InvalidAuthority(self.authority.encode(self.encoding))

        return matches

    def _match_subauthority(self) -> t.Optional[t.Match[str]]:
        return misc.SUBAUTHORITY_MATCHER.match(self.authority)

    @property
    def _validator(self) -> validators.Validator:
        v = getattr(self, "_cached_validator", None)
        if v is not None:
            return v
        self._cached_validator = validators.Validator().require_presence_of(
            "scheme"
        )
        return self._cached_validator

    @property
    def host(self) -> t.Optional[str]:
        """If present, a string representing the host."""
        try:
            authority = self.authority_info()
        except exc.InvalidAuthority:
            return None
        return authority["host"]

    @property
    def port(self) -> t.Optional[str]:
        """If present, the port extracted from the authority."""
        try:
            authority = self.authority_info()
        except exc.InvalidAuthority:
            return None
        return authority["port"]

    @property
    def userinfo(self) -> t.Optional[str]:
        """If present, the userinfo extracted from the authority."""
        try:
            authority = self.authority_info()
        except exc.InvalidAuthority:
            return None
        return authority["userinfo"]

    def is_absolute(self) -> bool:
        """Determine if this URI Reference is an absolute URI.

        See http://tools.ietf.org/html/rfc3986#section-4.3 for explanation.

        :returns: ``True`` if it is an absolute URI, ``False`` otherwise.
        :rtype: bool
        """
        return bool(misc.ABSOLUTE_URI_MATCHER.match(self.unsplit()))

    def is_valid(self, **kwargs: bool) -> bool:
        """Determine if the URI is valid.

        .. deprecated:: 1.1.0

            Use the :class:`~rfc3986.validators.Validator` object instead.

        :param bool require_scheme: Set to ``True`` if you wish to require the
            presence of the scheme component.
        :param bool require_authority: Set to ``True`` if you wish to require
            the presence of the authority component.
        :param bool require_path: Set to ``True`` if you wish to require the
            presence of the path component.
        :param bool require_query: Set to ``True`` if you wish to require the
            presence of the query component.
        :param bool require_fragment: Set to ``True`` if you wish to require
            the presence of the fragment component.
        :returns: ``True`` if the URI is valid. ``False`` otherwise.
        :rtype: bool
        """
        warnings.warn(
            "Please use rfc3986.validators.Validator instead. "
            "This method will be eventually removed.",
            DeprecationWarning,
        )
        validators = [
            (self.scheme_is_valid, kwargs.get("require_scheme", False)),
            (self.authority_is_valid, kwargs.get("require_authority", False)),
            (self.path_is_valid, kwargs.get("require_path", False)),
            (self.query_is_valid, kwargs.get("require_query", False)),
            (self.fragment_is_valid, kwargs.get("require_fragment", False)),
        ]
        return all(v(r) for v, r in validators)

    def authority_is_valid(self, require: bool = False) -> bool:
        """Determine if the authority component is valid.

        .. deprecated:: 1.1.0

            Use the :class:`~rfc3986.validators.Validator` object instead.

        :param bool require:
            Set to ``True`` to require the presence of this component.
        :returns:
            ``True`` if the authority is valid. ``False`` otherwise.
        :rtype:
            bool
        """
        warnings.warn(
            "Please use rfc3986.validators.Validator instead. "
            "This method will be eventually removed.",
            DeprecationWarning,
        )
        try:
            self.authority_info()
        except exc.InvalidAuthority:
            return False

        return validators.authority_is_valid(
            self.authority,
            host=self.host,
            require=require,
        )

    def scheme_is_valid(self, require: bool = False) -> bool:
        """Determine if the scheme component is valid.

        .. deprecated:: 1.1.0

            Use the :class:`~rfc3986.validators.Validator` object instead.

        :param str require: Set to ``True`` to require the presence of this
            component.
        :returns: ``True`` if the scheme is valid. ``False`` otherwise.
        :rtype: bool
        """
        warnings.warn(
            "Please use rfc3986.validators.Validator instead. "
            "This method will be eventually removed.",
            DeprecationWarning,
        )
        return validators.scheme_is_valid(self.scheme, require)

    def path_is_valid(self, require: bool = False) -> bool:
        """Determine if the path component is valid.

        .. deprecated:: 1.1.0

            Use the :class:`~rfc3986.validators.Validator` object instead.

        :param str require: Set to ``True`` to require the presence of this
            component.
        :returns: ``True`` if the path is valid. ``False`` otherwise.
        :rtype: bool
        """
        warnings.warn(
            "Please use rfc3986.validators.Validator instead. "
            "This method will be eventually removed.",
            DeprecationWarning,
        )
        return validators.path_is_valid(self.path, require)

    def query_is_valid(self, require: bool = False) -> bool:
        """Determine if the query component is valid.

        .. deprecated:: 1.1.0

            Use the :class:`~rfc3986.validators.Validator` object instead.

        :param str require: Set to ``True`` to require the presence of this
            component.
        :returns: ``True`` if the query is valid. ``False`` otherwise.
        :rtype: bool
        """
        warnings.warn(
            "Please use rfc3986.validators.Validator instead. "
            "This method will be eventually removed.",
            DeprecationWarning,
        )
        return validators.query_is_valid(self.query, require)

    def fragment_is_valid(self, require: bool = False) -> bool:
        """Determine if the fragment component is valid.

        .. deprecated:: 1.1.0

            Use the Validator object instead.

        :param str require: Set to ``True`` to require the presence of this
            component.
        :returns: ``True`` if the fragment is valid. ``False`` otherwise.
        :rtype: bool
        """
        warnings.warn(
            "Please use rfc3986.validators.Validator instead. "
            "This method will be eventually removed.",
            DeprecationWarning,
        )
        return validators.fragment_is_valid(self.fragment, require)

    def normalized_equality(self, other_ref: "uri.URIReference") -> bool:
        """Compare this URIReference to another URIReference.

        :param URIReference other_ref: (required), The reference with which
            we're comparing.
        :returns: ``True`` if the references are equal, ``False`` otherwise.
        :rtype: bool
        """
        return tuple(self.normalize()) == tuple(other_ref.normalize())

    def resolve_with(  # noqa: C901
        self,
        base_uri: t.Union[str, "uri.URIReference"],
        strict: bool = False,
    ) -> _Self:
        """Use an absolute URI Reference to resolve this relative reference.

        Assuming this is a relative reference that you would like to resolve,
        use the provided base URI to resolve it.

        See http://tools.ietf.org/html/rfc3986#section-5 for more information.

        :param base_uri: Either a string or URIReference. It must be an
            absolute URI or it will raise an exception.
        :returns: A new URIReference which is the result of resolving this
            reference using ``base_uri``.
        :rtype: :class:`URIReference`
        :raises rfc3986.exceptions.ResolutionError:
            If the ``base_uri`` does not at least have a scheme.
        """
        if not isinstance(base_uri, URIMixin):
            base_uri = type(self).from_string(base_uri)

        if t.TYPE_CHECKING:
            base_uri = t.cast(uri.URIReference, base_uri)

        try:
            self._validator.validate(base_uri)
        except exc.ValidationError:
            raise exc.ResolutionError(base_uri)

        # This is optional per
        # http://tools.ietf.org/html/rfc3986#section-5.2.1
        base_uri = base_uri._normalized_reference()

        # The reference we're resolving
        resolving = self

        if not strict and resolving.scheme == base_uri.scheme:
            resolving = resolving.copy_with(scheme=None)

        # http://tools.ietf.org/html/rfc3986#page-32
        if resolving.scheme is not None:
            target = resolving.copy_with(
                path=normalizers.normalize_path(resolving.path)
            )
        else:
            if resolving.authority is not None:
                target = resolving.copy_with(
                    scheme=base_uri.scheme,
                    path=normalizers.normalize_path(resolving.path),
                )
            else:
                if resolving.path is None:
                    if resolving.query is not None:
                        query = resolving.query
                    else:
                        query = base_uri.query
                    target = resolving.copy_with(
                        scheme=base_uri.scheme,
                        authority=base_uri.authority,
                        path=base_uri.path,
                        query=query,
                    )
                else:
                    if resolving.path.startswith("/"):
                        path = normalizers.normalize_path(resolving.path)
                    else:
                        path = normalizers.normalize_path(
                            misc.merge_paths(base_uri, resolving.path)
                        )
                    target = resolving.copy_with(
                        scheme=base_uri.scheme,
                        authority=base_uri.authority,
                        path=path,
                        query=resolving.query,
                    )
        return target

    def relative_to(
        self,
        base_uri: t.Union[str, "uri.URIReference"],
        strict: bool = True,
    ) -> _Self:
        """Create a reference relative to an absolute base URI.

        The returned reference resolves back to this reference when passed to
        :meth:`resolve_with` with the same base URI. When this reference has
        the same scheme and authority as the base, a path-relative reference
        is returned. When the schemes differ, the reference is absolute. When
        the schemes match but the authorities differ, a network-path
        reference is returned.

        :param base_uri: Either a string or URIReference. It must be an
            absolute URI or it will raise an exception.
        :param bool strict: When ``False``, schemes which differ only by case
            are treated as equivalent.
        :returns: A new reference relative to ``base_uri``.
        :rtype: :class:`URIReference`
        :raises rfc3986.exceptions.ResolutionError:
            If either this reference or ``base_uri`` does not have a scheme.
        """
        if not isinstance(base_uri, URIMixin):
            base_uri = type(self).from_string(base_uri)

        if t.TYPE_CHECKING:
            base_uri = t.cast(uri.URIReference, base_uri)

        try:
            self._validator.validate(self)
            self._validator.validate(base_uri)
        except exc.ValidationError:
            invalid_uri = self if self.scheme is None else base_uri
            raise exc.ResolutionError(invalid_uri)

        target = self._normalized_reference()
        base = base_uri._normalized_reference()
        if strict:
            same_scheme = self.scheme == base_uri.scheme
            same_authority = self.authority == base_uri.authority
        else:
            same_scheme = target.scheme == base.scheme
            same_authority = target.authority == base.authority

        if not same_scheme:
            return self.copy_with()

        if not same_authority:
            return self.copy_with(scheme=None)

        reference = target.copy_with(scheme=None)

        if target.path is None:
            can_omit_path = base.path is None and (
                target.query is not None or base.query is None
            )
            if not can_omit_path:
                return self.copy_with()
            return reference.copy_with(authority=None, path=None)

        if base.path is not None and "/" not in base.path:
            return self.copy_with()

        base_path = base.path or ""
        base_slash = base_path.rfind("/")
        if base_slash == -1:
            base_directory = []
        else:
            base_directory = base_path[:base_slash].split("/")
        target_segments = (target.path or "").split("/")

        common = 0
        while (
            common < len(base_directory)
            and common < len(target_segments) - 1
            and base_directory[common] == target_segments[common]
        ):
            common += 1

        relative_segments = [".."] * (len(base_directory) - common)
        relative_segments.extend(target_segments[common:])
        relative_path = "/".join(relative_segments)

        if relative_path == "":
            empty_path_preserves_target = target.path == base.path and (
                target.query is not None or base.query is None
            )
            if not empty_path_preserves_target:
                relative_path = "."
        elif self._relative_path_needs_dot_slash(relative_path):
            relative_path = "./" + relative_path

        if relative_path == "":
            return reference.copy_with(authority=None, path=None)
        return reference.copy_with(authority=None, path=relative_path)

    @staticmethod
    def _relative_path_needs_dot_slash(path: str) -> bool:
        first_segment = path.split("/", 1)[0]
        return ":" in first_segment

    def _normalized_reference(self) -> _Self:
        normalize = getattr(self, "normalize", None)
        if callable(normalize):
            return normalize()

        authority = self.authority
        if authority:
            try:
                authority_info = self.authority_info()
            except exc.InvalidAuthority:
                pass
            else:
                authority_parts = []
                if authority_info["userinfo"]:
                    authority_parts.append(authority_info["userinfo"])
                    authority_parts.append("@")
                authority_parts.append(
                    normalizers.normalize_host(authority_info["host"])
                )
                if authority_info["port"]:
                    authority_parts.append(":")
                    authority_parts.append(authority_info["port"])
                authority = "".join(authority_parts)

        return self.copy_with(
            scheme=normalizers.normalize_scheme(self.scheme or ""),
            authority=authority,
            path=normalizers.normalize_path(self.path or ""),
            query=normalizers.normalize_query(self.query),
            fragment=normalizers.normalize_fragment(self.fragment),
        )

    def unsplit(self) -> str:
        """Create a URI string from the components.

        :returns: The URI Reference reconstituted as a string.
        :rtype: str
        """
        # See http://tools.ietf.org/html/rfc3986#section-5.3
        result_list: list[str] = []
        if self.scheme:
            result_list.extend([self.scheme, ":"])
        if self.authority:
            result_list.extend(["//", self.authority])
        if self.path:
            result_list.append(self.path)
        if self.query is not None:
            result_list.extend(["?", self.query])
        if self.fragment is not None:
            result_list.extend(["#", self.fragment])
        return "".join(result_list)

    def copy_with(
        self,
        scheme: t.Optional[str] = misc.UseExisting,
        authority: t.Optional[str] = misc.UseExisting,
        path: t.Optional[str] = misc.UseExisting,
        query: t.Optional[str] = misc.UseExisting,
        fragment: t.Optional[str] = misc.UseExisting,
    ) -> _Self:
        """Create a copy of this reference with the new components.

        :param str scheme:
            (optional) The scheme to use for the new reference.
        :param str authority:
            (optional) The authority to use for the new reference.
        :param str path:
            (optional) The path to use for the new reference.
        :param str query:
            (optional) The query to use for the new reference.
        :param str fragment:
            (optional) The fragment to use for the new reference.
        :returns:
            New URIReference with provided components.
        :rtype:
            URIReference
        """
        attributes = {
            "scheme": scheme,
            "authority": authority,
            "path": path,
            "query": query,
            "fragment": fragment,
        }
        for key, value in list(attributes.items()):
            if value is misc.UseExisting:
                del attributes[key]
        uri: _Self = self._replace(**attributes)
        uri.encoding = self.encoding
        return uri
