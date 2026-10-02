2.x.y - 202z-aa-bb
------------------

- Add ``URIBuilder.add_path_segment`` and ``URIBuilder.add_path_segments``
  to append raw data as individual, percent-encoded path segments. ``/``,
  ``?`` and ``#`` inside the data are encoded, so object keys and similar
  values cannot change the structure of the URI. Empty segments add
  slashes, and ``.`` and ``..`` are kept verbatim rather than resolved.
- Add ``URIBuilder.add_encoded_path_segment`` and
  ``URIBuilder.add_encoded_path_segments`` to append already
  percent-encoded segments without double encoding; invalid percent
  sequences raise ``ValueError``.

.. links below here
