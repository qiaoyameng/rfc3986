2.x.y - 202z-aa-bb
------------------

- Add ``URIBuilder.add_path_segment`` to append a single path segment that
  is percent-encoded as raw data, so values containing ``/``, ``?``, ``#``,
  or literal ``%`` (such as object keys) cannot alter the URI structure.

- Add ``URIBuilder.add_encoded_path_segment`` as the explicit entry point
  for already percent-encoded segments. It validates percent sequences to
  prevent double-encoding and rejects raw delimiters and dot segments.

.. links below here
