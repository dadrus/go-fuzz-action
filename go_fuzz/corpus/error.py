"""Corpus failure contract."""

from ..errors import FuzzActionError


class CorpusError(FuzzActionError):
    """A native corpus could not be validated or processed."""
