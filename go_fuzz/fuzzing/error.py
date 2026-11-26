"""Fuzzing failure contract."""

from ..errors import FuzzActionError


class FuzzingError(FuzzActionError):
    """The fuzzing session or its finding invariants failed."""
