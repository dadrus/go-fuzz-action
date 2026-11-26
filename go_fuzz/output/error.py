"""Output failure contract."""

from ..errors import FuzzActionError


class OutputError(FuzzActionError):
    """The result writer could not publish a valid analysis result."""
