"""Native go failure contract."""

from ..errors import FuzzActionError


class NativeGoError(FuzzActionError):
    """Native Go execution or its evidence could not be trusted."""
