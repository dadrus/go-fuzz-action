"""Failure contract shared by the analysis and its adapters."""


class FuzzActionError(Exception):
    """A run could not be completed or its results could not be trusted."""


__all__ = ["FuzzActionError"]
