"""Analysis result persistence and report serialization."""

from .error import OutputError
from .writer import AnalysisResult, ResultWriter

__all__ = [
    "AnalysisResult",
    "OutputError",
    "ResultWriter",
]
