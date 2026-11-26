"""Reusable Go fuzz analysis, independent of GitHub Actions."""

from .analyzer import FuzzAnalyzer
from .config import Config, ResultsFormat
from .errors import FuzzActionError
from .fuzzing import Finding
from .native_go import Target, TargetSelector
from .output import AnalysisResult

__all__ = [
    "AnalysisResult",
    "Config",
    "Finding",
    "FuzzActionError",
    "FuzzAnalyzer",
    "ResultsFormat",
    "Target",
    "TargetSelector",
]
