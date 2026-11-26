"""Native Go execution, exact target selection and test evidence."""

from .error import NativeGoError
from .runner import Runner, TestResult
from .target import Target
from .target_selector import SEED_NAME, TargetSelector
from .test_outcome import TestOutcome

__all__ = [
    "SEED_NAME",
    "NativeGoError",
    "Runner",
    "Target",
    "TargetSelector",
    "TestOutcome",
    "TestResult",
]
