"""Coordinate a complete single-target fuzz analysis."""

from .config import Config
from .fuzzing import Session
from .output import AnalysisResult, ResultWriter


class FuzzAnalyzer:
    def __init__(self, config: Config) -> None:
        self._session = Session(config)
        self._output = ResultWriter(config)

    def run(self) -> AnalysisResult:
        with (
            self._output.open() as output,
            self._session.run() as result,
        ):
            return output.write(result)
