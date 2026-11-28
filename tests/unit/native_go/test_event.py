"""Validate external Go JSONL events at the parser boundary."""

import json
import tempfile
import unittest
from pathlib import Path

from go_fuzz.native_go.error import NativeGoError
from go_fuzz.native_go.event import Event, parse_events

PACKAGE = "example.com/project"


class TestEventParser(unittest.TestCase):
    def setUp(self):
        self.path = Path(self.enterContext(tempfile.TemporaryDirectory())) / "events"

    def test_parse_and_reject_invalid_event(self):
        # GIVEN
        path = self.path
        path.write_text(
            json.dumps({"Action": "run", "Package": PACKAGE, "Test": "FuzzA"}) + "\n"
        )

        # WHEN
        events = list(parse_events(path))

        # THEN
        self.assertEqual(events, [Event("run", PACKAGE, "FuzzA")])

        for raw in (
            b"{bad}\n",
            b"{}\n",
            b"[]\n",
            b'{"Action": 1}\n',
            b'{"Action": "run", "Package": "example.com/project", "Test": null}\n',
            b'{"Action": "output", "Package": "example.com/project", "Output": 1}\n',
            b'{"Action": "run", "Package": 1, "Test": "FuzzA"}\n',
            b'{"Action": "run", "Test": "FuzzA"}\n',
        ):
            with self.subTest(raw=raw):
                # GIVEN
                path.write_bytes(raw)

                # WHEN / THEN
                with self.assertRaises(NativeGoError):
                    list(parse_events(path))
