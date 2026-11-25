import datetime
import io
from pathlib import Path
import subprocess
import sys
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "stream_log.py"


class TimestampLoggingTests(unittest.TestCase):
    def test_timestamped_lines_are_complete(self):
        output = subprocess.run([sys.executable, str(SCRIPT)], input="first\nsecond\n",
                                text=True, capture_output=True, check=True).stdout.splitlines()
        self.assertEqual(len(output), 2)
        for line, original in zip(output, ("first", "second")):
            stamp, message = line.split(" ", 1)
            parsed = datetime.datetime.fromisoformat(stamp)
            self.assertIsNotNone(parsed.tzinfo)
            self.assertEqual(message, original)

    def test_timestamps_can_be_disabled(self):
        result = subprocess.run([sys.executable, str(SCRIPT), "--no-timestamps"],
                                input="hello\n", text=True, capture_output=True, check=True)
        self.assertEqual(result.stdout, "hello\n")

    def test_empty_stream_is_empty(self):
        result = subprocess.run([sys.executable, str(SCRIPT)],
                                input="", text=True, capture_output=True, check=True)
        self.assertEqual(result.stdout, "")


if __name__ == "__main__":
    unittest.main()
