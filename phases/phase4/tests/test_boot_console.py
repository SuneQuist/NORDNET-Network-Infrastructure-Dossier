import sys
import unittest
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from ios_console import recv_prompt


class FakeTime:
    def __init__(self):
        self.t = 0.0
    def monotonic(self):
        return self.t
    def sleep(self, secs):
        self.t += secs


class SlowBootConsole:
    def __init__(self, clock):
        self.clock = clock
        self.sent = []
        self.stage = 0
    def read_very_eager(self):
        t = self.clock.monotonic()
        if self.stage == 0:
            self.stage = 1
            return b"*Oct 31: %PLATFORM-5-SIGNATURE_VERIFIED: Image verified\r\n"
        if t > 29 and self.stage == 1:
            self.stage = 2
            return b"Would you like to enter the initial configuration dialog? [yes/no]: "
        if t > 33 and self.stage == 2 and b'no\r\n' in self.sent:
            self.stage = 3
            return b"\r\nPress RETURN to get started!\r\n"
        if t > 36 and self.stage == 3:
            self.stage = 4
            return b"\r\nRouter>"
        return b""
    def write(self, data):
        self.sent.append(data)


class BootConsoleTests(unittest.TestCase):
    def test_boot_waits_over_25_seconds_and_handles_initial_dialog(self):
        clock = FakeTime()
        con = SlowBootConsole(clock)
        with patch('ios_console.time.monotonic', clock.monotonic), \
             patch('ios_console.time.sleep', clock.sleep):
            out = recv_prompt(con, timeout=90, first_boot=True)
        self.assertIn('Router>', out)
        self.assertIn(b'no\r\n', con.sent)
        self.assertGreater(clock.t, 36)
        self.assertLess(clock.t, 90)

if __name__ == '__main__':
    unittest.main()
