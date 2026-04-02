#!/usr/bin/env python3
"""Tests for the lines2file program."""

import os
import signal
import subprocess
import tempfile
import time
import unittest

# Path to the binary, relative to this test file's directory.
BINARY = os.path.join(os.path.dirname(os.path.abspath(__file__)), "lines2file")


class Lines2FileTest(unittest.TestCase):
    """Test suite for lines2file."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp(prefix="lines2file_test_")
        self.outpath = os.path.join(self.tmpdir, "output.txt")

    def tearDown(self):
        # Clean up temp files.
        for name in os.listdir(self.tmpdir):
            os.unlink(os.path.join(self.tmpdir, name))
        os.rmdir(self.tmpdir)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _start(self):
        """Start lines2file with a pipe on stdin; stderr passes through."""
        proc = subprocess.Popen(
            [BINARY, self.outpath],
            stdin=subprocess.PIPE,
            stdout=subprocess.DEVNULL,
        )
        # Give it a moment to open the output file.
        time.sleep(0.05)
        return proc

    def _read_output(self):
        with open(self.outpath, "r") as f:
            return f.read()

    # ------------------------------------------------------------------
    # Tests
    # ------------------------------------------------------------------

    def test_basic_passthrough(self):
        """Lines written to stdin appear in the output file."""
        proc = self._start()
        proc.stdin.write(b"hello\nworld\n")
        proc.stdin.close()
        proc.wait(timeout=5)
        self.assertEqual(proc.returncode, 0)
        self.assertEqual(self._read_output(), "hello\nworld\n")

    def test_empty_input(self):
        """EOF with no data produces an empty (or missing) output file."""
        proc = self._start()
        proc.stdin.close()
        proc.wait(timeout=5)
        self.assertEqual(proc.returncode, 0)
        self.assertEqual(self._read_output(), "")

    def test_sigterm_exits_cleanly(self):
        """SIGTERM causes a clean exit."""
        proc = self._start()
        proc.stdin.write(b"line1\n")
        proc.stdin.flush()
        time.sleep(0.1)
        proc.send_signal(signal.SIGTERM)
        proc.wait(timeout=5)
        proc.stdin.close()
        self.assertEqual(proc.returncode, 0)
        self.assertEqual(self._read_output(), "line1\n")

    def test_sigint_exits_cleanly(self):
        """SIGINT causes a clean exit."""
        proc = self._start()
        proc.stdin.write(b"line1\n")
        proc.stdin.flush()
        time.sleep(0.1)
        proc.send_signal(signal.SIGINT)
        proc.wait(timeout=5)
        proc.stdin.close()
        self.assertEqual(proc.returncode, 0)
        self.assertEqual(self._read_output(), "line1\n")

    def test_sigterm_finishes_line(self):
        """SIGTERM while mid-line: the line is completed before exiting."""
        proc = self._start()
        # Write a partial line (no newline yet).
        proc.stdin.write(b"partial")
        proc.stdin.flush()
        time.sleep(0.1)
        # Send SIGTERM — the process should keep reading to finish the line.
        proc.send_signal(signal.SIGTERM)
        time.sleep(0.1)
        # Now complete the line.
        proc.stdin.write(b"-done\n")
        proc.stdin.flush()
        proc.stdin.close()
        proc.wait(timeout=5)
        self.assertEqual(proc.returncode, 0)
        self.assertEqual(self._read_output(), "partial-done\n")

    def test_sigusr1_reopens_file(self):
        """SIGUSR1 causes the output file to be closed and reopened."""
        proc = self._start()
        proc.stdin.write(b"before\n")
        proc.stdin.flush()
        time.sleep(0.1)

        # Rename the output file; after reopen, new data goes to the
        # original path (a new file).
        renamed = self.outpath + ".old"
        os.rename(self.outpath, renamed)

        proc.send_signal(signal.SIGUSR1)
        time.sleep(0.2)

        proc.stdin.write(b"after\n")
        proc.stdin.flush()
        time.sleep(0.1)

        proc.stdin.close()
        proc.wait(timeout=5)
        self.assertEqual(proc.returncode, 0)

        # The old file should have the first line.
        with open(renamed, "r") as f:
            self.assertEqual(f.read(), "before\n")
        # The new file should have the second line.
        self.assertEqual(self._read_output(), "after\n")

    def test_sighup_reopens_file(self):
        """SIGHUP also causes a reopen (same as SIGUSR1)."""
        proc = self._start()
        proc.stdin.write(b"before\n")
        proc.stdin.flush()
        time.sleep(0.1)

        renamed = self.outpath + ".old"
        os.rename(self.outpath, renamed)

        proc.send_signal(signal.SIGHUP)
        time.sleep(0.2)

        proc.stdin.write(b"after\n")
        proc.stdin.flush()
        time.sleep(0.1)

        proc.stdin.close()
        proc.wait(timeout=5)
        self.assertEqual(proc.returncode, 0)

        with open(renamed, "r") as f:
            self.assertEqual(f.read(), "before\n")
        self.assertEqual(self._read_output(), "after\n")

    def test_sigusr1_finishes_line_before_reopen(self):
        """SIGUSR1 mid-line: the current line is finished before reopening."""
        proc = self._start()
        # Write a partial line.
        proc.stdin.write(b"mid")
        proc.stdin.flush()
        time.sleep(0.1)

        # Rename and signal.
        renamed = self.outpath + ".old"
        os.rename(self.outpath, renamed)
        proc.send_signal(signal.SIGUSR1)
        time.sleep(0.1)

        # Finish the line.
        proc.stdin.write(b"dle\n")
        proc.stdin.flush()
        time.sleep(0.2)

        # Write another line (should go to the new file).
        proc.stdin.write(b"new-file\n")
        proc.stdin.flush()
        time.sleep(0.1)

        proc.stdin.close()
        proc.wait(timeout=5)
        self.assertEqual(proc.returncode, 0)

        with open(renamed, "r") as f:
            self.assertEqual(f.read(), "middle\n")
        self.assertEqual(self._read_output(), "new-file\n")

    def test_multiple_lines(self):
        """Multiple lines are all written correctly."""
        lines = [f"line-{i}\n" for i in range(100)]
        proc = self._start()
        proc.stdin.write("".join(lines).encode())
        proc.stdin.close()
        proc.wait(timeout=5)
        self.assertEqual(proc.returncode, 0)
        self.assertEqual(self._read_output(), "".join(lines))

    def test_no_args_fails(self):
        """Running without arguments prints help to stderr and exits nonzero."""
        proc = subprocess.Popen(
            [BINARY],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
        )
        _, err = proc.communicate(timeout=5)
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn(b"Usage", err)
        self.assertIn(b"SIGUSR1", err)

    def test_help_flag(self):
        """--help prints help to stdout and exits zero."""
        for flag in ("-h", "--help"):
            proc = subprocess.Popen(
                [BINARY, flag],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
            )
            out, _ = proc.communicate(timeout=5)
            self.assertEqual(proc.returncode, 0, f"flag={flag}")
            self.assertIn(b"Usage", out)
            self.assertIn(b"SIGUSR1", out)

    def test_append_mode(self):
        """Output file is opened in append mode."""
        # Pre-populate the file.
        with open(self.outpath, "w") as f:
            f.write("existing\n")

        proc = self._start()
        proc.stdin.write(b"appended\n")
        proc.stdin.close()
        proc.wait(timeout=5)
        self.assertEqual(proc.returncode, 0)
        self.assertEqual(self._read_output(), "existing\nappended\n")


if __name__ == "__main__":
    unittest.main()