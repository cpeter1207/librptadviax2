#!/usr/bin/env python3
"""Release archive creation must work in a container-owned checkout."""

import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]


class ReleaseArchiveTests(unittest.TestCase):
    def test_dist_marks_only_the_checked_out_repository_as_safe(self):
        makefile = (ROOT / "Makefile").read_text(encoding="utf-8")

        self.assertIn("git -c safe.directory=$(CURDIR) archive", makefile)


if __name__ == "__main__":
    unittest.main()
