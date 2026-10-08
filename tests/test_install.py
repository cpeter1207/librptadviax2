#!/usr/bin/env python3
"""Staged shared-object installation contract checks."""

import pathlib
import subprocess
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]


class InstallTests(unittest.TestCase):
    def test_install_check_stages_runtime_and_development_abi(self):
        subprocess.run(["make", "install-check"], cwd=ROOT, check=True)


if __name__ == "__main__":
    unittest.main()
