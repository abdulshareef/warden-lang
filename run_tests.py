#!/usr/bin/env python3
"""Run the full Warden test suite. Exit code 0 only if every test passes."""
import os
import sys
import unittest

here = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, here)
sys.path.insert(0, os.path.join(here, "tests"))

if __name__ == "__main__":
    suite = unittest.defaultTestLoader.discover(os.path.join(here, "tests"), pattern="test_*.py")
    result = unittest.TextTestRunner(verbosity=1 if "-q" in sys.argv else 2, buffer=True).run(suite)
    print("\nTOTAL: %d  FAILED: %d  ERRORS: %d  SKIPPED: %d" % (
        result.testsRun, len(result.failures), len(result.errors), len(result.skipped)))
    sys.exit(0 if result.wasSuccessful() else 1)
