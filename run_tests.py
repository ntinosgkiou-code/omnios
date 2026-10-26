"""Run the whole suite:  python run_tests.py   (on Windows set PYTHONUTF8=1 first; the machine's default codepage breaks Greek text)."""
import os
import sys
import unittest

os.environ.setdefault("PYTHONUTF8", "1")
here = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, here)
sys.path.insert(0, os.path.join(here, "tests"))
suite = unittest.defaultTestLoader.discover(os.path.join(here, "tests"))
res = unittest.TextTestRunner(verbosity=1).run(suite)
sys.exit(0 if res.wasSuccessful() else 1)
