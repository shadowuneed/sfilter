from __future__ import annotations

import shutil
import subprocess
import unittest
from pathlib import Path


class FrontendHardStopTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which("node"), "Node.js is required for frontend behavioral tests")
    def test_hard_stop_browser_behaviors(self) -> None:
        result = subprocess.run(
            [shutil.which("node"), "--test", str(Path(__file__).with_name("frontend_hard_stop.js"))],
            capture_output=True,
            text=True,
            encoding="utf-8",
            timeout=20,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
