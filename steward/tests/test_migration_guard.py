from __future__ import annotations

import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
GUARD = ROOT / "scripts" / "check-steward-migration.py"


def test_migration_guard_passes_and_exercises_negative_fixtures() -> None:
    subprocess.run([sys.executable, str(GUARD), "--self-test"], cwd=ROOT, check=True)
    subprocess.run([sys.executable, str(GUARD)], cwd=ROOT, check=True)
