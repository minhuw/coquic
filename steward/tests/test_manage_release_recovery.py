from __future__ import annotations

from pathlib import Path
import subprocess


def test_fake_selector_interruption_matrix_and_negative_cases() -> None:
    repository = Path(__file__).resolve().parents[2]
    result = subprocess.run(
        ["bash", "steward/containers/test-manage.sh", "--lifecycle"],
        cwd=repository,
        check=False,
        capture_output=True,
        text=True,
        timeout=180,
    )

    assert result.returncode == 0, result.stdout + result.stderr
    assert "management smoke test passed (--lifecycle" in result.stdout
