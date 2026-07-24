from __future__ import annotations

from pathlib import Path

from coquic_steward.control_loop import ControlLoopArchive, ControlLoopLedger
from coquic_steward.core.config import StewardConfig
from coquic_steward.storage import TaskStore


def test_runtime_has_raw_archive_peers(config: StewardConfig) -> None:
    config.ensure_dirs()
    assert config.tasks_dir.parent == config.control_loop_dir.parent
    assert config.control_loop_dir.name == "control-loop"
    assert config.tasks_dir.name == "tasks"


def test_store_initializes_private_control_loop_ledger(config: StewardConfig) -> None:
    store = TaskStore(config.db_path)
    assert isinstance(store.control_loop_ledger, ControlLoopLedger)
    assert store.control_loop_ledger.epoch_id == config.ensure_epoch()["epochId"]


def test_archive_rejects_symlink_root(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.mkdir()
    root = tmp_path / "control-loop"
    root.symlink_to(target, target_is_directory=True)
    try:
        ControlLoopArchive(root)
    except ValueError:
        pass
    except RuntimeError:
        pass
    else:
        raise AssertionError("symlink archive root was accepted")
