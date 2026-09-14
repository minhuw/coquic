"""Daemon NSS bind files: exercise the management helper without Docker."""
import os
from pathlib import Path
import stat
import subprocess
import sys

import pytest


MANAGE = Path(__file__).resolve().parents[1] / "containers/manage.sh"
FUNCTIONS = MANAGE.read_text().split('command="${1:-}"', 1)[0]
IDENTITY = FUNCTIONS.split("<<'PY_IDENTITY'", 1)[1].split("\n", 1)[1].split("\nPY_IDENTITY", 1)[0]


def run_helper(home, **overrides):
    env = {
        **os.environ,
        "COQUIC_HOME": str(home),
        "STEWARD_UID": str(os.getuid()),
        "STEWARD_GID": str(os.getgid()),
        "STEWARD_DOCKER_GID": str(os.getgid()),
        **overrides,
    }
    return subprocess.run(
        ["bash", "-c", "source /dev/stdin"],
        input=FUNCTIONS + "\nrequire_paths; with_lock; prepare_daemon_identity",
        env=env, text=True, capture_output=True,
    )


@pytest.fixture
def home(tmp_path):
    path = tmp_path / "home"
    (path / "private").mkdir(parents=True, mode=0o700)
    return path


@pytest.mark.parametrize("uid,gid,docker_gid", [(1000, 1000, 988), (12345, 23456, 34567), (12345, 23456, 23456)])
def test_identity_records(home, monkeypatch, uid, gid, docker_gid):
    # Simulate ownership only: these configured users need not exist on the test host.
    fstat = os.fstat

    def configured_owner(fd):
        values = list(fstat(fd))
        values[4] = uid
        return os.stat_result(values)

    monkeypatch.setattr(os, "fstat", configured_owner)
    monkeypatch.setattr(os, "fchown", lambda fd, owner, group: None)
    monkeypatch.setattr(sys, "argv", ["identity", str(home), str(uid), str(gid), str(docker_gid)])
    exec(compile(IDENTITY, str(MANAGE), "exec"), {})
    runtime = home / "private/runtime"
    assert (runtime / "daemon-passwd").read_text() == (
        f"root:x:0:0:root:/root:/bin/bash\nsteward:x:{uid}:{gid}:Steward:/tmp:/bin/bash\n"
    )
    expected = f"root:x:0:\nsteward:x:{gid}:steward\n"
    if docker_gid != gid:
        expected += f"docker:x:{docker_gid}:steward\n"
    assert (runtime / "daemon-group").read_text() == expected


def test_identity_private_atomic_and_idempotent(home):
    result = run_helper(home)
    assert result.returncode == 0, result.stderr
    runtime = home / "private/runtime"
    paths = [runtime / "daemon-passwd", runtime / "daemon-group"]
    before = [path.stat() for path in paths]
    assert all(stat.S_IMODE(info.st_mode) == 0o600 and info.st_uid == os.getuid() for info in before)
    assert run_helper(home).returncode == 0
    assert [(path.stat().st_ino, path.stat().st_mtime_ns, path.stat().st_ctime_ns) for path in paths] == [
        (info.st_ino, info.st_mtime_ns, info.st_ctime_ns) for info in before
    ]
    # Keep the old inode open, as a running bind mount would, during replacement.
    with paths[0].open("rb") as old:
        paths[0].write_text("outdated\n")
        assert run_helper(home).returncode == 0
        assert old.read() == b"outdated\n"
        assert paths[0].stat().st_ino != before[0].st_ino
    assert sorted(path.name for path in runtime.iterdir()) == ["daemon-group", "daemon-passwd"]


@pytest.mark.parametrize("name", ["STEWARD_UID", "STEWARD_GID", "STEWARD_DOCKER_GID"])
@pytest.mark.parametrize("value", ["", "0", "00", "01000", "-1", "4294967295", "99999999999999999999999", "1:2", "1\nroot:x:0", "../1000", "1/2"])
def test_identity_rejects_invalid_ids(home, name, value):
    result = run_helper(home, **{name: value})
    assert result.returncode != 0
    assert "canonical non-root ID" in result.stderr
    assert not (home / "private/runtime").exists()


@pytest.mark.parametrize("unsafe", ["symlink", "directory", "fifo", "hardlink", "public", "special-mode"])
def test_identity_rejects_unsafe_file(home, unsafe):
    assert run_helper(home).returncode == 0
    path = home / "private/runtime/daemon-group"
    passwd = home / "private/runtime/daemon-passwd"
    before = passwd.stat()
    if unsafe in {"symlink", "directory", "fifo", "hardlink"}:
        path.unlink()
        if unsafe == "symlink":
            path.symlink_to(passwd)
        elif unsafe == "directory":
            path.mkdir()
        elif unsafe == "fifo":
            os.mkfifo(path)
        else:
            os.link(passwd, path)
    else:
        path.chmod(0o644 if unsafe == "public" else 0o4600)
    result = run_helper(home)
    assert result.returncode != 0
    assert passwd.stat().st_ino == before.st_ino
    assert passwd.stat().st_mtime_ns == before.st_mtime_ns


@pytest.mark.parametrize("component", ["home", "private", "runtime", "ancestor"])
def test_identity_rejects_symlink_directories(home, component):
    (home / "private/runtime").mkdir(mode=0o700)
    path = {"home": home, "private": home / "private", "runtime": home / "private/runtime", "ancestor": home.parent}[component]
    moved = path.with_name(path.name + "-real")
    path.rename(moved)
    path.symlink_to(moved, target_is_directory=True)
    assert run_helper(home).returncode != 0
    assert not (home / "private/runtime/daemon-passwd").exists()


def test_identity_requires_private_directory(home):
    (home / "private").chmod(0o755)
    assert run_helper(home).returncode != 0


def test_identity_requires_lock(home):
    result = subprocess.run(["bash", "-c", "source /dev/stdin"], input=FUNCTIONS + "\nprepare_daemon_identity", text=True, capture_output=True)
    assert result.returncode != 0
    assert "requires the lifecycle lock" in result.stderr


def test_identity_rejects_wrong_file_owner(home, monkeypatch):
    assert run_helper(home).returncode == 0
    fstat = os.fstat

    def foreign_owner(fd):
        metadata = fstat(fd)
        if stat.S_ISREG(metadata.st_mode):
            values = list(metadata)
            values[4] = os.getuid() + 1
            return os.stat_result(values)
        return metadata

    monkeypatch.setattr(os, "fstat", foreign_owner)
    monkeypatch.setattr(sys, "argv", ["identity", str(home), str(os.getuid()), str(os.getgid()), str(os.getgid())])
    with pytest.raises(ValueError, match="unsafe identity file"):
        exec(compile(IDENTITY, str(MANAGE), "exec"), {})


def test_identity_mounts_refuse_missing_sources():
    compose = (MANAGE.parent / "compose.yml").read_text()
    for name in ("passwd", "group"):
        assert f"""      - type: bind
        source: ${{COQUIC_HOME:?}}/private/runtime/daemon-{name}
        target: /etc/{name}
        read_only: true
        bind:
          create_host_path: false
""" in compose
    flake = (MANAGE.parents[2] / "flake.nix").read_text()
    closure = flake.split("stewardDaemonToolClosure = pkgs.buildEnv {", 1)[1].split("};", 1)[0]
    assert "pkgs.bash" in closure and '"/bin"' in closure
