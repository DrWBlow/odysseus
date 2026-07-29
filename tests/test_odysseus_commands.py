import os
import shutil
import subprocess
import time
from pathlib import Path


def make_repo(tmp_path: Path) -> tuple[Path, dict[str, str]]:
    root = Path(__file__).resolve().parents[1]
    repo = tmp_path / "repository with spaces"
    repo.mkdir()
    for name in ("odysseus.command", "odysseus-stop.command"):
        shutil.copy2(root / name, repo / name)
    (repo / "start-macos.sh").write_text(
        """#!/bin/bash
printf '%s\\n' "$$" >> "$FAKE_LAUNCHES"
if [ "$FAKE_MODE" = fail ]; then exit 23; fi
sleep 300 &
child=$!
trap 'kill "$child" 2>/dev/null; wait "$child" 2>/dev/null; exit 0' TERM
wait "$child"
"""
    )
    (repo / "start-macos.sh").chmod(0o755)
    env = os.environ | {"FAKE_LAUNCHES": str(repo / "launches"), "FAKE_MODE": "run"}
    return repo, env


def run(repo: Path, name: str, env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run([str(repo / name)], cwd=repo.parent, env=env, text=True, capture_output=True, timeout=12)


def wait_for_exit(pid: int) -> None:
    for _ in range(50):
        if subprocess.run(["/bin/ps", "-p", str(pid)], capture_output=True).returncode:
            return
        time.sleep(0.1)


def test_immediate_failure(tmp_path: Path) -> None:
    repo, env = make_repo(tmp_path)
    env["FAKE_MODE"] = "fail"
    result = run(repo, "odysseus.command", env)
    assert result.returncode and "exited during startup" in result.stderr
    assert not (repo / "logs" / "odysseus.pid").exists()


def test_duplicate_start_and_normal_stop(tmp_path: Path) -> None:
    repo, env = make_repo(tmp_path)
    assert run(repo, "odysseus.command", env).returncode == 0
    pid = int((repo / "logs" / "odysseus.pid").read_text())
    try:
        second = run(repo, "odysseus.command", env)
        assert second.returncode == 0 and "already starting or running" in second.stdout
        assert (repo / "launches").read_text().splitlines() == [str(pid)]
        assert run(repo, "odysseus-stop.command", env).returncode == 0
        assert not (repo / "logs" / "odysseus.pid").exists()
        wait_for_exit(pid)
    finally:
        if subprocess.run(["/bin/ps", "-p", str(pid)], capture_output=True).returncode == 0:
            os.kill(pid, 15)


def test_stop_refuses_unrelated_pid(tmp_path: Path) -> None:
    repo, env = make_repo(tmp_path)
    unrelated = subprocess.Popen(["sleep", "30"])
    try:
        logs = repo / "logs"
        logs.mkdir()
        (logs / "odysseus.pid").write_text(f"{unrelated.pid}\n")
        result = run(repo, "odysseus-stop.command", env)
        assert result.returncode and "unverified live PID" in result.stderr
        assert unrelated.poll() is None
    finally:
        unrelated.terminate()
        unrelated.wait(timeout=5)
