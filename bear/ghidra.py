"""Persistent, exclusively locked Ghidra projects shared by all inspection modes."""

import fcntl
import hashlib
import json
import os
import shlex
import shutil
import time
import uuid
from pathlib import Path
from typing import Callable, Literal

from bear.models import GhidraRequest


class DisassembleRequest(GhidraRequest):
    backend: Literal["auto", "ghidra", "objdump"] = "auto"


def build_command(headless: str, binary: str, project: Path, reuse: bool,
                  script_name: str, script_args: list[str]) -> str:
    script_dir = Path(__file__).with_name("ghidra_scripts")
    if not (script_dir / script_name).is_file():
        raise ValueError(f"Ghidra script not found: {script_name}")
    # Shell quoting does not stop analyzeHeadless from interpreting script args
    # as its own options. Do not allow a target to become -deleteProject, etc.
    if any(arg.lstrip().startswith("-") or "\0" in arg for arg in script_args):
        raise ValueError("Ghidra script arguments cannot start with '-' or contain NUL")
    argv = [headless, str(project), "bear_project"]
    argv += ["-process", "-noanalysis"] if reuse else ["-import", binary]
    argv += ["-scriptPath", str(script_dir), "-postScript", script_name, *script_args]
    return shlex.join(argv)


def fingerprint(path: Path, check_cancelled: Callable[[], None]) -> dict:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        before = os.fstat(source.fileno())
        while chunk := source.read(1024 * 1024):
            check_cancelled()
            digest.update(chunk)
        after = os.fstat(source.fileno())
    fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
    if any(getattr(before, field) != getattr(after, field) for field in fields):
        raise ValueError(f"File changed while fingerprinting: {path}")
    return {"sha256": digest.hexdigest(), **{field: getattr(after, field) for field in fields}}


def run_project(binary: str, headless: str, operation: Callable[[Path, bool], dict],
                check_cancelled: Callable[[], None], progress: Callable[..., None]) -> dict:
    """Hold an OS lock through execution, parsing, and readiness publication.

    Each attempt without a ready project gets a UUID directory. A killed JVM
    cannot poison a subsequent import, even if executor cleanup was interrupted.
    Lock files are permanent: unlinking them would let waiters lock different inodes.
    """
    binary_path = Path(binary).resolve()
    if not binary_path.is_file():
        raise ValueError(f"Binary not found: {binary}")
    headless_path = Path(headless).resolve()
    # Ghidra rejects hidden components anywhere in a project path, so BEAR's
    # usual .bear_cache (or ~/.cache) cannot hold these projects.
    root = Path(os.environ.get("BEAR_GHIDRA_PROJECT_DIR",
                               f"/var/tmp/bear_ghidra_projects_{os.getuid()}")).expanduser().resolve()
    if any(part.startswith(".") for part in root.parts):
        raise ValueError("BEAR_GHIDRA_PROJECT_DIR must not contain hidden path components")
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    key = hashlib.sha256(os.fsencode(binary_path)).hexdigest()
    bucket = root / key
    bucket.mkdir(parents=True, exist_ok=True)
    progress(stage="waiting_for_project", binary=binary)
    with (bucket / "project.lock").open("a+b") as lock:
        while True:
            check_cancelled()
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                time.sleep(0.05)
        check_cancelled()
        progress(stage="fingerprinting", binary=binary)
        identity = {"path": str(headless_path), "launcher": fingerprint(headless_path, check_cancelled)}
        properties = headless_path.parent.parent / "Ghidra" / "application.properties"
        if properties.is_file():
            identity["application"] = fingerprint(properties, check_cancelled)
        expected = {"schema": 1, "binary": fingerprint(binary_path, check_cancelled), "ghidra": identity}
        ready = bucket / "ready.json"
        try:
            saved = json.loads(ready.read_text())
        except (FileNotFoundError, ValueError):
            saved = {}
        generation = saved.get("generation", "") if isinstance(saved, dict) else ""
        valid_generation = (isinstance(generation, str) and len(generation) == 32
                            and all(c in "0123456789abcdef" for c in generation))
        project = bucket / ("project-" + generation) if valid_generation else bucket
        reuse = (valid_generation and saved.get("fingerprint") == expected
                 and (project / "bear_project.gpr").is_file()
                 and (project / "bear_project.rep").is_dir())
        # Even a reused project may be modified by headless. A crash or exception
        # must leave it unready, not silently reusable by the next request.
        ready.unlink(missing_ok=True)
        if not reuse:
            generation = uuid.uuid4().hex
            project = bucket / ("project-" + generation)
            project.mkdir()
        committed = False
        try:
            check_cancelled()
            progress(stage="processing" if reuse else "analyzing", project_reused=reuse)
            result = operation(project, reuse)
            check_cancelled()
            if not result.get("success"):
                return result
            if (fingerprint(binary_path, check_cancelled) != expected["binary"]
                    or fingerprint(headless_path, check_cancelled) != identity["launcher"]
                    or ("application" in identity
                        and fingerprint(properties, check_cancelled) != identity["application"])):
                return {"success": False, "error": "Binary or Ghidra installation changed during analysis"}
            if not ((project / "bear_project.gpr").is_file() and (project / "bear_project.rep").is_dir()):
                return {"success": False, "error": "Ghidra did not save an analyzed project", "details": result}
            temporary = bucket / "ready.tmp"
            temporary.write_text(json.dumps({"fingerprint": expected, "generation": generation}))
            temporary.replace(ready)
            committed = True
            progress(stage="completed", project_reused=reuse)
            return result
        finally:
            if not committed:
                shutil.rmtree(project, ignore_errors=True)
