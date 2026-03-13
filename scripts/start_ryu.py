#!/usr/bin/env python3
"""Start a compatible Ryu or OS-Ken controller for Sentinel.

Search order:
1. repo-local .venv-controller manager binaries
2. repo-local .venv manager binaries
3. system manager binaries on PATH
4. python -m fallbacks

If an OS-Ken source tree is present, it is injected into PYTHONPATH so patched
apps restored from source can be imported.
"""

from __future__ import annotations

import os
import shutil
import sys
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class ControllerRuntime:
    label: str
    argv: list[str]
    family: str


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _prepend_pythonpath(env: dict[str, str], path: Path) -> None:
    current = env.get("PYTHONPATH", "")
    env["PYTHONPATH"] = str(path) if not current else f"{path}:{current}"


def _osken_source_candidates(repo_root: Path) -> list[Path]:
    candidates: list[Path] = []
    env_path = os.environ.get("SENTINEL_OSKEN_SOURCE", "").strip()
    if env_path:
        candidates.append(Path(env_path).expanduser())
    candidates.append((Path.home() / "os-ken-source").expanduser())
    candidates.append(repo_root / "os-ken-source")
    return candidates


def _detect_osken_source(repo_root: Path) -> Path | None:
    for candidate in _osken_source_candidates(repo_root):
        if (candidate / "os_ken").exists():
            return candidate
    return None


def _manager_candidates(repo_root: Path) -> list[ControllerRuntime]:
    candidates: list[ControllerRuntime] = []

    for env_name in (".venv-controller", ".venv"):
        bin_dir = repo_root / env_name / "bin"
        for executable, family in (("ryu-manager", "ryu"), ("osken-manager", "osken")):
            manager = bin_dir / executable
            if manager.is_file() and os.access(manager, os.X_OK):
                candidates.append(
                    ControllerRuntime(
                        label=f"repo {env_name}/{executable}",
                        argv=[str(manager)],
                        family=family,
                    )
                )

    for executable, family in (("ryu-manager", "ryu"), ("osken-manager", "osken")):
        resolved = shutil.which(executable)
        if resolved:
            candidates.append(
                ControllerRuntime(
                    label=f"system {executable}",
                    argv=[resolved],
                    family=family,
                )
            )

    candidates.append(
        ControllerRuntime(
            label="python -m ryu.cmd.manager",
            argv=[sys.executable, "-m", "ryu.cmd.manager"],
            family="ryu",
        )
    )
    candidates.append(
        ControllerRuntime(
            label="python -m os_ken.cmd.manager",
            argv=[sys.executable, "-m", "os_ken.cmd.manager"],
            family="osken",
        )
    )
    return candidates


def _controller_apps(family: str) -> list[str]:
    if family == "ryu":
        return ["ryu.app.simple_switch_13", "ryu.app.ofctl_rest"]
    return ["os_ken.app.simple_switch_13", "os_ken.app.ofctl_rest"]


def main() -> int:
    repo_root = _repo_root()
    runtime = _manager_candidates(repo_root)[0]
    env = os.environ.copy()

    if runtime.family == "osken":
        source_path = _detect_osken_source(repo_root)
        if source_path is None:
            print("[WARN] No patched OS-Ken source tree found. Continuing with installed OS-Ken runtime.")
            print("       Set SENTINEL_OSKEN_SOURCE if your patched source lives outside ~/os-ken-source.")
        else:
            _prepend_pythonpath(env, source_path)
            print(f"[INFO] Using OS-Ken source tree: {source_path}")

    argv = runtime.argv + _controller_apps(runtime.family)
    print(f"[INFO] Starting controller via {runtime.label}")
    print(f"[INFO] Loading apps: {argv[len(runtime.argv):]}")

    try:
        os.execvpe(argv[0], argv, env)
    except FileNotFoundError:
        print("[ERROR] No supported controller runtime was found.")
        print("        Install Ryu/OS-Ken system-wide or in .venv-controller/.venv.")
        return 1
    except Exception as exc:
        print(f"[ERROR] Failed to start controller: {exc}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
