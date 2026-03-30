#!/usr/bin/env python3
"""Start a compatible Ryu or OS-Ken controller for Sentinel.

Search order:
1. repo-local OS-Ken compatibility launcher (preferred)
2. repo-local .venv-controller manager binaries
3. repo-local .venv manager binaries
4. system manager binaries on PATH
5. python -m fallbacks

If an OS-Ken source tree is present, it is injected into PYTHONPATH so patched
apps restored from source can be imported.
"""

from __future__ import annotations

import os
import shutil
import sys
import subprocess
import importlib.util
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
    env["PYTHONPATH"] = str(path) if not current else f"{path}{os.pathsep}{current}"


def _python_candidates(env_root: Path) -> list[Path]:
    candidates: list[Path]
    if os.name == "nt":
        candidates = [
            env_root / "Scripts" / "python.exe",
            env_root / "Scripts" / "python",
        ]
    else:
        candidates = [
            env_root / "bin" / "python3",
            env_root / "bin" / "python",
        ]
    return [candidate for candidate in candidates if candidate.is_file() and os.access(candidate, os.X_OK)]


def _manager_binary_candidates(env_root: Path, executable: str) -> list[Path]:
    if os.name == "nt":
        candidates = [
            env_root / "Scripts" / executable,
            env_root / "Scripts" / f"{executable}.exe",
        ]
    else:
        candidates = [
            env_root / "bin" / executable,
        ]
    return [candidate for candidate in candidates if candidate.is_file() and os.access(candidate, os.X_OK)]


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
    source_path = _detect_osken_source(repo_root)

    if source_path is not None and (source_path / "os_ken" / "cmd" / "manager.py").is_file():
        candidates.append(
            ControllerRuntime(
                label="current interpreter -m os_ken.cmd.manager (source tree)",
                argv=[sys.executable, "-m", "os_ken.cmd.manager"],
                family="osken",
            )
        )

    # Fallback compatibility launcher for environments where the real manager is unavailable.
    compat_launcher = repo_root / "scripts" / "osken_manager_compat.py"
    if compat_launcher.is_file():
        candidates.append(
            ControllerRuntime(
                label="current interpreter osken_manager_compat.py",
                argv=[sys.executable, str(compat_launcher)],
                family="osken",
            )
        )
        for env_name in (".venv-sdn", ".venv-wsl", ".venv-controller", ".venv"):
            for py_bin in _python_candidates(repo_root / env_name):
                candidates.append(
                    ControllerRuntime(
                        label=f"repo {env_name}/osken_manager_compat.py",
                        argv=[str(py_bin), str(compat_launcher)],
                        family="osken",
                    )
                )

    # 2. Module fallbacks for the current interpreter (if it already has ryu/os_ken)
    for module_pkg, family in (("os_ken", "osken"), ("ryu", "ryu")):
        try:
            # We use a primitive check to avoid triggering the parent package's __init__
            # if it's broken or tries to import missing submodules.
            if importlib.util.find_spec(module_pkg) is not None:
                candidates.append(
                    ControllerRuntime(
                        label=f"current interpreter -m {module_pkg}.cmd.manager",
                        argv=[sys.executable, "-m", f"{module_pkg}.cmd.manager"],
                        family=family,
                    )
                )
        except Exception:
            pass

    # 3. Virtualenv-binaries
    for env_name in (".venv-sdn", ".venv-wsl", ".venv-controller", ".venv"):
        for executable, family in (("ryu-manager", "ryu"), ("osken-manager", "osken")):
            for manager in _manager_binary_candidates(repo_root / env_name, executable):
                candidates.append(
                    ControllerRuntime(
                        label=f"repo {env_name}/{manager.name}",
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


def _controller_apps(family: str, repo_root: Path) -> list[str]:
    local_sdn_dir = repo_root / "scripts" / "sdn_apps"
    apps = []
    upstream_root = "ryu" if family == "ryu" else "os_ken"
    upstream_switch = f"{upstream_root}.app.simple_switch_13"
    upstream_rest = f"{upstream_root}.app.ofctl_rest"

    if (local_sdn_dir / "simple_switch_13.py").is_file():
        apps.append("scripts.sdn_apps.simple_switch_13")
    elif importlib.util.find_spec(upstream_switch) is not None:
        apps.append(upstream_switch)
    else:
        raise RuntimeError(f"Unable to locate a real {upstream_switch} controller app.")

    if (local_sdn_dir / "ofctl_rest.py").is_file():
        apps.append("scripts.sdn_apps.ofctl_rest")
    elif importlib.util.find_spec(upstream_rest) is not None:
        apps.append(upstream_rest)
    else:
        raise RuntimeError(f"Unable to locate a real {upstream_rest} REST app.")

    return apps


def _runtime_supported(runtime: ControllerRuntime) -> bool:
    """Return True when a runtime candidate is likely runnable in this env."""
    # Binary managers were already existence-checked in _manager_candidates().
    if len(runtime.argv) >= 3 and runtime.argv[1] == "-m":
        module_name = runtime.argv[2]
        try:
            spec = importlib.util.find_spec(module_name)
        except Exception:
            spec = None
        if spec is not None:
            return True
        if module_name.startswith("os_ken."):
            source_path = _detect_osken_source(_repo_root())
            if source_path is None:
                return False
            relative = Path(*module_name.split(".")).with_suffix(".py")
            return (source_path / relative).is_file()
        return False
    return True


def main() -> int:
    repo_root = _repo_root()
    source_path = _detect_osken_source(repo_root)
    runtime: ControllerRuntime | None = None
    extra_args = sys.argv[1:]

    # Logic:
    # 1. If on Python 3.13+, we MUST use the compatibility launcher to avoid eventlet crashes.
    # 2. Otherwise, prefer the source-tree manager if available.
    # 3. Fall back to candidates list.

    if sys.version_info >= (3, 13) and (repo_root / "scripts" / "osken_manager_compat.py").is_file():
        runtime = ControllerRuntime(
            label="current interpreter osken_manager_compat.py (Python 3.13+ Fix)",
            argv=[sys.executable, str(repo_root / "scripts" / "osken_manager_compat.py")],
            family="osken",
        )
        print(f"[INFO] Python 3.13+ detected — forcing compatibility launcher: {runtime.label}")
    elif source_path is not None and (source_path / "os_ken" / "cmd" / "manager.py").is_file():
        runtime = ControllerRuntime(
            label="current interpreter -m os_ken.cmd.manager (source tree)",
            argv=[sys.executable, "-m", "os_ken.cmd.manager"],
            family="osken",
        )
        print(f"[DEBUG] Using source-tree controller runtime: {runtime.label}")

    runtimes = _manager_candidates(repo_root)
    print(f"[DEBUG] Found {len(runtimes)} candidates")
    if runtime is None:
        for r in runtimes:
            print(f"[DEBUG] Checking candidate: {r.label} (argv: {r.argv})")
            if _runtime_supported(r):
                runtime = r
                print(f"[DEBUG] -> Accepted: {r.label}")
                break
            else:
                print(f"[DEBUG] -> Rejected (not supported in this env)")
    
    if runtime is None:
        print("[ERROR] No supported controller runtime was found.")
        print("        Install Ryu/OS-Ken system-wide or in .venv-controller/.venv.")
        return 1
    env = os.environ.copy()

    if runtime.family == "osken":
        if source_path is None:
            print("[WARN] No patched OS-Ken source tree found. Continuing with installed OS-Ken runtime.")
            print("       Set SENTINEL_OSKEN_SOURCE if your patched source lives outside ~/os-ken-source.")
        else:
            _prepend_pythonpath(env, source_path)
            print(f"[INFO] Using OS-Ken source tree: {source_path}")

    argv = runtime.argv + extra_args + _controller_apps(runtime.family, repo_root)
    print(f"[INFO] Starting controller via {runtime.label}")
    print(f"[INFO] Extra controller args: {extra_args}")
    print(f"[INFO] Loading apps: {argv[len(runtime.argv) + len(extra_args):]}")

    try:
        completed = subprocess.run(argv, env=env, check=False)
        return completed.returncode
    except FileNotFoundError:
        print("[ERROR] No supported controller runtime was found.")
        print("        Install Ryu/OS-Ken system-wide or in .venv-controller/.venv.")
        return 1
    except Exception as exc:
        print(f"[ERROR] Failed to start controller: {exc}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
