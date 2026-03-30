"""Compatibility shim that loads the real Ryu/OS-Ken REST app."""

from __future__ import annotations

import importlib


def _load_upstream_rest_api():
    errors: list[str] = []

    for module_name in ("os_ken.app.ofctl_rest", "ryu.app.ofctl_rest"):
        try:
            module = importlib.import_module(module_name)
        except (ImportError, ModuleNotFoundError) as exc:  # pragma: no cover - depends on controller runtime
            missing_name = getattr(exc, "name", "") or ""
            if missing_name and missing_name not in {module_name, module_name.split(".")[0]}:
                errors.append(f"{module_name} failed because '{missing_name}' is missing")
            else:
                errors.append(f"{module_name} unavailable ({exc})")
            continue

        rest_api = getattr(module, "RestStatsApi", None)
        if rest_api is not None:
            return rest_api

        errors.append(f"{module_name} loaded without RestStatsApi")

    detail = "; ".join(errors) if errors else "no controller runtime candidates were importable"
    raise RuntimeError(
        "Sentinel requires the real OS-Ken/Ryu 'ofctl_rest' module for SDN REST support. "
        f"Import details: {detail}. No mock REST fallback is used."
    )


UpstreamRestStatsApi = _load_upstream_rest_api()

class RestStatsApi(UpstreamRestStatsApi):
    pass

__all__ = ["RestStatsApi"]
