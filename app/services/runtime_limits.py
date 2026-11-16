"""Adapt optional scan features to a known, local container memory limit."""
from __future__ import annotations

from dataclasses import replace
from pathlib import Path

from app.config import Settings


_MIB = 1024 * 1024
_LOW_MEMORY_LIMIT = 768 * _MIB
_CGROUP_V2_PATH = Path("/sys/fs/cgroup/memory.max")
_CGROUP_V1_PATH = Path("/sys/fs/cgroup/memory/memory.limit_in_bytes")
# The v1 kernel commonly reports an effectively unlimited, page-rounded value
# near LONG_MAX. Such values are not a meaningful, provisioned memory budget.
_V1_UNLIMITED_FLOOR = 1 << 60


def _memory_limit_bytes(v2_path: Path, v1_path: Path) -> int | None:
    for path, is_v1 in ((v2_path, False), (v1_path, True)):
        try:
            value = Path(path).read_text(encoding="ascii").strip()
        except OSError:
            continue
        except UnicodeError:
            return None
        # An existing v2 controller is authoritative, including its unlimited
        # or unknown value. Do not combine unrelated v1 and v2 hierarchies.
        if not value.isdecimal():
            return None
        try:
            limit = int(value)
        except ValueError:
            return None
        if is_v1 and limit >= _V1_UNLIMITED_FLOOR:
            return None
        return limit
    return None


def apply_runtime_limits(
    settings: Settings,
    *,
    _cgroup_v2_path: Path = _CGROUP_V2_PATH,
    _cgroup_v1_path: Path = _CGROUP_V1_PATH,
) -> tuple[Settings, dict[str, bool | int | None]]:
    """Read cgroup files only; preserve configured settings for unknown limits.

    The health field uses integral MiB, while the threshold comparison uses
    exact bytes. A new frozen Settings instance is returned only in low-memory
    mode. Private path overrides make detection testable without host probes.
    """
    limit = _memory_limit_bytes(_cgroup_v2_path, _cgroup_v1_path)
    low_memory = limit is not None and limit <= _LOW_MEMORY_LIMIT
    info = {
        "low_memory_mode": low_memory,
        "container_memory_limit_mb": limit // _MIB if limit is not None else None,
    }
    if not low_memory:
        return settings, info
    return replace(
        settings,
        scan_concurrency=1,
        screenshot_concurrency=1,
        # A cold Chromium launch on the small shared-CPU plan needs more than
        # the normal ten seconds, while capture and hard stop stay bounded.
        screenshot_timeout_seconds=max(45, settings.screenshot_timeout_seconds),
    ), info
