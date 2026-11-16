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
_MAX_CGROUP_READ_BYTES = 8192


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
        screenshot_freeze_after_render=settings.screenshot_javascript_enabled,
        # A cold Chromium launch on the small shared-CPU plan needs more than
        # the normal ten seconds, while capture and hard stop stay bounded.
        screenshot_timeout_seconds=max(90, settings.screenshot_timeout_seconds),
    ), info


def _read_bounded_cgroup(path: Path) -> str | None:
    try:
        with Path(path).open("rb") as handle:
            raw = handle.read(_MAX_CGROUP_READ_BYTES + 1)
        if len(raw) > _MAX_CGROUP_READ_BYTES:
            return None
        return raw.decode("ascii")
    except (OSError, UnicodeError):
        return None


def _nonnegative_counter(value: str | None) -> int | None:
    if value is None or not value.strip().isdecimal():
        return None
    try:
        count = int(value.strip())
    except ValueError:
        return None
    return count if count <= (1 << 64) - 1 else None


def _cgroup_counters(text: str | None, keys: tuple[str, ...]) -> dict[str, int | None]:
    values = dict.fromkeys(keys)
    seen = set()
    for line in (text or "").splitlines():
        fields = line.split()
        if not fields or fields[0] not in values:
            continue
        key = fields[0]
        if key in seen:
            values[key] = None
        else:
            values[key] = _nonnegative_counter(fields[1]) if len(fields) == 2 else None
        seen.add(key)
    return values


def read_cgroup_memory_usage(
    *,
    _memory_current_path: Path = Path("/sys/fs/cgroup/memory.current"),
    _memory_stat_path: Path = Path("/sys/fs/cgroup/memory.stat"),
    _memory_events_path: Path = Path("/sys/fs/cgroup/memory.events"),
) -> dict[str, float | int | None]:
    """Return safe aggregate v2 telemetry; unavailable values remain unknown.

    memory.current includes file cache and kernel charges, so it is not RSS.
    No process enumeration, host-memory estimate, or raw file content is exposed.
    Each source is bounded to 8 KiB. Memory values are MiB rounded to one decimal.
    """
    current = _nonnegative_counter(_read_bounded_cgroup(_memory_current_path))
    stats = _cgroup_counters(_read_bounded_cgroup(_memory_stat_path), ("anon", "file"))
    events = _cgroup_counters(_read_bounded_cgroup(_memory_events_path), ("oom_kill",))

    def mib(value: int | None) -> float | None:
        return round(value / _MIB, 1) if value is not None else None

    return {
        "container_memory_usage_mb": mib(current),
        "container_memory_anon_mb": mib(stats["anon"]),
        "container_memory_file_mb": mib(stats["file"]),
        "container_memory_oom_kill_count": events["oom_kill"],
    }
