"""Native headless-shell capture without a Playwright/Node driver."""
from __future__ import annotations

import asyncio
from dataclasses import dataclass, replace
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time

from app.config import Settings
from app.services.process_cleanup import (
    ProcessIdentity, ScreenshotProcessScope, capture_owned_tree, kill_processes, process_identity,
)


NATIVE_READINESS_WARNING = (
    "Page content readiness was not confirmed; native Chromium browser frame may be incomplete "
    "(virtual-time budget 1800 ms)"
)


@dataclass(frozen=True)
class NativeCaptureResult:
    captured: bool
    error: str | None = None
    unavailable: bool = False
    cleanup_confirmed: bool = True


def find_headless_shell(*, _package_root: Path | None = None,
                       _browser_roots: tuple[Path, ...] | None = None) -> Path | None:
    """Find the installed shell for this Playwright revision, without Node.

    Only the genuine chrome-headless-shell executable is eligible. Full Chrome
    and stale revisions are not substitutes. Rendering capability is covered by
    the opt-in real-browser smoke test, not inferred from --help output.
    """
    if _package_root is None:
        spec = importlib.util.find_spec("playwright")
        if spec is None or spec.origin is None:
            return None
        _package_root = Path(spec.origin).parent
    try:
        registry = json.loads((_package_root / "driver/package/browsers.json").read_text(encoding="utf-8"))
        revision = str(next(item["revision"] for item in registry["browsers"]
                            if item["name"] == "chromium-headless-shell"))
        if not revision.isdecimal():
            return None
    except (OSError, ValueError, KeyError, StopIteration, TypeError):
        return None
    if _browser_roots is None:
        configured = os.environ.get("PLAYWRIGHT_BROWSERS_PATH")
        if configured == "0":
            roots = (_package_root / "driver/package/.local-browsers",)
        elif configured:
            roots = (Path(configured),)
        elif sys.platform == "win32":
            local = os.environ.get("LOCALAPPDATA")
            roots = (Path(local) / "ms-playwright",) if local else ()
        elif sys.platform == "darwin":
            roots = (Path.home() / "Library/Caches/ms-playwright",)
        else:
            roots = (Path(os.environ.get("XDG_CACHE_HOME", str(Path.home() / ".cache"))) / "ms-playwright",)
    else:
        roots = _browser_roots
    executable = "chrome-headless-shell.exe" if sys.platform == "win32" else "chrome-headless-shell"
    for root in roots:
        version = Path(root) / f"chromium_headless_shell-{revision}"
        try:
            candidates = [version / executable, *sorted(version.glob(f"*/{executable}"))]
            for candidate in candidates:
                if candidate.is_file() and (os.name == "nt" or os.access(candidate, os.X_OK)):
                    return candidate.resolve()
        except OSError:
            continue
    return None


def _valid_png(path: Path) -> bool:
    try:
        from PIL import Image

        with Image.open(path) as image:
            if image.format != "PNG" or image.size != (1280, 720):
                return False
            image.verify()
        return True
    except (OSError, ValueError, SyntaxError):
        return False


async def capture_native(settings: Settings, url: str, output: Path, deadline: float,
                         process_scope: ScreenshotProcessScope, user_agent: str) -> NativeCaptureResult:
    """Capture a real viewport PNG under a caller-owned, wall-clock deadline.

    No proxy is silently bypassed. unavailable=True means no process was ever
    launched, so only that result permits a caller to select Playwright.
    The caller still confirms scope cleanup and owns semaphore/quarantine.
    """
    binary = find_headless_shell()
    if binary is None:
        return NativeCaptureResult(False, "Native Chromium headless shell is not installed", unavailable=True)
    if settings.kz_proxy_url:
        return NativeCaptureResult(False, "Native Chromium cannot use the configured proxy")
    if not (settings.screenshots_enabled and settings.browser_screenshots_enabled
            and settings.screenshot_javascript_enabled):
        return NativeCaptureResult(False, "Native Chromium is disabled by capture configuration")

    loop = asyncio.get_running_loop()
    process = None
    identity = None
    tracked: dict[tuple[int, float], ProcessIdentity] = {}
    profile = None
    temporary_png = None
    tracking_failed = False
    result = NativeCaptureResult(False, "Native Chromium capture did not complete")

    def remember() -> None:
        nonlocal tracking_failed
        try:
            process_scope.track()
            if identity is not None:
                for child in capture_owned_tree(identity):
                    tracked[child.key] = child
        except Exception:
            tracking_failed = True

    try:
        output = Path(output).resolve()
        output.parent.mkdir(parents=True, exist_ok=True)
        profile = tempfile.TemporaryDirectory(prefix="qalqan-native-")
        descriptor, name = tempfile.mkstemp(prefix=".native-", suffix=".png", dir=output.parent)
        os.close(descriptor)
        temporary_png = Path(name).resolve()
        args = [str(binary), "--headless", "--no-sandbox", "--disable-setuid-sandbox", "--ignore-certificate-errors",
                "--disable-dev-shm-usage", "--disable-gpu", "--disable-extensions",
                "--disable-background-networking", "--disable-component-update",
                "--disable-domain-reliability", "--disable-default-apps", "--disable-sync",
                "--disable-site-isolation-trials",
                "--disable-features=BackForwardCache,MediaRouter,OptimizationHints,Translate",
                "--disk-cache-size=1", "--media-cache-size=1", "--metrics-recording-only",
                "--mute-audio", "--no-first-run", "--no-zygote", "--renderer-process-limit=1",
                "--disable-blink-features=AutomationControlled", "--js-flags=--max-old-space-size=64",
                "--window-size=1280,720", "--force-device-scale-factor=1", "--lang=ru-RU",
                "--timeout=20000", "--virtual-time-budget=1800", f"--user-agent={user_agent}",
                f"--user-data-dir={profile.name}", f"--screenshot={temporary_png}", url]
        if loop.time() >= deadline:
            result = NativeCaptureResult(False, "Native Chromium wall-clock deadline exceeded")
        else:
            options = {"creationflags": subprocess.CREATE_NO_WINDOW} if os.name == "nt" else {}
            process = subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                       stderr=subprocess.DEVNULL, shell=False, **options)
            identity = process_identity(process.pid)
            while process.poll() is None:
                remember()
                remaining = deadline - loop.time()
                if remaining <= 0:
                    break
                await asyncio.sleep(min(0.05, remaining))
            remember()
            if process.poll() is None:
                result = NativeCaptureResult(False, "Native Chromium wall-clock deadline exceeded")
            elif process.returncode != 0:
                result = NativeCaptureResult(False, "Native Chromium exited without a completed capture")
            elif not _valid_png(temporary_png):
                result = NativeCaptureResult(False, "Native Chromium did not produce a valid 1280x720 PNG")
            else:
                os.replace(temporary_png, output)
                result = NativeCaptureResult(True, NATIVE_READINESS_WARNING)
    except asyncio.CancelledError:
        raise
    except Exception as exc:
        # No argv, URLs, profile paths, proxy credentials, or Settings repr.
        result = NativeCaptureResult(False, f"Native Chromium capture failed ({type(exc).__name__})")
    finally:
        if process is not None:
            remember()
            try:
                cleanup_ok = kill_processes(list(tracked.values()), timeout=0.75)
            except Exception:
                cleanup_ok = False
            if process.poll() is None:
                try:
                    process.kill()
                except OSError:
                    pass
                stop_deadline = time.monotonic() + 0.25
                while process.poll() is None and time.monotonic() < stop_deadline:
                    # This short, bounded wait also completes during task
                    # cancellation; no executor thread survives asyncio.run.
                    time.sleep(0.01)
            cleanup_ok = cleanup_ok and process.poll() is not None and not tracking_failed
            if not cleanup_ok:
                result = replace(result, cleanup_confirmed=False)
        if temporary_png is not None:
            try:
                temporary_png.unlink(missing_ok=True)
            except OSError:
                pass
        if profile is not None:
            try:
                profile.cleanup()
            except OSError:
                # Never mask cancellation, or pretend that a locked profile
                # proves all browser processes have been confirmed terminated.
                result = replace(result, cleanup_confirmed=False)
    return result
