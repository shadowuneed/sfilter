"""Bounded cleanup of processes created by one serialized browser capture."""
from __future__ import annotations

from dataclasses import dataclass
import os
import time

import psutil


class ProcessCleanupError(RuntimeError):
    pass


@dataclass(frozen=True)
class ProcessIdentity:
    process: psutil.Process
    pid: int
    created: float

    @property
    def key(self) -> tuple[int, float]:
        return self.pid, self.created


def process_identity(process: psutil.Process | int) -> ProcessIdentity:
    if isinstance(process, int):
        process = psutil.Process(process)
    return ProcessIdentity(process, process.pid, process.create_time())


def _alive(identity: ProcessIdentity) -> bool:
    try:
        return (identity.process.is_running()
                and identity.process.create_time() == identity.created
                and identity.process.status() != psutil.STATUS_ZOMBIE)
    except (psutil.NoSuchProcess, psutil.ZombieProcess):
        return False


def is_process_alive(identity: ProcessIdentity) -> bool:
    """Check a saved identity without reaping a library-managed child."""
    return _alive(identity)


def capture_owned_tree(root: ProcessIdentity) -> list[ProcessIdentity]:
    """Snapshot an already-owned root before termination can reparent children."""
    result = [root]
    try:
        if _alive(root):
            for child in root.process.children(recursive=True):
                try:
                    result.append(process_identity(child))
                except (psutil.NoSuchProcess, psutil.ZombieProcess):
                    pass
    except psutil.Error:
        raise ProcessCleanupError("Could not snapshot the owned process tree") from None
    return result


def kill_processes(identities: list[ProcessIdentity], timeout: float = 0.75,
                   protected_pids: set[int] | None = None) -> bool:
    """Kill only saved identities, regardless of their current parent/session."""
    protected = {os.getpid(), os.getppid(), *(protected_pids or ())}
    try:
        protected.update(parent.pid for parent in psutil.Process().parents())
    except psutil.Error:
        return False
    owned = {identity.key: identity for identity in identities if identity.pid not in protected}
    failed = False
    direct_children = set()
    deadline = time.monotonic() + max(0.0, timeout)
    for identity in owned.values():
        try:
            if _alive(identity):
                if os.name != "nt" and identity.process.ppid() == os.getpid():
                    # multiprocessing/asyncio/Popen own waitpid for these
                    # children. Do not steal their exit status with psutil.wait.
                    direct_children.add(identity.pid)
                identity.process.kill()
        except (psutil.NoSuchProcess, psutil.ZombieProcess):
            pass
        except psutil.Error:
            failed = True
    while True:
        try:
            alive = [identity.process for identity in owned.values() if _alive(identity)]
        except psutil.Error:
            return False
        if not alive:
            return not failed
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return False
        try:
            waitable = [process for process in alive if process.pid not in direct_children]
            if waitable:
                psutil.wait_procs(waitable, timeout=min(0.05, remaining))
            else:
                time.sleep(min(0.01, remaining))
        except psutil.Error:
            return False


class ScreenshotProcessScope:
    """Use only with a single browser slot and no other child-producing work.

    Save process handles and creation times before graceful shutdown can orphan
    descendants. Existing children and their subtrees are never owned by this
    scope; PID-only signalling and process-group signalling are not used.
    """
    def __init__(self) -> None:
        self._owner = psutil.Process(os.getpid())
        self._protected_pids = {os.getpid(), os.getppid()}
        self._owned: dict[tuple[int, float], ProcessIdentity] = {}
        try:
            self._protected_pids.update(parent.pid for parent in self._owner.parents())
            self._baseline = self._descendants(self._owner)
        except psutil.Error:
            raise ProcessCleanupError("Could not establish browser process ownership") from None
        self._protected = set(self._baseline)

    @staticmethod
    def _descendants(process: psutil.Process) -> dict[tuple[int, float], ProcessIdentity]:
        result = {}
        try:
            children = process.children(recursive=True)
        except (psutil.NoSuchProcess, psutil.ZombieProcess):
            return result
        for child in children:
            try:
                identity = process_identity(child)
            except (psutil.NoSuchProcess, psutil.ZombieProcess):
                continue
            result[identity.key] = identity
        return result

    def _allowed(self, identity: ProcessIdentity) -> bool:
        return identity.pid not in self._protected_pids and identity.key not in self._protected

    def track(self) -> None:
        try:
            # A pre-existing child may itself create new children during this
            # capture. Protect those as well, instead of claiming all new PIDs.
            for existing in self._baseline.values():
                if _alive(existing):
                    self._protected.update(self._descendants(existing.process))
            for key, identity in self._descendants(self._owner).items():
                if self._allowed(identity):
                    self._owned[key] = identity
        except psutil.Error:
            raise ProcessCleanupError("Could not track browser process ownership") from None

    def cleanup(self, timeout: float = 0.75) -> bool:
        deadline = time.monotonic() + max(0.0, timeout)
        failed = False
        try:
            self.track()
        except ProcessCleanupError:
            failed = True
        # Retained handles still identify children reparented by driver exit.
        for identity in list(self._owned.values()):
            try:
                if self._allowed(identity) and _alive(identity):
                    for key, child in self._descendants(identity.process).items():
                        if self._allowed(child):
                            self._owned[key] = child
            except psutil.Error:
                failed = True
        owned = [identity for identity in self._owned.values() if self._allowed(identity)]
        return kill_processes(owned, max(0.0, deadline - time.monotonic()), self._protected_pids) and not failed
