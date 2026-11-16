"""Own scan processes independently of the API and stop their process trees.

Only the parent owns lifecycle records. Child logs cross a pipe so the API can
retain live events in its own Database instance. No credentials are logged.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import logging
import multiprocessing
import os
import signal
import subprocess
import threading
import time
from typing import Any, Callable

from app.services.process_cleanup import (
    ProcessIdentity, capture_owned_tree, is_process_alive, kill_processes, process_identity,
)


_LOGGER = logging.getLogger(__name__)
_STOP_TIMEOUT_SECONDS = 2.5
_START_TIMEOUT_SECONDS = 30.0


def _lower_worker_priority() -> None:
    """Yield CPU to the control API; positive niceness never raises priority."""
    try:
        nice = getattr(os, "nice", None)
        if nice is not None:
            nice(10)
    except (OSError, AttributeError, NotImplementedError):
        # Sandboxes may deny priority changes. That must not prevent a scan.
        pass


def _execute_job(settings: Any, job: dict[str, Any], emit: Callable[..., None]) -> None:
    # Imports and runtime objects belong to the child. In particular, importing
    # app.main here would create a second API and run unwanted startup actions.
    from app.database import Database
    from app.services.gemini import GeminiClient
    from app.services.investigator import Investigator

    db = Database(settings.database_url or settings.database_path)
    # The parent persists errors and owns the live log buffer. Writing twice
    # would duplicate error rows and leave INFO/WARNING in an invisible buffer.
    db.add_log = emit
    investigator = Investigator(settings, db, GeminiClient(settings, db))
    event = threading.Event()
    run_id = int(job["run_id"])
    kind = job["kind"]
    if kind == "auto":
        investigator.run(
            run_id, job.get("seed_query"), int(job["max_candidates"]),
            bool(job.get("take_screenshots", True)), event, job.get("search_mode", "auto"),
        )
    elif kind == "manual":
        investigator.run_manual(
            run_id, str(job["target"]), job.get("category", "manual"),
            bool(job.get("take_screenshots", True)), event,
        )
    elif kind == "repair":
        investigator.repair_completed_screenshot_backlog()
    else:
        raise ValueError("Unknown run worker job kind")


def _child_entry(send: Any, launch_gate: Any, settings: Any, job: dict[str, Any], entry: Callable[..., None]) -> None:
    send_lock = threading.Lock()

    def emit(run_id: int, level: str, message: str, meta: Any = None) -> None:
        try:
            with send_lock:
                send.send(("log", int(run_id), level, message, meta))
        except (EOFError, OSError, BrokenPipeError):
            pass

    try:
        if os.name != "nt":
            # Establish ownership before a driver or browser can be launched.
            # A failed setsid must not fall through and spawn unowned children.
            os.setsid()
            _lower_worker_priority()
            identity = (os.getpid(), os.getsid(0), os.getpgrp())
            if len(set(identity)) != 1:
                raise RuntimeError("Worker session was not isolated")
        else:
            identity = (os.getpid(), None, None)
        with send_lock:
            send.send(("ready", *identity))
        # The parent validates ownership and starts the log watcher before any
        # runtime import, network request, or browser launch is allowed.
        launch_gate.wait()
        entry(settings, job, emit)
    except BaseException as exc:
        # Exception messages can contain DSNs or provider responses. Forward
        # only the exception class, and suppress multiprocessing's traceback.
        emit(int(job["run_id"]), "error", "Run worker failed", {"error_type": type(exc).__name__})
        raise SystemExit(1) from None
    finally:
        send.close()


@dataclass
class _Worker:
    process: Any
    receive: Any
    launch_gate: Any = None
    stop_lock: threading.Lock = field(default_factory=threading.Lock)
    force_stopped: bool = False
    session_ready: bool = False
    tree_stopped: bool = False
    watcher_started: bool = False
    identity: ProcessIdentity | None = None
    owned_processes: dict[tuple[int, float], ProcessIdentity] = field(default_factory=dict)
    next_process_snapshot: float = 0.0


class RunWorkerManager:
    def __init__(
        self,
        on_log: Callable[[int, str, str, Any], None],
        on_exit: Callable[[int, int, bool], None],
        *,
        _entry: Callable[..., None] = _execute_job,
        _context: Any = None,
        _bootstrap: Callable[..., None] = _child_entry,
        _start_timeout: float = _START_TIMEOUT_SECONDS,
    ) -> None:
        self._on_log = on_log
        self._on_exit = on_exit
        self._entry = _entry
        self._bootstrap = _bootstrap
        self._start_timeout = max(0.01, float(_start_timeout))
        self._context = _context or multiprocessing.get_context("spawn")
        self._lock = threading.RLock()
        self._workers: dict[int, _Worker] = {}

    def start(self, run_id: int, settings: Any, job: dict[str, Any]) -> None:
        run_id = int(run_id)
        child_job = dict(job, run_id=run_id)
        # Hold the registry lock only through process registration/start, not
        # cold Python imports or the ownership handshake. A starting worker
        # remains visible and stoppable while its watcher awaits readiness.
        with self._lock:
            if run_id in self._workers:
                raise RuntimeError("A worker for this run is already registered")
            receive, send = self._context.Pipe(duplex=False)
            launch_gate = self._context.Event()
            process = self._context.Process(
                target=self._bootstrap, args=(send, launch_gate, settings, child_job, self._entry),
                name=f"qalqan-run-{run_id}", daemon=True,
            )
            worker = _Worker(process, receive, launch_gate=launch_gate)
            self._workers[run_id] = worker
            try:
                process.start()
                worker.identity = process_identity(process.pid)
                watcher = threading.Thread(
                    target=self._watch, args=(run_id, worker),
                    name=f"qalqan-run-watch-{run_id}", daemon=True,
                )
                watcher.start()
                worker.watcher_started = True
            except BaseException:
                cleanup_failed = False
                try:
                    if process.pid is not None and process.is_alive():
                        deadline = time.monotonic() + _STOP_TIMEOUT_SECONDS
                        self._kill_tree(worker, time.monotonic() + _STOP_TIMEOUT_SECONDS)
                        process.join(timeout=max(0.0, deadline - time.monotonic()))
                    if process.pid is not None and process.is_alive():
                        cleanup_failed = True
                    else:
                        self._cleanup_owned_session(worker)
                except Exception:
                    cleanup_failed = True
                if cleanup_failed:
                    # Keep ownership reachable by force_stop/stop_all instead
                    # of abandoning a process after a failed watcher launch.
                    raise RuntimeError("Worker launch failed and its process tree is still tracked for cleanup") from None
                worker.tree_stopped = True
                self._workers.pop(run_id, None)
                receive.close()
                raise
            finally:
                # The child has its own duplicated handle after spawn.
                send.close()

    def is_running(self, run_id: int) -> bool:
        with self._lock:
            worker = self._workers.get(int(run_id))
            # A dead root can still own browser descendants. Report completion
            # only after tree cleanup, independently of the exit callback.
            return bool(worker and not worker.tree_stopped)

    def running_ids(self) -> list[int]:
        with self._lock:
            return sorted(run_id for run_id, worker in self._workers.items() if not worker.tree_stopped)

    def force_stop(self, run_id: int) -> bool:
        deadline = time.monotonic() + _STOP_TIMEOUT_SECONDS
        if not self._lock.acquire(timeout=_STOP_TIMEOUT_SECONDS):
            raise RuntimeError("Run worker launch did not finish within the stop deadline")
        try:
            worker = self._workers.get(int(run_id))
        finally:
            self._lock.release()
        if worker is None:
            return False
        remaining = max(0.0, deadline - time.monotonic())
        if not worker.stop_lock.acquire(timeout=remaining):
            raise RuntimeError("Run worker stop deadline exceeded")
        try:
            if worker.tree_stopped:
                return False
            worker.force_stopped = True
            if worker.process.is_alive():
                self._kill_tree(worker, deadline)
                worker.process.join(timeout=max(0.0, deadline - time.monotonic()))
            if worker.process.is_alive():
                raise RuntimeError("Run worker did not stop within the deadline")
            self._cleanup_owned_session(worker, timeout=max(0.0, deadline - time.monotonic()))
            worker.tree_stopped = True
            if not worker.watcher_started:
                # A failed launch never released the job gate. There is no
                # watcher/callback to wait for, but its retained ownership must
                # remain stoppable and must not prevent a later retry.
                with self._lock:
                    if self._workers.get(int(run_id)) is worker:
                        del self._workers[int(run_id)]
                worker.receive.close()
            # Never join the watcher: its callback may need an API launch lock
            # currently held by the caller of force_stop.
            return True
        finally:
            worker.stop_lock.release()

    def stop_all(self) -> list[int]:
        stopped, errors = [], []
        with self._lock:
            run_ids = list(self._workers)
        for run_id in run_ids:
            try:
                if self.force_stop(run_id):
                    stopped.append(run_id)
            except RuntimeError:
                errors.append(run_id)
        if errors:
            raise RuntimeError("One or more run worker trees could not be stopped")
        return stopped

    @staticmethod
    def _kill_tree(worker: _Worker, deadline: float) -> None:
        process = worker.process
        pid = process.pid
        if pid is None or pid == os.getpid():
            raise RuntimeError("Invalid owned worker process")
        if os.name == "nt":
            try:
                result = subprocess.run(
                    ["taskkill", "/PID", str(pid), "/T", "/F"],
                    stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                    timeout=max(0.01, deadline - time.monotonic()),
                    creationflags=subprocess.CREATE_NO_WINDOW, check=False,
                )
            except (OSError, subprocess.TimeoutExpired):
                # Kill the owned root as a last resort, but do not claim that
                # all descendants were terminated if taskkill did not finish.
                if process.is_alive():
                    process.kill()
                raise RuntimeError("Unable to stop the owned worker process tree") from None
            if result.returncode and process.is_alive():
                raise RuntimeError("Unable to stop the owned worker process tree")
            return
        # Playwright can launch Chromium with detached:true. Session/group
        # signalling alone would miss that descendant, so snapshot its stable
        # identity before killing the worker and reparenting the browser.
        if worker.identity is not None:
            roots = capture_owned_tree(worker.identity)
            for identity in list(roots):
                for descendant in capture_owned_tree(identity):
                    worker.owned_processes[descendant.key] = descendant
            descendants_stopped = kill_processes(
                list(worker.owned_processes.values()),
                timeout=min(0.75, max(0.0, deadline - time.monotonic())),
            )
            RunWorkerManager._cleanup_owned_session(
                worker, timeout=max(0.0, deadline - time.monotonic())
            )
            if not descendants_stopped:
                raise RuntimeError("Owned worker descendants did not stop within the deadline")
            return
        try:
            pgid = os.getpgid(pid)
            sid = os.getsid(pid)
        except ProcessLookupError:
            RunWorkerManager._cleanup_owned_session(worker)
            return
        if pgid == sid == pid and pgid != os.getpgrp():
            worker.session_ready = True
            try:
                os.killpg(pgid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        else:
            # Before setsid there can be no job descendants. In particular,
            # never signal the API's inherited process group.
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass

    @staticmethod
    def _cleanup_owned_session(worker: _Worker, timeout: float = 0.75) -> None:
        # A child may exit before its driver/browser descendants. The ready
        # handshake proves this PGID belonged to our isolated child session;
        # querying the already-dead root with getpgid would lose that proof.
        if worker.owned_processes and not kill_processes(list(worker.owned_processes.values()), timeout):
            raise RuntimeError("Owned worker descendants did not stop within the deadline")
        if os.name == "nt" or not worker.session_ready:
            return
        pid = worker.process.pid
        if pid is None or pid in {os.getpid(), os.getpgrp(), os.getsid(0)}:
            return
        try:
            os.killpg(pid, signal.SIGKILL)
        except ProcessLookupError:
            pass

    def _watch(self, run_id: int, worker: _Worker) -> None:
        receive = worker.receive
        ownership_ready = False
        startup_error = None
        try:
            try:
                ownership_ready = self._await_ownership(worker)
            except Exception as exc:
                if not worker.force_stopped:
                    startup_error = {"phase": "startup", "error_type": type(exc).__name__,
                                     "timeout_seconds": self._start_timeout}
            if not ownership_ready:
                return
            while True:
                self._remember_owned_processes(worker)
                try:
                    has_message = receive.poll(0.05)
                    if has_message:
                        message = receive.recv()
                        if message[0] == "ready":
                            pid = worker.process.pid
                            worker.session_ready = os.name != "nt" and tuple(message[1:]) == (pid, pid, pid)
                        elif message[0] == "log":
                            self._remember_owned_processes(worker)
                            try:
                                self._on_log(*message[1:])
                            except Exception:
                                _LOGGER.error("Run worker log callback failed")
                            self._remember_owned_processes(worker)
                        continue
                except (EOFError, OSError):
                    break
                if not worker.process.is_alive():
                    break
        finally:
            if not ownership_ready:
                # No job passed the launch gate. Kill a failed/cancelled cold
                # start before waiting for the process or invoking callbacks.
                with worker.stop_lock:
                    try:
                        if not worker.tree_stopped:
                            deadline = time.monotonic() + _STOP_TIMEOUT_SECONDS
                            if worker.process.is_alive():
                                self._kill_tree(worker, deadline)
                                worker.process.join(timeout=max(0.0, deadline - time.monotonic()))
                            if worker.process.is_alive():
                                raise RuntimeError("Starting worker could not be stopped")
                            self._cleanup_owned_session(worker, timeout=max(0.0, deadline - time.monotonic()))
                            worker.tree_stopped = True
                    except Exception:
                        worker.watcher_started = False
                        _LOGGER.error("Starting worker cleanup failed; ownership is retained")
                        return
            if startup_error is not None and not worker.force_stopped:
                try:
                    self._on_log(run_id, "error", "Run worker failed during ownership handshake", startup_error)
                except Exception:
                    _LOGGER.error("Run worker startup log callback failed")
            # EOF normally arrives only when the root has exited, but close
            # the pipe first and wait for actual liveness before finalization.
            receive.close()
            worker.process.join()
            with worker.stop_lock:
                try:
                    if not worker.tree_stopped:
                        self._cleanup_owned_session(worker)
                        worker.tree_stopped = True
                except (OSError, RuntimeError):
                    _LOGGER.error("Failed to clean up an owned worker session; ownership is retained")
                    return
            with self._lock:
                if self._workers.get(run_id) is worker:
                    del self._workers[run_id]
            try:
                self._on_exit(run_id, int(worker.process.exitcode or 0), worker.force_stopped)
            except Exception:
                _LOGGER.error("Run worker exit callback failed")

    def _await_ownership(self, worker: _Worker) -> bool:
        deadline = time.monotonic() + self._start_timeout
        while True:
            if worker.force_stopped or worker.tree_stopped:
                return False
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("Run worker did not establish ownership before the launch deadline")
            if worker.receive.poll(min(0.05, remaining)):
                ready = worker.receive.recv()
                pid = worker.process.pid
                expected = ("ready", pid, None, None) if os.name == "nt" else ("ready", pid, pid, pid)
                if ready != expected:
                    raise RuntimeError("Run worker ownership handshake failed")
                with worker.stop_lock:
                    worker.session_ready = os.name != "nt"
                    if worker.force_stopped or worker.tree_stopped:
                        return False
                    # Gate and Stop share this lock: cancellation can never be
                    # followed by a delayed watcher starting the actual job.
                    worker.launch_gate.set()
                return True
            if not worker.process.is_alive():
                raise RuntimeError("Run worker exited before the ownership handshake")

    @staticmethod
    def _remember_owned_processes(worker: _Worker) -> None:
        # Cache detached descendants while the root is alive: after an OOM or
        # os._exit they can be reparented and disappear from children(root).
        now = time.monotonic()
        if now < worker.next_process_snapshot:
            return
        with worker.stop_lock:
            if worker.tree_stopped or now < worker.next_process_snapshot:
                return
            worker.next_process_snapshot = now + 0.25
            retained = {}
            for key, identity in worker.owned_processes.items():
                try:
                    if is_process_alive(identity):
                        retained[key] = identity
                except Exception:
                    # Unknown identity state is not proof that cleanup finished.
                    retained[key] = identity
            worker.owned_processes = retained
            if worker.identity is not None and worker.process.is_alive():
                try:
                    for identity in capture_owned_tree(worker.identity):
                        if is_process_alive(identity):
                            worker.owned_processes[identity.key] = identity
                except Exception:
                    if worker.process.is_alive():
                        _LOGGER.warning("Could not refresh owned worker process identities")
