from __future__ import annotations

import ctypes
import importlib.util
import multiprocessing
import os
from pathlib import Path
import signal
import subprocess
import sys
from tempfile import TemporaryDirectory
import threading
import time
import unittest
from unittest.mock import patch

from app.services.run_workers import RunWorkerManager


def _fixture_tree(settings, job, emit):
    """Real child and grandchild; neither has a cooperative cancellation path."""
    if os.name != "nt":
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
    heartbeat = job["heartbeat"]
    script = (
        "import pathlib,sys,time; p=pathlib.Path(sys.argv[1]); "
        "\nwhile True:\n p.write_text(str(time.time_ns())); time.sleep(0.03)\n"
    )
    options = ({"creationflags": subprocess.CREATE_NO_WINDOW} if os.name == "nt"
               else {"start_new_session": True})
    descendant = subprocess.Popen([sys.executable, "-B", "-c", script, heartbeat], **options)
    Path(job["pid_file"]).write_text(str(descendant.pid), encoding="ascii")
    emit(job["run_id"], "info", "fixture tree ready", {"fixture": True})
    while True:
        time.sleep(0.05)


def _fixture_logs(settings, job, emit):
    emit(job["run_id"], "info", "fixture info", {"step": 1})
    emit(job["run_id"], "warning", "fixture warning", {"step": 2})


def _fixture_idle(settings, job, emit):
    emit(job["run_id"], "info", "fixture idle", None)
    while True:
        time.sleep(0.05)


def _fixture_leave_descendant(settings, job, emit):
    descendant = subprocess.Popen([sys.executable, "-B", "-c", "import time; time.sleep(60)"])
    Path(job["pid_file"]).write_text(str(descendant.pid), encoding="ascii")
    emit(job["run_id"], "info", "fixture left descendant", None)


def _fixture_abrupt_detached_descendant(settings, job, emit):
    script = (
        "import pathlib,sys,time; p=pathlib.Path(sys.argv[1]); "
        "\nwhile True:\n p.write_text(str(time.time_ns())); time.sleep(0.03)\n"
    )
    options = ({"creationflags": subprocess.CREATE_NO_WINDOW | subprocess.CREATE_NEW_PROCESS_GROUP}
               if os.name == "nt" else {"start_new_session": True})
    descendant = subprocess.Popen([sys.executable, "-B", "-c", script, job["heartbeat"]], **options)
    Path(job["pid_file"]).write_text(str(descendant.pid), encoding="ascii")
    emit(job["run_id"], "info", "fixture detached descendant ready", None)
    time.sleep(1.0)
    os._exit(17)


class _DelayedProcess:
    def __init__(self, process, entered, proceed):
        self._process = process
        self._entered = entered
        self._proceed = proceed

    def __getattr__(self, name):
        return getattr(self._process, name)

    def start(self):
        self._entered.set()
        if not self._proceed.wait(3):
            raise RuntimeError("fixture launch gate timed out")
        self._process.start()


class _DelayedContext:
    def __init__(self, entered, proceed):
        self._context = multiprocessing.get_context("spawn")
        self._entered = entered
        self._proceed = proceed

    def Pipe(self, **kwargs):
        return self._context.Pipe(**kwargs)

    def Event(self):
        return self._context.Event()

    def Process(self, **kwargs):
        return _DelayedProcess(self._context.Process(**kwargs), self._entered, self._proceed)


def _pid_running(pid):
    if os.name == "nt":
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.OpenProcess.argtypes = [ctypes.c_uint32, ctypes.c_int, ctypes.c_uint32]
        kernel.OpenProcess.restype = ctypes.c_void_p
        kernel.WaitForSingleObject.argtypes = [ctypes.c_void_p, ctypes.c_uint32]
        kernel.CloseHandle.argtypes = [ctypes.c_void_p]
        handle = kernel.OpenProcess(0x00100000, False, pid)
        if not handle:
            return False
        try:
            return kernel.WaitForSingleObject(handle, 0) == 0x00000102
        finally:
            kernel.CloseHandle(handle)
    try:
        stat = Path(f"/proc/{pid}/stat")
        if stat.exists() and stat.read_text().split(")", 1)[1].split()[0] == "Z":
            return False
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False


def _wait_for(predicate, timeout=6):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.025)
    return False


class _BrokenContext:
    Pipe = staticmethod(multiprocessing.get_context("spawn").Pipe)
    Event = staticmethod(multiprocessing.get_context("spawn").Event)

    class Process:
        pid = None

        def __init__(self, **kwargs):
            pass

        def start(self):
            raise RuntimeError("fixture cannot start process")

        def close(self):
            pass


class RunWorkerTests(unittest.TestCase):
    def test_abrupt_exit_cleans_cached_detached_descendant_before_exit_callback(self):
        from app.services.process_cleanup import kill_processes, process_identity

        parent_pid = os.getpid()
        exits = []
        exited = threading.Event()
        with TemporaryDirectory() as directory:
            heartbeat = Path(directory) / "abrupt-heartbeat.txt"
            pid_file = Path(directory) / "abrupt-descendant.txt"
            manager = RunWorkerManager(lambda *args: None,
                                       lambda *args: (exits.append(args), exited.set()),
                                       _entry=_fixture_abrupt_detached_descendant)
            self.addCleanup(manager.stop_all)
            manager.start(134, None, {"kind": "auto", "run_id": 134,
                                      "heartbeat": str(heartbeat), "pid_file": str(pid_file)})
            self.assertTrue(_wait_for(lambda: pid_file.exists() and heartbeat.exists()))
            descendant_pid = int(pid_file.read_text())
            descendant = process_identity(descendant_pid)
            self.addCleanup(kill_processes, [descendant], 0.5)
            self.assertTrue(exited.wait(6))
            self.assertEqual(exits, [(134, 17, False)])
            self.assertEqual(os.getpid(), parent_pid)
            self.assertFalse(_pid_running(descendant_pid))
            final_heartbeat = heartbeat.read_text()
            time.sleep(0.12)
            self.assertEqual(heartbeat.read_text(), final_heartbeat)
            self.assertEqual(manager.running_ids(), [])

    def test_production_entry_accepts_settings_and_empty_repair_database(self):
        required = ("httpx", "bs4", "requests", "tldextract")
        if any(importlib.util.find_spec(name) is None for name in required):
            self.skipTest("Production entry requires the application's runtime dependencies")
        from app.config import Settings
        from app.database import Database

        exits, logs = [], []
        exited = threading.Event()
        with TemporaryDirectory() as directory:
            root = Path(directory)
            settings = Settings(database_path=root / "repair.db", evidence_dir=root / "evidence",
                                export_dir=root / "exports", screenshots_enabled=False,
                                browser_screenshots_enabled=False)
            db = Database(settings.database_path)
            db.init()
            manager = RunWorkerManager(lambda *args: logs.append(args),
                                       lambda *args: (exits.append(args), exited.set()))
            self.addCleanup(manager.stop_all)
            manager.start(0, settings, {"kind": "repair", "run_id": 0})
            self.assertTrue(exited.wait(8))
            self.assertEqual(exits, [(0, 0, False)])
            self.assertEqual(logs, [])
            self.assertEqual(db.list_runs(), [])
            self.assertEqual(manager.running_ids(), [])

    def test_force_stop_kills_uncooperative_child_and_descendant(self):
        parent_pid = os.getpid()
        exited = threading.Event()
        exits = []
        with TemporaryDirectory() as directory:
            heartbeat = Path(directory) / "heartbeat.txt"
            pid_file = Path(directory) / "descendant.txt"
            manager = RunWorkerManager(
                lambda *args: None,
                lambda *args: (exits.append(args), exited.set()),
                _entry=_fixture_tree,
            )
            self.addCleanup(manager.stop_all)
            manager.start(134, None, {"kind": "auto", "run_id": 134,
                                      "heartbeat": str(heartbeat), "pid_file": str(pid_file)})
            self.assertTrue(_wait_for(lambda: pid_file.exists() and heartbeat.exists()))
            descendant_pid = int(pid_file.read_text())
            self.assertTrue(_pid_running(descendant_pid))
            self.assertTrue(manager.is_running(134))
            started = time.monotonic()
            self.assertTrue(manager.force_stop(134))
            self.assertLess(time.monotonic() - started, 3.1)
            self.assertEqual(os.getpid(), parent_pid)
            self.assertFalse(manager.is_running(134))
            self.assertTrue(_wait_for(lambda: not _pid_running(descendant_pid), timeout=1))
            stopped_heartbeat = heartbeat.read_text()
            time.sleep(0.12)
            self.assertEqual(heartbeat.read_text(), stopped_heartbeat)
            self.assertTrue(exited.wait(3))
            self.assertEqual(exits[0][0], 134)
            self.assertTrue(exits[0][2])
            self.assertEqual(manager.running_ids(), [])

    def test_logs_are_forwarded_before_exit_and_registry_is_removed(self):
        logs, exits = [], []
        exited = threading.Event()
        manager = RunWorkerManager(
            lambda *args: logs.append(args),
            lambda *args: (exits.append((args, manager.running_ids())), exited.set()),
            _entry=_fixture_logs,
        )
        self.addCleanup(manager.stop_all)
        manager.start(42, None, {"kind": "manual", "run_id": 42})
        self.assertTrue(exited.wait(6))
        self.assertEqual([(row[0], row[1], row[2]) for row in logs], [
            (42, "info", "fixture info"), (42, "warning", "fixture warning")])
        self.assertEqual(logs[1][3], {"step": 2})
        self.assertEqual(exits, [((42, 0, False), [])])

    def test_process_start_failure_leaves_no_worker(self):
        exits = []
        manager = RunWorkerManager(lambda *args: None, lambda *args: exits.append(args),
                                   _context=_BrokenContext())
        with self.assertRaisesRegex(RuntimeError, "cannot start"):
            manager.start(134, None, {"kind": "auto", "run_id": 134})
        self.assertEqual(manager.running_ids(), [])
        self.assertFalse(manager.is_running(134))
        self.assertFalse(manager.force_stop(134))
        self.assertEqual(exits, [])

    def test_failed_launch_cleanup_keeps_ownership_until_a_successful_stop(self):
        exits = []
        manager = RunWorkerManager(lambda *args: None, lambda *args: exits.append(args),
                                   _entry=_fixture_idle)
        self.addCleanup(manager.stop_all)
        with patch("app.services.run_workers.threading.Thread", side_effect=RuntimeError("fixture no watcher")), \
                patch.object(manager, "_kill_tree", side_effect=RuntimeError("fixture stop failed")):
            with self.assertRaisesRegex(RuntimeError, "still tracked"):
                manager.start(134, None, {"kind": "auto", "run_id": 134})
        self.assertTrue(manager.is_running(134))
        self.assertEqual(manager.running_ids(), [134])
        self.assertTrue(manager.force_stop(134))
        self.assertFalse(manager.is_running(134))
        self.assertEqual(manager.running_ids(), [])
        self.assertNotIn(134, manager._workers)
        self.assertEqual(exits, [])

    def test_force_stop_does_not_wait_for_exit_callback(self):
        callback_lock = threading.Lock()
        callback_done = threading.Event()
        ready = threading.Event()

        def on_exit(*args):
            with callback_lock:
                callback_done.set()

        manager = RunWorkerManager(lambda *args: ready.set(), on_exit, _entry=_fixture_idle)
        self.addCleanup(manager.stop_all)
        with callback_lock:
            manager.start(134, None, {"kind": "auto", "run_id": 134})
            self.assertTrue(ready.wait(6))
            started = time.monotonic()
            self.assertTrue(manager.force_stop(134))
            self.assertLess(time.monotonic() - started, 3.1)
            self.assertFalse(callback_done.is_set())
        self.assertTrue(callback_done.wait(3))

    def test_stop_during_launch_waits_for_owned_process_registration(self):
        entered, proceed, started, stopped = (threading.Event() for _ in range(4))
        failures = []
        manager = RunWorkerManager(lambda *args: None, lambda *args: None,
                                   _entry=_fixture_idle, _context=_DelayedContext(entered, proceed))
        self.addCleanup(manager.stop_all)

        def launch():
            try:
                manager.start(134, None, {"kind": "auto", "run_id": 134})
                started.set()
            except Exception as exc:
                failures.append(type(exc).__name__)

        def stop():
            try:
                if manager.force_stop(134):
                    stopped.set()
            except Exception as exc:
                failures.append(type(exc).__name__)

        launching = threading.Thread(target=launch)
        launching.start()
        self.assertTrue(entered.wait(2))
        stopping = threading.Thread(target=stop)
        stopping.start()
        time.sleep(0.05)
        self.assertFalse(stopped.is_set())
        proceed.set()
        launching.join(4)
        stopping.join(4)
        self.assertEqual(failures, [])
        self.assertTrue(started.is_set())
        self.assertTrue(stopped.is_set())
        self.assertFalse(manager.is_running(134))

    @unittest.skipIf(os.name == "nt", "POSIX session cleanup")
    def test_normal_exit_terminates_descendant_in_owned_session(self):
        exited = threading.Event()
        with TemporaryDirectory() as directory:
            pid_file = Path(directory) / "left-descendant.txt"
            manager = RunWorkerManager(lambda *args: None, lambda *args: exited.set(),
                                       _entry=_fixture_leave_descendant)
            self.addCleanup(manager.stop_all)
            manager.start(134, None, {"kind": "auto", "run_id": 134, "pid_file": str(pid_file)})
            self.assertTrue(exited.wait(6))
            descendant_pid = int(pid_file.read_text())
            self.assertTrue(_wait_for(lambda: not _pid_running(descendant_pid), timeout=1))
            self.assertFalse(manager.is_running(134))

    @unittest.skipIf(os.name == "nt", "POSIX session cleanup")
    def test_stop_all_cleans_dead_root_while_log_callback_is_blocked(self):
        blocked, release, exited = (threading.Event() for _ in range(3))

        def on_log(*args):
            blocked.set()
            release.wait(6)

        with TemporaryDirectory() as directory:
            pid_file = Path(directory) / "blocked-descendant.txt"
            manager = RunWorkerManager(on_log, lambda *args: exited.set(),
                                       _entry=_fixture_leave_descendant)
            self.addCleanup(release.set)
            self.addCleanup(manager.stop_all)
            try:
                manager.start(134, None, {"kind": "auto", "run_id": 134, "pid_file": str(pid_file)})
                self.assertTrue(blocked.wait(4))
                worker = manager._workers[134]
                self.assertTrue(_wait_for(lambda: not worker.process.is_alive()))
                descendant_pid = int(pid_file.read_text())
                self.assertTrue(_pid_running(descendant_pid))
                self.assertTrue(manager.is_running(134))
                self.assertEqual(manager.running_ids(), [134])
                started = time.monotonic()
                self.assertEqual(manager.stop_all(), [134])
                self.assertLess(time.monotonic() - started, 3.1)
                self.assertTrue(_wait_for(lambda: not _pid_running(descendant_pid), timeout=1))
                self.assertFalse(manager.is_running(134))
                self.assertFalse(exited.is_set())
            finally:
                release.set()
            self.assertTrue(exited.wait(3))


if __name__ == "__main__":
    unittest.main()
