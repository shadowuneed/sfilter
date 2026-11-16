from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from app.config import Settings
from app.services.runtime_limits import apply_runtime_limits


MIB = 1024 * 1024


class RuntimeLimitsTests(unittest.TestCase):
    def setUp(self):
        self.directory = TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.v2 = self.root / "memory.max"
        self.v1 = self.root / "memory.limit_in_bytes"
        self.settings = Settings(scan_concurrency=3, screenshots_enabled=True,
                                 browser_screenshots_enabled=True, screenshot_fallback_enabled=True,
                                 screenshot_concurrency=3)

    def apply(self, settings=None):
        return apply_runtime_limits(settings or self.settings,
                                    _cgroup_v2_path=self.v2, _cgroup_v1_path=self.v1)

    def test_v2_512_mib_serializes_checks_and_keeps_real_screenshots_without_mutating_settings(self):
        self.v2.write_text(str(512 * MIB), encoding="ascii")
        effective, info = self.apply()
        self.assertEqual(info, {"low_memory_mode": True, "container_memory_limit_mb": 512})
        self.assertIsNot(effective, self.settings)
        self.assertEqual(effective.scan_concurrency, 1)
        self.assertEqual(effective.screenshot_concurrency, 1)
        self.assertTrue(effective.screenshots_enabled)
        self.assertTrue(effective.browser_screenshots_enabled)
        self.assertTrue(effective.screenshot_fallback_enabled)
        self.assertEqual(self.settings.scan_concurrency, 3)
        self.assertEqual(self.settings.screenshot_concurrency, 3)
        self.assertTrue(self.settings.screenshots_enabled)
        self.assertTrue(self.settings.browser_screenshots_enabled)
        self.assertTrue(self.settings.screenshot_fallback_enabled)
        self.assertEqual(effective.database_path, self.settings.database_path)

    def test_low_memory_preserves_every_explicit_screenshot_flag(self):
        self.v2.write_text(str(512 * MIB), encoding="ascii")
        for enabled, browser, fallback in [(False, False, False), (True, False, False),
                                            (False, True, True), (True, True, False)]:
            with self.subTest(enabled=enabled, browser=browser, fallback=fallback):
                configured = replace(self.settings, screenshots_enabled=enabled,
                                     browser_screenshots_enabled=browser,
                                     screenshot_fallback_enabled=fallback)
                effective, info = self.apply(configured)
                self.assertTrue(info["low_memory_mode"])
                self.assertEqual(effective.scan_concurrency, 1)
                self.assertEqual(effective.screenshot_concurrency, 1)
                self.assertEqual(effective.screenshots_enabled, enabled)
                self.assertEqual(effective.browser_screenshots_enabled, browser)
                self.assertEqual(effective.screenshot_fallback_enabled, fallback)

    def test_verified_low_memory_gives_cold_browser_a_bounded_45_second_budget(self):
        self.v2.write_text(str(512 * MIB), encoding="ascii")
        effective, info = self.apply()
        self.assertTrue(info["low_memory_mode"])
        self.assertEqual(effective.screenshot_timeout_seconds, 45)
        self.assertEqual(self.settings.screenshot_timeout_seconds, 10)

    def test_low_memory_preserves_a_longer_explicit_screenshot_budget(self):
        self.v2.write_text(str(512 * MIB), encoding="ascii")
        configured = replace(self.settings, screenshot_timeout_seconds=60)
        effective, _ = self.apply(configured)
        self.assertEqual(effective.screenshot_timeout_seconds, 60)

    def test_threshold_uses_bytes_and_includes_exactly_768_mib(self):
        for limit, low in [(768 * MIB, True), (768 * MIB + 1, False)]:
            with self.subTest(limit=limit):
                self.v2.write_text(str(limit), encoding="ascii")
                effective, info = self.apply()
                self.assertEqual(info["low_memory_mode"], low)
                self.assertEqual(effective.scan_concurrency, 1 if low else 3)

    def test_v1_limit_is_used_when_v2_file_is_absent(self):
        self.v1.write_text(f" {384 * MIB}\n", encoding="ascii")
        effective, info = self.apply()
        self.assertEqual(info, {"low_memory_mode": True, "container_memory_limit_mb": 384})
        self.assertEqual(effective.scan_concurrency, 1)

    def test_v2_is_authoritative_when_both_files_exist(self):
        self.v2.write_text(str(2 * 1024 * MIB), encoding="ascii")
        self.v1.write_text(str(512 * MIB), encoding="ascii")
        effective, info = self.apply()
        self.assertIs(effective, self.settings)
        self.assertEqual(info, {"low_memory_mode": False, "container_memory_limit_mb": 2048})

    def test_v2_unlimited_does_not_invent_a_limit_from_v1(self):
        self.v2.write_text("max\n", encoding="ascii")
        self.v1.write_text(str(512 * MIB), encoding="ascii")
        effective, info = self.apply()
        self.assertIs(effective, self.settings)
        self.assertEqual(info, {"low_memory_mode": False, "container_memory_limit_mb": None})

    def test_unknown_or_malformed_v2_does_not_change_settings(self):
        for text in ["", "not-a-limit", "-1", "512MB", "512_000_000"]:
            with self.subTest(text=text):
                self.v2.write_text(text, encoding="ascii")
                effective, info = self.apply()
                self.assertIs(effective, self.settings)
                self.assertEqual(info, {"low_memory_mode": False, "container_memory_limit_mb": None})

    def test_missing_files_do_not_assume_a_host_or_container_limit(self):
        effective, info = self.apply()
        self.assertIs(effective, self.settings)
        self.assertEqual(info, {"low_memory_mode": False, "container_memory_limit_mb": None})

    def test_v1_unlimited_sentinel_and_malformed_values_are_unknown(self):
        for text in ["9223372036854771712", "max", "-1", "invalid", ""]:
            with self.subTest(text=text):
                self.v1.write_text(text, encoding="ascii")
                effective, info = self.apply()
                self.assertIs(effective, self.settings)
                self.assertEqual(info["container_memory_limit_mb"], None)
                self.assertFalse(info["low_memory_mode"])

    def test_32_gib_vm_preserves_full_features_and_configured_parallelism(self):
        self.v2.write_text(str(32 * 1024 * MIB), encoding="ascii")
        effective, info = self.apply()
        self.assertIs(effective, self.settings)
        self.assertEqual(info, {"low_memory_mode": False, "container_memory_limit_mb": 32768})
        self.assertTrue(effective.browser_screenshots_enabled)
        self.assertEqual(effective.scan_concurrency, 3)

    def test_large_container_does_not_enable_explicitly_disabled_features(self):
        self.v2.write_text(str(2 * 1024 * MIB), encoding="ascii")
        configured = replace(self.settings, screenshots_enabled=False,
                             browser_screenshots_enabled=False, screenshot_fallback_enabled=False)
        effective, info = self.apply(configured)
        self.assertIs(effective, configured)
        self.assertFalse(info["low_memory_mode"])
        self.assertFalse(effective.screenshots_enabled)
        self.assertFalse(effective.browser_screenshots_enabled)
        self.assertFalse(effective.screenshot_fallback_enabled)

    def test_unreadable_v2_falls_back_to_available_v1(self):
        self.v2.mkdir()
        self.v1.write_text(str(512 * MIB), encoding="ascii")
        effective, info = self.apply()
        self.assertTrue(info["low_memory_mode"])
        self.assertEqual(effective.scan_concurrency, 1)

    def test_non_ascii_limit_is_treated_as_unknown(self):
        self.v2.write_bytes(b"\xff\xfe")
        effective, info = self.apply()
        self.assertIs(effective, self.settings)
        self.assertIsNone(info["container_memory_limit_mb"])


if __name__ == "__main__":
    unittest.main()
