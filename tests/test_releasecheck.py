#!/usr/bin/env python3
"""Tests for releasecheck. Standard library only:  python3 -m unittest discover -s tests -v
"""
from __future__ import annotations

import contextlib
import io
import json
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE.parent / "demo"))

import releasecheck  # noqa: E402
import make_fixtures  # noqa: E402


class TestHelpers(unittest.TestCase):
    def test_mask_never_reveals_the_value(self):
        secret = b"ghp_Aa0Bb1Cc2Dd3Ee4Ff5Gg6Hh7Ii8Jj9Kk0Ll1"
        self.assertNotIn(b"Aa0Bb1Cc2Dd3Ee4Ff".decode(), releasecheck.mask(secret))

    def test_image_size_reads_png_and_gif(self):
        with tempfile.TemporaryDirectory() as tmp:
            png = Path(tmp) / "a.png"
            make_fixtures.build_png(png, 1600, 2560)
            self.assertEqual(releasecheck.image_size(png.read_bytes()), (1600, 2560))
        self.assertEqual(releasecheck.image_size(b"GIF89a\x40\x01\xf0\x00"), (320, 240))

    def test_pdf_info_flags_truncation_and_encryption(self):
        with tempfile.TemporaryDirectory() as tmp:
            pdf = Path(tmp) / "b.pdf"
            make_fixtures.build_pdf(pdf, pages=2)
            info = releasecheck.pdf_info(pdf.read_bytes())
            self.assertTrue(info["header"])
            self.assertTrue(info["eof"])
            self.assertEqual(info["pages_approx"], 2)
            self.assertFalse(info["encrypted"])
        self.assertFalse(releasecheck.pdf_info(b"%PDF-1.4\n/Encrypt 5 0 R")["eof"])


class TestChecks(unittest.TestCase):
    def _run(self, folder: Path) -> dict:
        manifest_path = folder / "releasecheck.json"
        manifest = json.loads(manifest_path.read_text()) if manifest_path.is_file() else {}
        return releasecheck.run(folder, manifest, online=False)

    def _status(self, report: dict, check: str) -> set[str]:
        return {item["status"] for item in report["findings"] if item["check"] == check}

    def test_good_fixture_passes(self):
        with tempfile.TemporaryDirectory() as tmp:
            report = self._run(make_fixtures.build_good(Path(tmp) / "good"))
            self.assertEqual(report["status"], "PASS", json.dumps(report["findings"], indent=2))

    def test_broken_fixture_fails_every_intended_check(self):
        with tempfile.TemporaryDirectory() as tmp:
            report = self._run(make_fixtures.build_broken(Path(tmp) / "broken"))
            self.assertEqual(report["status"], "FAIL")
            for check in ("archives", "metadata", "pdf", "images", "hashes", "files", "placeholders",
                          "secrets", "links"):
                self.assertIn("fail", self._status(report, check), f"{check} did not fail")
            self.assertIn("warn", self._status(report, "duplicates"))

    def test_secret_inside_an_archive_is_found_and_masked(self):
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp) / "pack"
            folder.mkdir()
            token = "ghp_" + "Zz9Yy8Xx7Ww6Vv5Uu4Tt3Ss2Rr1Qq0Pp9"
            with zipfile.ZipFile(folder / "bundle.zip", "w") as zf:
                zf.writestr("inner.txt", f"token: '{token}'\n")
            report = self._run(folder)
            secrets = [item for item in report["findings"] if item["check"] == "secrets"]
            self.assertTrue(any(item["status"] == "fail" for item in secrets))
            self.assertNotIn(token, json.dumps(report))

    def test_zip_slip_member_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp) / "pack"
            folder.mkdir()
            with zipfile.ZipFile(folder / "evil.zip", "w") as zf:
                zf.writestr("../../etc/passwd", "x")
            report = self._run(folder)
            self.assertIn("fail", self._status(report, "archives"))
            self.assertTrue(any("zip-slip" in item["message"] for item in report["findings"]))

    def test_stale_hash_is_reported(self):
        with tempfile.TemporaryDirectory() as tmp:
            folder = make_fixtures.build_good(Path(tmp) / "good")
            (folder / "book.epub").write_bytes((folder / "book.epub").read_bytes() + b" ")
            report = self._run(folder)
            self.assertIn("fail", self._status(report, "hashes"))

    def test_offline_mode_skips_external_links(self):
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp) / "site"
            folder.mkdir()
            (folder / "index.html").write_text('<a href="https://example.invalid/">x</a>')
            report = self._run(folder)
            self.assertEqual(self._status(report, "links-online"), {"skip"})


class TestOutput(unittest.TestCase):
    def test_reports_render_and_keep_the_limits(self):
        with tempfile.TemporaryDirectory() as tmp:
            report = releasecheck.run(make_fixtures.build_good(Path(tmp) / "good"), {}, online=False)
            text = releasecheck.render_text(report)
            self.assertIn("What this does not prove", text)
            self.assertIn("does not read the Git history", releasecheck.render_md(report))
            self.assertEqual(text.splitlines()[4], "PASS")

    def test_main_returns_exit_codes(self):
        with tempfile.TemporaryDirectory() as tmp:
            good = make_fixtures.build_good(Path(tmp) / "good")
            broken = make_fixtures.build_broken(Path(tmp) / "broken")
            quiet = ["--quiet"]
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(releasecheck.main(["check", str(good)] + quiet), 0)
                self.assertEqual(releasecheck.main(["check", str(broken)] + quiet), 1)
                self.assertEqual(releasecheck.main(["check", str(Path(tmp) / "nope")] + quiet), 2)


if __name__ == "__main__":
    unittest.main(verbosity=2)
