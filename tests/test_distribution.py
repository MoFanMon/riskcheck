"""Exercise the downloadable distribution, not just the source checkout."""

import hashlib
import importlib.util
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

BASE = Path(__file__).resolve().parents[1]
BUILDER = BASE / "tools" / "build_release.py"
if BUILDER.exists():
    spec = importlib.util.spec_from_file_location("build_release", BUILDER)
    builder = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(builder)
else:
    builder = None


class DistributionTests(unittest.TestCase):
    def build(self, project, output):
        fn = getattr(builder, "build_release", None)
        self.assertTrue(callable(fn), "portable release builder is missing")
        return fn(project, output)

    def test_version_is_available_without_a_target_directory(self):
        result = subprocess.run(
            [sys.executable, "-I", "-S", str(BASE / "riskcheck.py"), "--version"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertRegex(result.stdout.strip(), r"^riskcheck-offline \d+\.\d+\.\d+$")

    def test_portable_archive_runs_away_from_checkout_with_embedded_rules(self):
        with tempfile.TemporaryDirectory() as temp:
            folder = Path(temp)
            artifacts = self.build(BASE, folder / "dist")
            portable = next(p for p in artifacts if p.suffix == ".pyz")
            target = folder / "empty"
            target.mkdir()
            result = subprocess.run(
                [
                    sys.executable,
                    "-I",
                    "-S",
                    str(portable),
                    "--root",
                    str(target),
                    "--inventory-only",
                    "--inventory",
                    str(BASE / "examples/inventory-fixed.json"),
                    "--as-of",
                    "2026-10-22",
                    "--format",
                    "json",
                ],
                cwd=target,
                capture_output=True,
                text=True,
                timeout=10,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            report = json.loads(result.stdout)
            self.assertEqual(report["summary"]["gate"], "pass_scoped")
            self.assertRegex(report["tool_version"], r"^\d+\.\d+\.\d+$")
            self.assertEqual(report["summary"]["assets"], 7)
            invalid = folder / "invalid.json"
            invalid.write_text('{"schema_version":1,"rules":[]}', encoding="utf-8")
            bad = subprocess.run(
                [
                    sys.executable,
                    "-I",
                    "-S",
                    str(portable),
                    "--root",
                    str(target),
                    "--rules",
                    str(invalid),
                ],
                capture_output=True,
                text=True,
                timeout=10,
            )
            self.assertEqual(bad.returncode, 2)

    def test_source_download_excludes_private_files_and_git_history(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            project = root / "source"
            shutil.copytree(
                BASE,
                project,
                ignore=shutil.ignore_patterns(
                    ".git",
                    "__pycache__",
                    "dist",
                    "build",
                    "*.egg-info",
                    ".ruff_cache",
                ),
            )
            (project / ".env").write_text("EXAMPLE_PRIVATE_DATA=must-not-publish\n")
            (project / "risk-report.json").write_text("must-not-publish")
            (project / ".git").mkdir()
            (project / ".git/config").write_text("must-not-publish")
            artifacts = self.build(project, root / "dist")
            source = next(p for p in artifacts if p.name.endswith("-source.zip"))
            with zipfile.ZipFile(source) as archive:
                names = {"/".join(p.split("/")[1:]) for p in archive.namelist()}
                self.assertIn("riskcheck.py", names)
                self.assertIn("pyproject.toml", names)
                self.assertIn("LICENSE", names)
                self.assertIn("requirements-dev.txt", names)
                self.assertNotIn(".env", names)
                self.assertNotIn("risk-report.json", names)
                self.assertFalse(any(".git/" in p for p in names))

    def test_missing_bundled_data_reports_an_error_without_a_traceback(self):
        with tempfile.TemporaryDirectory() as temp:
            script = Path(temp) / "riskcheck.py"
            shutil.copyfile(BASE / "riskcheck.py", script)
            result = subprocess.run(
                [sys.executable, "-I", "-S", str(script), "--root", temp],
                capture_output=True,
                text=True,
                timeout=10,
            )
            self.assertEqual(result.returncode, 2)
            self.assertNotIn("Traceback", result.stderr)

    def test_download_checksums_cover_the_actual_artifact_bytes(self):
        with tempfile.TemporaryDirectory() as temp:
            artifacts = self.build(BASE, Path(temp))
            manifest = next(p for p in artifacts if p.name == "SHA256SUMS")
            entries = {}
            for line in manifest.read_text().splitlines():
                digest, filename = line.split("  ", 1)
                entries[filename] = digest
            payloads = [p for p in artifacts if p != manifest]
            self.assertTrue(payloads)
            self.assertEqual(set(entries), {p.name for p in payloads})
            for payload in payloads:
                self.assertEqual(
                    entries[payload.name], hashlib.sha256(payload.read_bytes()).hexdigest()
                )


if __name__ == "__main__":
    unittest.main()
