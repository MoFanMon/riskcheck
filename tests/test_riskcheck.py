"""Regression tests: wrong boundaries, silent gaps, and executing target code are bugs."""
import importlib.util
import inspect
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

BASE = Path(__file__).resolve().parents[1]
SCRIPT = BASE / "riskcheck.py"
if SCRIPT.exists():
    spec = importlib.util.spec_from_file_location("riskcheck", SCRIPT)
    rc = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(rc)
else:
    rc = None


class RiskCheckTests(unittest.TestCase):
    def call(self, name, *args, **kwargs):
        fn = getattr(rc, name, None)
        self.assertTrue(callable(fn), "missing behavior: " + name)
        return fn(*args, **kwargs)

    def assess(self, component, version, **extra):
        return self.call("assess_asset", dict(component=component, version=version,
                                             id="asset", kind="runtime", **extra))

    def item(self, results, rule):
        return next(x for x in results if x["rule_id"] == rule)

    def scan(self, files=None, inventory=None, **kwargs):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for name, data in (files or {}).items():
                p = root / name
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_text(data, encoding="utf-8")
            inv = None
            if inventory is not None:
                inv = root / "inventory.json"
                inv.write_text(json.dumps(inventory), encoding="utf-8")
            return self.call("scan", root, inventory=inv, as_of=kwargs.pop("as_of", "2026-10-22"), **kwargs)

    def test_node_branch_patch_boundaries_and_prerelease_are_not_conflated(self):
        # A comparison treating the fix or its release candidate as vulnerable/safe incorrectly fails.
        for version, status in [("22.23.3", "affected"), ("22.23.4", "not_affected"),
                                ("24.22.0", "affected"), ("24.22.1", "not_affected"),
                                ("26.12.0", "affected"), ("26.12.1", "not_affected"),
                                ("24.22.1-rc.1", "unknown")]:
            with self.subTest(version=version):
                self.assertEqual(self.item(self.assess("node", version),
                                           "CVE-2026-111497")["status"], status)

    def test_node_22_is_not_affected_by_the_fullwidth_regression(self):
        self.assertEqual(self.item(self.assess("node", "22.23.3"),
                                   "CVE-2026-105483")["status"], "not_affected")

    def test_realpath_issue_is_not_limited_to_node_26(self):
        self.assertEqual(self.item(self.assess("node", "22.23.3"),
                                   "CVE-2026-106073")["status"], "affected")

    def test_node_eol_and_unknown_future_branches_are_not_cleared(self):
        for version in ("20.19.0", "27.0.0", ">=24", "latest", "24.22"):
            with self.subTest(version=version):
                results = self.assess("node", version)
                self.assertTrue(results)
                self.assertTrue(all(x["status"] == "unknown" for x in results))

    def test_php_patch_boundary_and_vendor_suffix_need_vendor_evidence(self):
        for version, status in [("8.3.35", "affected"), ("8.3.36", "not_affected"),
                                ("8.2.35", "not_affected"), ("8.4.27", "not_affected"),
                                ("8.5.12", "not_affected"), ("8.1.34", "unknown"),
                                ("8.3.6-0ubuntu0.24.04.13", "unknown")]:
            self.assertEqual(self.item(self.assess("php", version),
                                       "CVE-2026-109618")["status"], status)

    def test_vendor_attestation_is_per_rule_and_not_independent_verification(self):
        results = self.assess("php", "8.3.6-0ubuntu0.24.04.13", vendor_fixes=[
            {"rule_id": "CVE-2026-109618", "reference": "https://ubuntu.com/security/notices/USN-8948-1"}])
        item = self.item(results, "CVE-2026-109618")
        self.assertEqual(item["status"], "vendor_attested")
        self.assertEqual(item["confidence"], "user_attested")
        self.assertEqual(self.item(results, "CVE-2026-109619")["status"], "unknown")

    def test_nginx_narrow_regression_ranges_and_stable_fix(self):
        cases = [("1.29.9", "CVE-2026-93479", "not_affected"),
                 ("1.31.1", "CVE-2026-93479", "not_affected"),
                 ("1.31.2", "CVE-2026-93479", "affected"),
                 ("1.30.5", "CVE-2026-15176", "affected"),
                 ("1.30.6", "CVE-2026-15176", "not_affected"),
                 ("1.31.7", "CVE-2026-95101", "not_affected"),
                 ("1.24.0", "CVE-2026-95101", "not_affected")]
        for version, rule, status in cases:
            with self.subTest(version=version, rule=rule):
                self.assertEqual(self.item(self.assess("nginx", version), rule)["status"], status)

    def test_go_supported_branches_and_older_binaries(self):
        for version, status in [("go1.26.9", "affected"), ("go1.26.10", "not_affected"),
                                ("1.27.2", "affected"), ("1.27.3", "not_affected"),
                                ("1.25.0", "affected"), ("1.28.0", "unknown")]:
            self.assertEqual(self.item(self.assess("go", version),
                                       "CVE-2026-111943")["status"], status)

    def test_tomcat_exact_branches(self):
        for version, status in [("9.0.122", "affected"), ("9.0.123", "not_affected"),
                                ("10.1.60", "affected"), ("10.1.61", "not_affected"),
                                ("11.0.26", "affected"), ("11.0.27", "not_affected"),
                                ("10.0.27", "unknown")]:
            self.assertEqual(self.item(self.assess("tomcat", version),
                                       "CVE-2026-101296")["status"], status)

    def test_rust_prerelease_and_compatibility_wrapper_do_not_get_blanket_pass(self):
        for version, status in [("0.103.15", "affected"), ("0.103.16", "not_affected"),
                                ("0.104.0-alpha.1", "affected"),
                                ("0.104.0-alpha.8", "not_affected")]:
            self.assertEqual(self.item(self.assess("rustls-webpki", version),
                                       "RUSTSEC-2026-0382")["status"], status)
        self.assertEqual(self.item(self.assess("webpki-roots", "0.26.11"),
                                   "RUSTSEC-2026-0381")["status"], "unknown")

    def test_context_false_does_not_suppress_vulnerable_version(self):
        item = self.item(self.assess("node", "24.22.0", context={"brotli_untrusted": False}),
                         "CVE-2026-111497")
        self.assertEqual(item["status"], "affected")
        self.assertEqual(item["reachability"], "user_reports_absent")

    def test_known_litellm_digest_and_historical_execution_survive_current_upgrade(self):
        report = self.scan(inventory={"schema_version": 1, "assets": [
            {"id": "current", "component": "litellm", "version": "1.106.2"},
            {"id": "history", "component": "litellm", "version": "1.107.0",
             "kind": "historical", "context": {"executed": True}}]})
        self.assertTrue(any(x["status"] == "exposure" and x["asset_id"] == "history"
                            for x in report["findings"]))
        self.assertEqual(self.call("exit_code", report), 1)
        digest = "sha256:1bbcb1443bc962e45f5aad53fe3d2c30600e0379715fb6c664cdd3ac126c339e"
        match = self.assess("litellm", "unknown", digest=digest)
        self.assertEqual(match[0]["status"], "artifact_match")

    def test_lockfile_is_a_version_match_not_confirmed_execution(self):
        report = self.scan({"requirements.txt": "litellm==1.107.0\n"})
        finding = report["findings"][0]
        self.assertEqual(finding["status"], "affected")
        self.assertEqual(finding["kind"], "locked")
        self.assertNotEqual(finding["confidence"], "execution_confirmed")

    def test_go_mod_minimum_is_not_treated_as_build_toolchain(self):
        report = self.scan({"go.mod": "module example.org/api\n\ngo 1.26.0\n"})
        self.assertTrue(any(x["status"] == "unknown" for x in report["findings"]))
        self.assertFalse(any(x["status"] == "affected" for x in report["findings"]))

    def test_cargo_lock_distinct_versions_and_safe_wrapper_parent(self):
        lock = ('version = 4\n\n[[package]]\nname = "webpki-roots"\nversion = "0.26.11"\n'
                'dependencies = ["webpki-root-certs"]\n\n[[package]]\n'
                'name = "webpki-root-certs"\nversion = "1.0.10"\n\n[[package]]\n'
                'name = "rustls-webpki"\nversion = "0.103.15"\n\n[[package]]\n'
                'name = "rustls-webpki"\nversion = "0.103.16"\n')
        report = self.scan({"Cargo.lock": lock})
        self.assertTrue(any(x["component"] == "rustls-webpki" and x["status"] == "affected"
                            for x in report["findings"]))
        wrapper = next(x for x in report["findings"] if x["component"] == "webpki-roots")
        # Merely seeing a safe parent in the same lockfile does not prove its graph edge.
        self.assertEqual(wrapper["status"], "unknown")

    def test_docker_exact_tags_and_floating_tags(self):
        report = self.scan({"Dockerfile": "FROM node:24.22.0-alpine AS builder\nFROM node:24-alpine\n"})
        self.assertTrue(any(x["status"] == "affected" for x in report["findings"]))
        self.assertTrue(any(x["status"] == "unknown" for x in report["findings"]))

    def test_golang_base_image_and_unrelated_multiline_run(self):
        report = self.scan({"Dockerfile": 'FROM golang:1.27.2-alpine\nRUN echo "a \\\n+b"\n'})
        self.assertTrue(any(x["component"] == "go" and x["status"] == "affected"
                            for x in report["findings"]))
        self.assertFalse(report["gaps"])

    def test_official_docker_hub_litellm_name_is_detected(self):
        report = self.scan({"Dockerfile": "FROM docker.io/litellm/litellm:v1.107.0\n"})
        self.assertTrue(any(x["component"] == "litellm" and x["status"] == "affected"
                            for x in report["findings"]))

    def test_empty_directory_explosion_is_bounded(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / ".nvmrc").write_text("24.22.1\n")
            for i in range(8):
                (root / str(i)).mkdir()
            report = self.call("scan", root, as_of="2026-10-22", max_files=3)
            self.assertTrue(report["gaps"])
            self.assertEqual(self.call("exit_code", report), 2)

    def test_similarly_named_python_package_is_not_litellm(self):
        report = self.scan({"requirements.txt": "litellm-proxy==1.107.0\n", ".nvmrc": "24.22.1\n"})
        self.assertFalse(any(x["component"] == "litellm" for x in report["assets"]))
        self.assertEqual(self.call("exit_code", report), 0)

    def test_inventory_only_uses_explicit_assets_without_ambiguous_declarations(self):
        self.assertIn("inventory_only", inspect.signature(rc.scan).parameters,
                      "scan must support an explicit inventory-only scope")
        report = self.scan({"go.mod": "module example.org/test\ngo 1.26\n"}, inventory={
            "schema_version": 1, "assets": [{"id": "build", "component": "go", "version": "1.27.3"}]
        }, inventory_only=True)
        self.assertEqual(self.call("exit_code", report), 0)
        self.assertEqual(report["coverage"]["mode"], "inventory_only")

    def test_empty_rules_and_uncovered_assets_are_not_cleared(self):
        self.assertTrue(SCRIPT.exists())
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / ".nvmrc").write_text("24.22.1\n")
            rules = root / "custom-rules.json"
            document = json.loads((BASE / "rules.json").read_text())
            document["rules"] = []
            rules.write_text(json.dumps(document))
            p = subprocess.run([sys.executable, "-I", "-S", str(SCRIPT), "--root", tmp,
                                "--rules", str(rules), "--as-of", "2026-10-22"],
                               capture_output=True, text=True, timeout=10)
            self.assertEqual(p.returncode, 2)
            self.assertNotIn("Traceback", p.stderr)
            document["rules"] = [dict(id="ONLY-PHP", component="php", severity="high", title="test",
                                      condition="serves_web", precondition="test", action="test")]
            rules.write_text(json.dumps(document))
            report = self.call("scan", root, rules_path=rules, as_of="2026-10-22")
            self.assertEqual(self.call("exit_code", report), 2)

    def test_constraints_environment_markers_and_includes_are_not_cleared(self):
        report = self.scan({"requirements.txt": 'litellm>=1.106\n-r extra.txt\nlitellm==1.107.0; python_version < "3"\n'})
        self.assertTrue(any(x["status"] == "unknown" for x in report["findings"]))
        self.assertTrue(report["gaps"])

    def test_static_config_hints_are_not_proof_of_exploitability_or_secret_leaks(self):
        report = self.scan({"nginx.conf": 'location / { alias /secret; rewrite ^ /x; }\n'
                           '# listen 443 quic;\nset $api_key SECRET_SHOULD_NOT_LEAK;\n',
                           "server.xml": '<Server><Realm className="org.apache.catalina.realm.JNDIRealm" '
                           'authentication="DIGEST-MD5" connectionPassword="SECRET_SHOULD_NOT_LEAK"/></Server>'})
        encoded = json.dumps(report)
        self.assertNotIn("SECRET_SHOULD_NOT_LEAK", encoded)
        names = {x["feature"] for x in report["signals"]}
        self.assertIn("nginx_alias_rewrite", names)
        self.assertIn("tomcat_non_gssapi_sasl", names)
        self.assertNotIn("nginx_http3", names)
        self.assertTrue(all(x["confidence"] == "static_hint" for x in report["signals"]))

    def test_source_files_are_never_executed_and_generic_sitecustomize_is_only_a_hint(self):
        report = self.scan({"sitecustomize.py": "raise RuntimeError('MUST NOT EXECUTE')\n",
                           "lib/python/site-packages/litellm-1.107.0.dist-info/METADATA":
                           "Metadata-Version: 2.1\nName: litellm\nVersion: 1.107.0\n",
                           ".env": "SECRET_SHOULD_NOT_LEAK=1\n"})
        self.assertTrue(any(x["kind"] == "installed" for x in report["findings"]))
        self.assertTrue(any(x["feature"] == "python_startup_file" for x in report["signals"]))
        self.assertNotIn("SECRET_SHOULD_NOT_LEAK", json.dumps(report))

    def test_symlinked_file_is_not_followed_and_scan_gap_is_visible(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "target"
            root.mkdir()
            outside = Path(tmp) / "outside"
            outside.write_text("litellm==1.107.0\n")
            (root / "requirements.txt").symlink_to(outside)
            report = self.call("scan", root, as_of="2026-10-22")
            self.assertFalse(report["assets"])
            self.assertTrue(report["gaps"])
            self.assertEqual(self.call("exit_code", report), 2)

    def test_oversized_or_invalid_manifest_is_not_silently_skipped(self):
        for files, options in [({"package.json": "{broken"}, {}),
                               ({"requirements.txt": "x" * 200}, {"max_bytes": 100})]:
            report = self.scan(files, **options)
            self.assertTrue(report["gaps"])
            self.assertEqual(self.call("exit_code", report), 2)

    def test_empty_scan_and_missing_required_component_fail_closed(self):
        empty = self.scan()
        self.assertEqual(self.call("exit_code", empty), 2)
        report = self.scan({".nvmrc": "24.22.1\n"}, required=["node", "php"])
        self.assertEqual(self.call("exit_code", report), 2)

    def test_stale_rule_database_fails_closed(self):
        report = self.scan({".nvmrc": "24.22.1\n"}, rules_age_days=30, as_of="2026-12-01")
        self.assertEqual(self.call("exit_code", report), 2)

    def test_threshold_does_not_hide_high_risk_and_fixed_scan_only_clears_scoped_rules(self):
        fixed = self.scan({".nvmrc": "24.22.1\n"})
        self.assertEqual(self.call("exit_code", fixed), 0)
        bad = self.scan({".nvmrc": "24.22.0\n"})
        self.assertEqual(self.call("exit_code", bad, fail_on="high"), 1)
        self.assertTrue(fixed["not_assessed"])

    def test_xml_entities_rejected_without_expansion(self):
        report = self.scan({"server.xml": '<!DOCTYPE x [<!ENTITY a "secret">]><Server>&a;</Server>'})
        self.assertTrue(report["gaps"])

    def test_inventory_schema_errors_are_actionable(self):
        report = self.scan(inventory={"schema_version": 1, "assets": [{"version": "1.0.0"}]})
        self.assertTrue(report["gaps"])
        self.assertEqual(self.call("exit_code", report), 2)

    def test_html_escapes_untrusted_asset_names(self):
        report = self.scan(inventory={"schema_version": 1, "assets": [
            {"id": '<img src=x onerror=alert(1)>', "component": "node", "version": "24.22.0"}]})
        html = self.call("render_html", report)
        self.assertNotIn("<img src=x", html)
        self.assertIn("&lt;img", html)
        self.assertIn("Content-Security-Policy", html)

    def test_cli_emits_parseable_json_and_ci_exit_code(self):
        self.assertTrue(SCRIPT.exists(), "missing offline CLI")
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / ".nvmrc").write_text("24.22.0\n")
            p = subprocess.run([sys.executable, "-I", "-S", str(SCRIPT), "--root", tmp,
                                "--as-of", "2026-10-22", "--format", "json"],
                               capture_output=True, text=True, timeout=10)
            self.assertEqual(p.returncode, 1, p.stderr)
            result = json.loads(p.stdout)
            self.assertEqual(result["summary"]["gate"], "fail")


if __name__ == "__main__":
    unittest.main()
