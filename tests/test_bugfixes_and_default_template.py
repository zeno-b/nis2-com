import os
import json
import http.server
import shutil
import socketserver
import subprocess
import tempfile
import threading
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

os.environ.setdefault("SCANNER_SKIP_PREREQ_CHECK", "1")

import scanner


class DefaultTemplateTests(unittest.TestCase):
    def test_default_template_is_t_yaml(self):
        self.assertEqual(scanner.DEFAULT_TEMPLATES, ["t.yaml"])

    def test_bundled_t_yaml_exists_and_resolves(self):
        fp = scanner.resolve_template_path("t.yaml")
        self.assertIsNotNone(fp, "t.yaml should resolve next to scanner.py")
        self.assertTrue(Path(fp).exists())

    def test_default_template_parses_named_checks(self):
        checks = scanner.parse_template_checks(scanner.DEFAULT_TEMPLATES)
        total = sum(len(v["checks"]) for v in checks.values())
        self.assertGreater(total, 0, "t.yaml must expose at least one named matcher")

    def test_default_template_severity_matches_default_filter(self):
        checks = scanner.parse_template_checks(scanner.DEFAULT_TEMPLATES)
        severities = {
            check["severity"]
            for template in checks.values()
            for check in template["checks"]
        }
        default_severities = set(scanner.DEFAULT_SEVERITY.split(","))
        self.assertTrue(severities)
        self.assertTrue(severities <= default_severities)

    def test_default_template_executes_with_nuclei_when_available(self):
        nuclei_bin = shutil.which("nuclei")
        local_nuclei = Path.home() / ".local" / "bin" / "nuclei"
        if nuclei_bin is None and local_nuclei.exists():
            nuclei_bin = str(local_nuclei)
        if nuclei_bin is None:
            self.skipTest("nuclei binary is not installed")

        class ThreadedTCPServer(socketserver.ThreadingMixIn,
                                socketserver.TCPServer):
            daemon_threads = True

        class BaselineHandler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                body = (
                    b"<html><head><meta name='generator' content='test'>"
                    b"</head><body>It works!</body></html>"
                )
                self.send_response(200)
                self.send_header("Server", "UnitTest/1.0")
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Security-Policy",
                                 "default-src 'self'; script-src 'unsafe-inline'")
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args):
                return

        with ThreadedTCPServer(("127.0.0.1", 0), BaselineHandler) as server:
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                with tempfile.TemporaryDirectory() as d:
                    target_file = Path(d) / "targets.txt"
                    output_file = Path(d) / "nuclei_results.jsonl"
                    target_file.write_text(
                        f"http://127.0.0.1:{server.server_address[1]}\n",
                        encoding="utf-8")

                    cmd = scanner.build_nuclei_cmd(
                        str(target_file), str(output_file),
                        scanner.DEFAULT_TEMPLATES,
                        rate=10, concur=2, timeout=5,
                        severity=scanner.DEFAULT_SEVERITY,
                        proxy=None)
                    cmd[0] = nuclei_bin
                    cmd = [arg for arg in cmd if arg != "-stats"]
                    cmd.extend(["-silent", "-omit-template", "-omit-raw"])

                    result = subprocess.run(
                        cmd, capture_output=True, text=True,
                        stdin=subprocess.DEVNULL, timeout=30)
                    self.assertEqual(
                        result.returncode, 0,
                        result.stdout[-2000:] + result.stderr[-2000:])

                    lines = [
                        json.loads(line)
                        for line in output_file.read_text(
                            encoding="utf-8").splitlines()
                        if line.strip()
                    ]
                    self.assertTrue(lines, "nuclei emitted no findings")
                    self.assertTrue(any(
                        row.get("template-id") == "t-default-nis2-headers"
                        for row in lines))
            finally:
                server.shutdown()


class BuildNucleiCmdTests(unittest.TestCase):
    def test_all_templates_are_added(self):
        templates = ["t.yaml", "http/a.yaml", "http/b.yaml"]
        cmd = scanner.build_nuclei_cmd(
            "targets.txt", "out.json", templates,
            rate=10, concur=3, timeout=5, severity="info", proxy=None)
        self.assertEqual(cmd.count("-t"), len(templates))
        self.assertEqual(cmd[0], "nuclei")

    def test_proxy_is_appended(self):
        cmd = scanner.build_nuclei_cmd(
            "targets.txt", "out.json", ["t.yaml"],
            rate=10, concur=3, timeout=5, severity="info",
            proxy="http://127.0.0.1:8080")
        self.assertIn("-proxy", cmd)
        self.assertIn("http://127.0.0.1:8080", cmd)


class RunNucleiReturnTests(unittest.TestCase):
    def test_run_nuclei_returns_int_on_success(self):
        fake_proc = mock.Mock()
        fake_proc.wait.return_value = None
        fake_proc.returncode = 0
        with mock.patch.object(scanner.subprocess, "Popen", return_value=fake_proc):
            rc = scanner.run_nuclei(
                "targets.txt", "out.json", ["t.yaml"],
                rate=10, concur=3, timeout=5, severity="info", proxy=None)
        self.assertEqual(rc, 0)


class FindFailedTargetsTests(unittest.TestCase):
    def test_returns_failed_hosts_on_success(self):
        with tempfile.TemporaryDirectory() as d:
            out = Path(d) / "nuclei_results.json"
            out.write_text(
                json.dumps({"type": "error", "host": "http://a.example/"}) + "\n" +
                json.dumps({"type": "error", "input": "http://b.example"}) + "\n" +
                json.dumps({"template-id": "x", "host": "http://c.example"}) + "\n",
                encoding="utf-8")
            failed = scanner.find_failed_targets(str(out))
        self.assertIsInstance(failed, list)
        self.assertCountEqual(failed, ["http://a.example", "http://b.example"])

    def test_returns_empty_list_when_missing(self):
        self.assertEqual(scanner.find_failed_targets("/nonexistent/path.json"), [])


class LoadExcludeListTests(unittest.TestCase):
    def test_returns_set_on_success(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "exclude.txt"
            p.write_text("# comment\nExample.com\n\nfoo.be\n", encoding="utf-8")
            result = scanner.load_exclude_list(str(p))
        self.assertEqual(result, {"example.com", "foo.be"})

    def test_missing_file_returns_empty_set(self):
        self.assertEqual(scanner.load_exclude_list("/nope/exclude.txt"), set())


class FilterResolvableTests(unittest.TestCase):
    def test_returns_resolved_list(self):
        urls = ["http://a.example", "http://b.example"]
        with mock.patch.object(scanner, "_resolve_one_dns",
                               side_effect=lambda u: (u, True, None)):
            resolved = scanner.filter_resolvable(urls)
        self.assertIsInstance(resolved, list)
        self.assertCountEqual(resolved, urls)


class RetryFailedTargetsTests(unittest.TestCase):
    def test_runs_nuclei_for_failed_targets(self):
        with tempfile.TemporaryDirectory() as d:
            out = Path(d) / "nuclei_results.json"
            out.write_text(
                json.dumps({"type": "error", "host": "http://a.example"}) + "\n",
                encoding="utf-8")
            with mock.patch.object(scanner, "run_nuclei", return_value=0) as m:
                scanner.retry_failed_targets(
                    d, str(out), ["t.yaml"],
                    rate=10, concur=3, timeout=5, severity="info", proxy=None)
            self.assertEqual(m.call_count, 1)
            self.assertTrue((Path(d) / scanner.RETRY_FILE).exists())

    def test_noop_when_no_failures(self):
        with tempfile.TemporaryDirectory() as d:
            out = Path(d) / "nuclei_results.json"
            out.write_text("", encoding="utf-8")
            with mock.patch.object(scanner, "run_nuclei", return_value=0) as m:
                scanner.retry_failed_targets(
                    d, str(out), ["t.yaml"],
                    rate=10, concur=3, timeout=5, severity="info", proxy=None)
            self.assertEqual(m.call_count, 0)


class ExampleConfigTests(unittest.TestCase):
    def test_example_config_is_valid_yaml_with_t_yaml(self):
        import yaml
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "ex.yml"
            scanner.write_example_config(str(p))
            cfg = yaml.safe_load(p.read_text(encoding="utf-8"))
        self.assertIsInstance(cfg, dict)
        self.assertEqual(cfg.get("templates"), ["t.yaml"])
        self.assertEqual(cfg.get("sector"), ["Health"])


class ApplyConfigTests(unittest.TestCase):
    def test_new_keys_applied(self):
        args = SimpleNamespace(
            enrich_contacts=False, no_smtp=False, hunter_key="",
            export_xlsx=False, annex1_only=False, run_mode="auto")
        scanner.apply_config_to_args(
            {"enrich_contacts": True, "no_smtp": True, "hunter_key": "k",
             "export_xlsx": True, "annex1_only": True}, args)
        self.assertTrue(args.enrich_contacts)
        self.assertTrue(args.no_smtp)
        self.assertEqual(args.hunter_key, "k")
        self.assertTrue(args.export_xlsx)
        self.assertTrue(args.annex1_only)


class SaveCoverageCsvTests(unittest.TestCase):
    def test_writes_csv_once_and_returns_path(self):
        matrix = {
            "http://a.example": {
                "tid/check1": {"status": "FINDING", "severity": "high",
                               "template": "tid"},
            }
        }
        all_checks = [{"key": "tid/check1", "template": "tid",
                       "name": "check1", "severity": "high"}]
        with tempfile.TemporaryDirectory() as d:
            path = scanner.save_coverage_csv(matrix, all_checks, {}, {}, d)
            self.assertIsNotNone(path)
            content = Path(path).read_text(encoding="utf-8").strip().splitlines()
        # 1 header row + 1 data row (host x check)
        self.assertEqual(len(content), 2)
        self.assertTrue(content[0].startswith("Host,Company"))


class ReadableScanReportTests(unittest.TestCase):
    def test_coverage_matrix_includes_finding_url_variants(self):
        template_checks = {
            "tid": {"path": "t.yaml",
                    "checks": [{"name": "check1", "severity": "low"}]}
        }
        findings = [{
            "template-id": "tid",
            "matcher-name": "check1",
            "host": "https://a.example:443",
            "matched-at": "https://a.example:443/",
            "info": {"severity": "low", "description": "variant URL finding"},
        }]

        matrix, all_checks = scanner.build_coverage_matrix(
            findings, ["https://a.example"], template_checks)
        report, _ = scanner._build_readable_scan_report(
            matrix, all_checks, findings, ["https://a.example"],
            {}, {}, "nuclei_results.json")

        self.assertEqual(
            matrix["https://a.example:443"]["tid/check1"]["status"],
            "FINDING")
        self.assertEqual(report["summary"]["hosts_scanned"], 1)
        self.assertEqual(report["summary"]["urls_reported"], 2)
        self.assertEqual(report["summary"]["hosts_affected"], 1)
        self.assertEqual(report["summary"]["finding_checks"], 1)
        self.assertEqual(
            report["findings_by_url"][0]["host"],
            "https://a.example:443")

    def test_save_readable_scan_reports_writes_json_csv_html(self):
        matrix = {
            "https://a.example": {
                "tid/check1": {"status": "FINDING", "severity": "low",
                               "template": "tid"},
                "tid/check2": {"status": "CLEAN", "severity": "low",
                               "template": "tid"},
            }
        }
        all_checks = [
            {"key": "tid/check1", "template": "tid",
             "name": "check1", "severity": "low"},
            {"key": "tid/check2", "template": "tid",
             "name": "check2", "severity": "low"},
        ]
        findings = [{
            "template-id": "tid",
            "matcher-name": "check1",
            "host": "https://a.example",
            "matched-at": "https://a.example/",
            "extracted-results": ["X-Test: vulnerable"],
            "info": {"severity": "low", "description": "test finding"},
        }]
        with tempfile.TemporaryDirectory() as d:
            paths = scanner.save_readable_scan_reports(
                matrix, all_checks, findings, ["https://a.example"],
                {}, {}, d, str(Path(d) / "nuclei_results.json"))
            json_data = json.loads(Path(paths["json"]).read_text(encoding="utf-8"))
            csv_content = Path(paths["csv"]).read_text(encoding="utf-8")
            html_content = Path(paths["html"]).read_text(encoding="utf-8")

        self.assertEqual(json_data["summary"]["hosts_scanned"], 1)
        self.assertEqual(json_data["summary"]["hosts_affected"], 1)
        self.assertEqual(json_data["summary"]["finding_checks"], 1)
        self.assertIn("findings_by_url", json_data)
        self.assertIn("Host,Company,Entity", csv_content)
        self.assertIn("Executive_Summary", csv_content)
        self.assertIn("Risk", csv_content)
        self.assertIn("Remediation", csv_content)
        self.assertIn("Matched at: https://a.example/", csv_content)
        self.assertIn("X-Test: vulnerable", csv_content)
        self.assertIn("Findings per URL", html_content)
        self.assertIn("Nuclei finding events", html_content)
        self.assertIn("Executive summary", html_content)
        self.assertIn("Remediation", html_content)
        self.assertIn("https://a.example", html_content)
        finding = json_data["findings_by_url"][0]["findings"][0]
        self.assertIn("Matched at: https://a.example/", finding["evidence"])
        self.assertIn("X-Test: vulnerable", finding["evidence"])
        self.assertIn("test finding", finding["executive_summary"])
        self.assertIn("Low risk", finding["risk"])
        self.assertIn("Track as hardening debt", finding["remediation"])
        self.assertIn("Executive summary:", finding["description"])
        self.assertIn("Risk:", finding["description"])
        self.assertIn("Remediation:", finding["description"])

    def test_print_scan_summary_writes_reports_for_empty_results(self):
        template_checks = {
            "tid": {"path": "t.yaml",
                    "checks": [{"name": "check1", "severity": "low"}]}
        }
        with tempfile.TemporaryDirectory() as d:
            results = Path(d) / "nuclei_results.json"
            results.write_text("", encoding="utf-8")
            scanner.print_scan_summary(
                str(results),
                output_dir=d,
                template_checks=template_checks,
                scanned_hosts=["https://clean.example"],
            )
            self.assertTrue((Path(d) / scanner.SCAN_RESULTS_JSON).exists())
            self.assertTrue((Path(d) / scanner.SCAN_RESULTS_CSV).exists())
            self.assertTrue((Path(d) / scanner.SCAN_RESULTS_HTML).exists())
            data = json.loads((Path(d) / scanner.SCAN_RESULTS_JSON).read_text(
                encoding="utf-8"))

        self.assertEqual(data["summary"]["findings_total"], 0)
        self.assertEqual(data["summary"]["hosts_clean"], 1)


class CompanyResolutionTests(unittest.TestCase):
    """A URL discovered from a KBO code must still resolve to its company even
    after redirects change the scheme, add a www. prefix, a port, or a path."""

    def _lookup(self):
        import pandas as pd
        df = pd.DataFrame([{
            "EntityNumber": "0123456789",
            "NaceCode": "62010",
            "NIS2_Sector": "Digital infrastructure",
        }])
        websites = {"0123456789": "example.com"}
        denoms = {"0123456789": "Example NV"}
        return scanner.build_url_company_lookup(df, websites, denoms)

    def test_resolves_url_variants_to_company(self):
        lookup, hidx = self._lookup()
        for probe in (
            "https://example.com",
            "http://example.com/",
            "https://www.example.com",
            "https://www.example.com/en/team",
            "https://example.com:443/path",
            "www.example.com",
        ):
            co = scanner.resolve_company(probe, lookup, hidx)
            self.assertIsNotNone(co, f"{probe} should resolve to a company")
            self.assertEqual(co["name"], "Example NV", probe)

    def test_unknown_host_returns_none(self):
        lookup, hidx = self._lookup()
        self.assertIsNone(
            scanner.resolve_company("https://unrelated.test", lookup, hidx))


class FindingRiskRemediationTests(unittest.TestCase):
    """Risk/remediation must be specific to the finding, including the matcher
    names emitted by the bundled default template (t.yaml)."""

    def test_default_template_matcher_names_have_mappings(self):
        checks = scanner.parse_template_checks(scanner.DEFAULT_TEMPLATES)
        names = {
            ch["name"]
            for tdata in checks.values()
            for ch in tdata["checks"]
        }
        self.assertTrue(names, "default template should expose matcher names")
        missing_desc = sorted(
            n for n in names if n not in scanner.FINDING_MATCHER_DESCRIPTIONS)
        missing_rem = sorted(
            n for n in names if n not in scanner.FINDING_MATCHER_REMEDIATIONS)
        self.assertEqual(missing_desc, [], f"missing descriptions: {missing_desc}")
        self.assertEqual(missing_rem, [], f"missing remediations: {missing_rem}")

    def test_finding_summary_is_specific_not_generic(self):
        finding = {
            "template-id": "t-default-nis2-headers",
            "matcher-name": "missing-strict-transport-security",
            "host": "https://a.example",
            "matched-at": "https://a.example/",
            "info": {"severity": "low"},
        }
        summary = scanner._finding_summary(finding)
        self.assertIn("Strict-Transport-Security", summary["risk"])
        self.assertIn("HSTS", summary["remediation"])
        # The generic hardening-debt fallback must NOT be used here.
        self.assertNotIn("Track as hardening debt", summary["remediation"])

    def test_remediation_falls_back_to_template_id(self):
        # No matcher-name, but the template-id matches a known key.
        action = scanner._finding_remediation("(no-matcher-name)", "medium",
                                              template="missing-csp")
        self.assertIn("CSP", action)


if __name__ == "__main__":
    unittest.main()
