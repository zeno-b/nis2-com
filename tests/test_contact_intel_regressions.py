import os
import json
import tempfile
import unittest
from unittest import mock
from pathlib import Path

os.environ.setdefault("SCANNER_SKIP_PREREQ_CHECK", "1")

import scanner

try:
    from bs4 import BeautifulSoup
except ImportError:  # pragma: no cover - environment-dependent
    BeautifulSoup = None


class _FakeResponse:
    def __init__(self, text: str):
        self.text = text
        self.status_code = 200


@unittest.skipUnless(BeautifulSoup is not None, "beautifulsoup4 is required")
class ContactIntelRegressionTests(unittest.TestCase):
    def setUp(self):
        self.proxies = {"http": None, "https": None}

    def test_ci_query_infobel_returns_dict_when_only_address_exists(self):
        html = """
        <html><body>
          <script type="application/ld+json">
          {"@type":"Organization","address":{"streetAddress":"Rue Test 1","postalCode":"1000","addressLocality":"Bruxelles"}}
          </script>
        </body></html>
        """
        with mock.patch.object(scanner, "_CI_HTTP", True), \
             mock.patch.object(scanner, "_ci_get", return_value=_FakeResponse(html)), \
             mock.patch.object(scanner, "info"):
            result = scanner.ci_query_infobel("Example Org", self.proxies, 0)

        self.assertIsInstance(result, dict)
        self.assertEqual(result["phone"], "")
        self.assertEqual(result["address"], "Rue Test 1 1000 Bruxelles")

    def test_ci_query_goudengids_returns_empty_shape_when_no_hits(self):
        html = "<html><body><p>No listing</p></body></html>"
        with mock.patch.object(scanner, "_CI_HTTP", True), \
             mock.patch.object(scanner, "_ci_get", return_value=_FakeResponse(html)), \
             mock.patch.object(scanner, "info"):
            result = scanner.ci_query_goudengids("Unknown Org", self.proxies, 0)

        self.assertEqual(result, {"phone": "", "address": ""})

    def test_ci_query_goudengids_extracts_phone_and_address(self):
        html = """
        <html><body>
          <a href="tel:02 123 45 67">Call</a>
          <div class="address">Mainstraat 1, 2000 Antwerpen</div>
        </body></html>
        """
        with mock.patch.object(scanner, "_CI_HTTP", True), \
             mock.patch.object(scanner, "_ci_get", return_value=_FakeResponse(html)), \
             mock.patch.object(scanner, "info"):
            result = scanner.ci_query_goudengids("Listed Org", self.proxies, 0)

        self.assertEqual(result["phone"], "+3221234567")
        self.assertIn("Mainstraat 1", result["address"])

    def test_serp_helpers_collect_multiple_links_and_strip_noise(self):
        soup = BeautifulSoup(
            """
            <html>
              <head><script>const hidden='x';</script><style>.x{}</style></head>
              <body>
                <nav>menu</nav>
                <a href="/url?q=https://example.com/profile&sa=U">Google wrapper</a>
                <a href="https://example.org/about">Direct link</a>
                <a href="https://www.google.com/search?q=test">Ignore engine link</a>
                <p>Visible content</p>
              </body>
            </html>
            """,
            "html.parser",
        )
        links = scanner._ci_serp_links(soup)
        text = scanner._ci_serp_text(soup)

        self.assertIn("https://example.com/profile", links)
        self.assertIn("https://example.org/about", links)
        self.assertNotIn("google.com/search", " ".join(links))
        self.assertIn("Visible content", text)
        self.assertNotIn("const hidden", text)
        self.assertNotIn("menu", text)

    def test_phone_extraction_handles_common_belgian_formats(self):
        text = "Call +32 2 123 45 67 or 0032/2/123.45.67 or 02-123-45-67"
        phones = scanner._ci_phones_from(text)
        self.assertGreaterEqual(len(phones), 1)
        self.assertEqual(len(phones), len(set(phones)))
        for p in phones:
            digits = "".join(ch for ch in p if ch.isdigit())
            self.assertGreaterEqual(len(digits), 9)

    def test_ci_score_applies_role_and_modifiers_once(self):
        c = scanner.CIContact(
            name="Alice Example",
            role="CISO",
            email_status="smtp-ok",
            linkedin_url="https://linkedin.com/in/alice-example",
            phone_type="practice",
        )
        base = max(
            (w for kw, w in scanner._CI_ROLE_SCORES.items() if kw in "ciso"),
            default=0,
        )
        expected = min(100, base + 5)
        expected = min(100, expected + 3)
        expected = max(0, expected - 8)
        self.assertEqual(scanner.ci_score(c), expected)

    def test_emailformat_returns_dict_shape_even_without_pattern(self):
        html = "<html><body>Contact us via sales@example.be</body></html>"
        with mock.patch.object(scanner, "_CI_HTTP", True), \
             mock.patch.object(scanner, "_ci_get", return_value=_FakeResponse(html)), \
             mock.patch.object(scanner, "info"):
            result = scanner.ci_query_emailformat("example.be", self.proxies, 0)

        self.assertIsInstance(result, dict)
        self.assertIn("pattern", result)
        self.assertIn("emails", result)
        self.assertIn("sales@example.be", result["emails"])

    def test_ci_query_riziv_extracts_phone_and_registry_number(self):
        html = """
        <html><body>
          <a href="tel:02 123 45 67">Call</a>
          <p>Erkenningsnummer: 1234567</p>
        </body></html>
        """
        with mock.patch.object(scanner, "_CI_HTTP", True), \
             mock.patch.object(scanner, "_ci_get", return_value=_FakeResponse(html)), \
             mock.patch.object(scanner, "info"):
            result = scanner.ci_query_riziv("Health Org", "0123.456.789", self.proxies, 0)

        self.assertEqual(result["phone"], "+3221234567")
        self.assertEqual(result["riziv_number"], "1234567")
        self.assertEqual(result["address"], "")

    def test_ci_query_vreg_fallback_csv_extracts_phone(self):
        csv_payload = (
            "col1;col2;col3\n"
            "Energy Org BV;active;029876543\n"
        )
        with mock.patch.object(scanner, "_CI_HTTP", True), \
             mock.patch.object(scanner, "_ci_get", side_effect=[None, _FakeResponse(csv_payload)]), \
             mock.patch.object(scanner, "info"):
            result = scanner.ci_query_vreg("Energy Org", "0123.456.789", self.proxies, 0)

        self.assertEqual(result["phone"], "+3229876543")
        self.assertEqual(result["license_type"], "")

    def test_ci_query_bipt_extracts_phone_and_operator_type(self):
        html = """
        <html><body>
          <table>
            <tr>
              <td>Telecom Operator</td>
              <td>0123456789</td>
              <td><a href="tel:02/456.78.90">Call</a></td>
            </tr>
          </table>
        </body></html>
        """
        with mock.patch.object(scanner, "_CI_HTTP", True), \
             mock.patch.object(scanner, "_ci_get", return_value=_FakeResponse(html)), \
             mock.patch.object(scanner, "info"):
            result = scanner.ci_query_bipt("Infra Org", "0123.456.789", self.proxies, 0)

        self.assertEqual(result["phone"], "+3224567890")
        self.assertEqual(result["operator_type"], "Telecom Operator")

    def test_regulator_queries_keep_dict_shape_on_empty_responses(self):
        with mock.patch.object(scanner, "_CI_HTTP", True), \
             mock.patch.object(scanner, "_ci_get", return_value=None), \
             mock.patch.object(scanner, "info"):
            riziv = scanner.ci_query_riziv("Org", "0123456789", self.proxies, 0)
            vreg = scanner.ci_query_vreg("Org", "0123456789", self.proxies, 0)
            bipt = scanner.ci_query_bipt("Org", "0123456789", self.proxies, 0)

        self.assertEqual(riziv, {"phone": "", "address": "", "riziv_number": ""})
        self.assertEqual(vreg, {"phone": "", "license_type": ""})
        self.assertEqual(bipt, {"phone": "", "operator_type": ""})

    def test_ci_run_single_smoke_with_mocked_sources(self):
        with mock.patch.object(scanner, "header"), \
             mock.patch.object(scanner, "info"), \
             mock.patch.object(scanner, "ci_fetch_kbo", return_value={
                 "name": "Acme",
                 "phone": "",
                 "email": "",
                 "address": "",
                 "domain": "",
                 "mandataries": [{"name": "Jane Doe", "role": "Bestuurder", "since": "2020"}],
             }), \
             mock.patch.object(scanner, "ci_scrape_website", return_value={
                 "staff": [],
                 "board": [],
                 "emails": [],
                 "phones": [],
                 "pattern": "",
             }), \
             mock.patch.object(scanner, "ci_fetch_staatsblad", return_value=[]), \
             mock.patch.object(scanner, "ci_run_serps", return_value={
                 "linkedin_url": "",
                 "emails": [],
                 "phones": [],
                 "mentions": [],
                 "sources": [],
             }), \
             mock.patch.object(scanner, "ci_try_linkedin_pubdir", return_value=""), \
             mock.patch.object(scanner, "ci_fetch_linkedin_company", return_value=""), \
             mock.patch.object(scanner, "ci_fetch_linkedin", return_value={}), \
             mock.patch.object(scanner, "ci_query_emailformat", return_value={"pattern": "", "emails": []}), \
             mock.patch.object(scanner, "ci_query_infobel", return_value={"phone": "", "address": ""}), \
             mock.patch.object(scanner, "ci_query_goudengids", return_value={"phone": "", "address": ""}), \
             mock.patch.object(scanner, "ci_query_riziv", return_value={"phone": "", "address": "", "riziv_number": ""}), \
             mock.patch.object(scanner, "ci_query_vreg", return_value={"phone": "", "license_type": ""}), \
             mock.patch.object(scanner, "ci_query_bipt", return_value={"phone": "", "address": "", "operator_id": ""}), \
             mock.patch.object(scanner, "ci_query_apollo", return_value={"emails": []}), \
             mock.patch.object(scanner, "ci_query_hunter", return_value={"pattern": "", "emails": []}):
            org = scanner.ci_run_single(
                kbo="0123456789",
                domain="www.example.be",
                delay=0,
                no_smtp=True,
                proxies=self.proxies,
            )

        self.assertEqual(org.domain, "example.be")
        self.assertIsInstance(org.contacts, list)

    def test_ci_enrich_from_scan_skips_kbo_found_in_child_folder_outputs(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            output_dir = root / "run_current"
            output_dir.mkdir(parents=True, exist_ok=True)

            manifest = output_dir / "nis2_companies_manifest.csv"
            with open(manifest, "w", encoding="utf-8", newline="") as f:
                f.write("EntityNumber,CompanyName,NaceCode,NIS2_Sector,Website,KBO_URL\n")
                f.write("0123.456.789,Done Org,6201,Digital,https://done.example,https://kbo/done\n")
                f.write("0987.654.321,New Org,6201,Digital,https://new.example,https://kbo/new\n")

            previous_dir = root / "run_old"
            previous_dir.mkdir(parents=True, exist_ok=True)
            with open(previous_dir / "contact_enrichment.json", "w", encoding="utf-8") as f:
                json.dump([{
                    "kbo": "0123.456.789",
                    "name": "Done Org",
                    "domain": "done.example",
                    "contacts": [],
                }], f)

            enriched_kbos = []

            def _fake_ci_run_single(kbo: str, domain: str, **_kwargs):
                enriched_kbos.append(kbo)
                return scanner.CIOrgProfile(
                    kbo=kbo,
                    name=f"Org {kbo}",
                    domain=domain,
                    contacts=[],
                )

            old_cwd = os.getcwd()
            os.chdir(root)
            try:
                with mock.patch.object(scanner, "load_url_lookup", return_value=({}, {})), \
                     mock.patch.object(scanner, "ci_run_single", side_effect=_fake_ci_run_single), \
                     mock.patch.object(scanner, "ci_print_report"), \
                     mock.patch.object(scanner, "ci_export_csv"), \
                     mock.patch.object(scanner, "ci_export_json"), \
                     mock.patch.object(scanner, "ci_export_html"):
                    scanner.ci_enrich_from_scan(
                        output_dir=str(output_dir),
                        nuclei_output=str(output_dir / "missing_nuclei.jsonl"),
                        contact_limit=10,
                        hunter_key="",
                        apollo_key="",
                        serp_delay=0,
                        no_smtp=True,
                        workers=1,
                        proxies=self.proxies,
                    )
            finally:
                os.chdir(old_cwd)

            self.assertEqual(enriched_kbos, ["0987654321"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
