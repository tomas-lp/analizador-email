import json
import os
import tempfile
import hashlib
import unittest
import urllib.parse
from unittest.mock import Mock, patch

import analizador


class FakeResponse:
    def __init__(self, payload):
        self.payload = json.dumps(payload).encode()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def read(self):
        return self.payload


class UrlIntelTests(unittest.TestCase):
    def test_analyzes_file_without_executing_it(self):
        with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as file_handle:
            file_handle.write(b"contenido de prueba")
            filepath = file_handle.name
        try:
            data = analizador.analyze_file_locally(filepath)
        finally:
            os.unlink(filepath)

        self.assertEqual(data["size"], len(b"contenido de prueba"))
        self.assertEqual(data["hashes"]["SHA-256"], hashlib.sha256(b"contenido de prueba").hexdigest())

    def test_uses_oldest_received_header_for_source_ip(self):
        message = (
            b"From: sender@example.com\n"
            b"To: user@example.net\n"
            b"Received: from relay.example ([198.51.100.10])\n"
            b"Received: from origin.example ([203.0.113.25])\n"
            b"Content-Type: text/plain; charset=utf-8\n\nHola"
        )
        with tempfile.NamedTemporaryFile(delete=False, suffix=".eml") as file_handle:
            file_handle.write(message)
            filepath = file_handle.name
        try:
            data = analizador.parse_eml_file(filepath)
        finally:
            os.unlink(filepath)

        self.assertEqual(data["source_ip"], "203.0.113.25")

    def test_detects_eicar_without_executing_it(self):
        eicar = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
        self.assertTrue(analizador.is_eicar_test_file(eicar))

    def test_looks_up_file_hash_without_uploading_file(self):
        response = {"data": {"attributes": {"last_analysis_stats": {"malicious": 2, "suspicious": 1}}}}
        with patch.object(analizador.urllib.request, "urlopen", return_value=FakeResponse(response)) as mocked_urlopen:
            result = analizador.vt_lookup_file_hash("a" * 64, "test-key")

        self.assertEqual(result["status"], "success")
        self.assertEqual(result["malicious"], 2)
        self.assertIn("/files/" + "a" * 64, mocked_urlopen.call_args.args[0].full_url)

    def test_reads_existing_sandbox_behavior_by_hash(self):
        response = {"data": [{"attributes": {"sandbox_name": "Sandbox", "verdict": "malicious", "processes": [{}], "network_connections": [{}, {}]}}]}
        with patch.object(analizador.urllib.request, "urlopen", return_value=FakeResponse(response)):
            result = analizador.vt_lookup_file_behavior("b" * 64, "test-key")

        self.assertEqual(result["status"], "success")
        self.assertEqual(result["processes"], 1)
        self.assertEqual(result["network"], 2)
    def test_extracts_common_obfuscation_candidates(self):
        text = "Texto U29tZSBtYWxpY2lvdXMgcGF5bG9hZA== %68%6f%6c%61 48 65 6c 6c 6f 20 77 6f 72 6c 64"
        candidates = analizador.extract_obfuscated_candidates(text)

        self.assertIn("U29tZSBtYWxpY2lvdXMgcGF5bG9hZA==", candidates)
        self.assertIn("%68%6f%6c%61", candidates)
        self.assertIn("48 65 6c 6c 6f 20 77 6f 72 6c 64", candidates)

    @patch.object(analizador.subprocess, "run")
    def test_runs_cyberchef_magic_locally(self, mocked_run):
        mocked_run.return_value = Mock(
            returncode=0,
            stdout=json.dumps({"output": "texto decodificado", "type": "string"}),
            stderr="",
        )

        results = analizador.analyze_obfuscation_with_cyberchef("U29tZSBtYWxpY2lvdXMgcGF5bG9hZA==")

        self.assertEqual(results[0]["status"], "success")
        self.assertEqual(results[0]["output"], "texto decodificado")
        command = mocked_run.call_args.args[0]
        self.assertEqual(command[0], "node")
        self.assertTrue(command[1].endswith("cyberchef_bridge.mjs"))

    @patch.object(analizador.subprocess, "run", side_effect=FileNotFoundError)
    def test_reports_missing_node(self, _mocked_run):
        results = analizador.analyze_obfuscation_with_cyberchef("U29tZSBtYWxpY2lvdXMgcGF5bG9hZA==")

        self.assertEqual(results[0]["status"], "unavailable")
    def test_analyzes_http_links_with_all_services(self):
        responses = [
            {"uuid": "scan-123", "result": "https://urlscan.io/result/scan-123/"},
            {
                "page": {
                    "url": "https://example.com/login",
                    "domain": "example.com",
                    "title": "Example",
                    "status": "200",
                },
                "verdicts": {
                    "overall": {
                        "malicious": False,
                        "score": -10,
                        "brands": [],
                    }
                },
            },
            [{"name_value": "example.com\nwww.example.com"}],
            {
                "registrar": "Example Registrar",
                "events": [{
                    "event_action": "expiration",
                    "event_date": "2030-01-01",
                }],
            },
        ]
        requests = []

        def fake_urlopen(request, **kwargs):
            requests.append(request)
            return FakeResponse(responses.pop(0))

        with patch.object(analizador.urllib.request, "urlopen", side_effect=fake_urlopen):
            with patch.object(analizador.time, "sleep"):
                results = analizador.analyze_links_with_intel(
                    {
                        "links": [
                            "https://example.com/login",
                            "https://example.com/login",
                            "mailto:help@example.com",
                            "javascript:alert(1)",
                        ]
                    },
                    "test-urlscan-key",
                    "test-whois-key",
                )

        self.assertEqual([result["provider"] for result in results], ["urlscan", "crt.sh", "WHOIS"])
        self.assertEqual(results[0]["status"], "success")
        self.assertEqual(results[0]["visibility"], "unlisted")
        self.assertFalse(results[0]["malicious"])
        self.assertEqual(results[0]["score"], -10)
        self.assertEqual(results[0]["page_title"], "Example")
        self.assertEqual(results[1]["certificate_count"], 1)
        self.assertIn("www.example.com", results[1]["names"])
        self.assertEqual(results[2]["expiration"], "2030-01-01")

        self.assertEqual(requests[0].get_header("Api-key"), "test-urlscan-key")
        self.assertEqual(json.loads(requests[0].data)["visibility"], "unlisted")
        self.assertEqual(requests[1].full_url, "https://urlscan.io/api/v1/result/scan-123/")
        self.assertEqual(requests[1].get_header("Api-key"), "test-urlscan-key")
        self.assertEqual(urllib.parse.parse_qs(urllib.parse.urlsplit(requests[2].full_url).query)["q"], ["%.example.com"])
        self.assertEqual(requests[3].full_url, "https://api.who.is/v1/whois/example.com")
        self.assertEqual(requests[3].get_header("Authorization"), "Bearer test-whois-key")

    def test_crtsh_runs_without_private_api_keys(self):
        with patch.object(
            analizador.urllib.request,
            "urlopen",
            return_value=FakeResponse([]),
        ) as mocked_urlopen:
            results = analizador.analyze_links_with_intel(
                {"links": ["https://example.com/"]},
                None,
                None,
            )

        self.assertEqual([result["status"] for result in results], ["no_key", "success", "no_key"])
        self.assertEqual(mocked_urlopen.call_count, 1)

    def test_hostname_rejects_non_http_links_and_normalizes_idn(self):
        self.assertIsNone(analizador.get_url_hostname("mailto:user@example.com"))
        self.assertEqual(
            analizador.get_url_hostname("https://BÜCHER.example/path"),
            "xn--bcher-kva.example",
        )


if __name__ == "__main__":
    unittest.main()
