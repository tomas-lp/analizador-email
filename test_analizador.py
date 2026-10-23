import json
import unittest
import urllib.parse
from unittest.mock import patch

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
