import json
import unittest
from unittest.mock import AsyncMock, patch

from app.main import app


class ASGITestClient:
    """Small HTTP-scope client for tests without the optional httpx dependency."""

    def __init__(self, asgi_app):
        self.app = asgi_app

    async def request(self, method, path, payload=None):
        body = json.dumps(payload).encode("utf-8") if payload is not None else b""
        headers = [(b"content-type", b"application/json")] if payload is not None else []
        scope = {
            "type": "http",
            "asgi": {"version": "3.0", "spec_version": "2.3"},
            "http_version": "1.1",
            "method": method,
            "scheme": "http",
            "path": path,
            "raw_path": path.encode("ascii"),
            "query_string": b"",
            "root_path": "",
            "headers": headers,
            "client": ("testclient", 50000),
            "server": ("testserver", 80),
            "state": {},
        }
        sent_request = False
        messages = []

        async def receive():
            nonlocal sent_request
            if not sent_request:
                sent_request = True
                return {"type": "http.request", "body": body, "more_body": False}
            return {"type": "http.disconnect"}

        async def send(message):
            messages.append(message)

        await self.app(scope, receive, send)
        start = next(message for message in messages if message["type"] == "http.response.start")
        response_body = b"".join(
            message.get("body", b"")
            for message in messages
            if message["type"] == "http.response.body"
        )
        return start["status"], json.loads(response_body) if response_body else None


class ApiIntegrationTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.client = ASGITestClient(app)

    async def test_health_endpoint_reports_database_and_generation_configuration(self):
        database = type("Database", (), {"command": lambda self, name: {"ok": 1}})()
        with (
            patch("app.api.routes.get_database", return_value=database),
            patch("app.api.routes.settings.gemini_api_key", "test-key"),
        ):
            status, body = await self.client.request("GET", "/api/health")
        self.assertEqual(status, 200)
        self.assertEqual(body["status"], "healthy")
        self.assertEqual(body["service"], "Cyber EvidentRAG API")
        self.assertEqual(body["dependencies"], {"mongodb": "healthy", "answer_generation": "configured"})

    async def test_models_endpoint_lists_allowlisted_gemini_text_models(self):
        status, body = await self.client.request("GET", "/api/models")
        self.assertEqual(status, 200)
        self.assertEqual(body["provider"], "Gemini and OpenRouter")
        model_ids = [model["id"] for model in body["models"]]
        self.assertEqual(model_ids, [
            "gemini-3.5-flash-lite",
            "gemini-flash-lite-latest",
            "openrouter:nvidia/nemotron-3-ultra-550b-a55b:free",
            "openrouter:nvidia/nemotron-3-super-120b-a12b:free",
        ])
        self.assertEqual(body["default_model"], "gemini-flash-lite-latest")

    async def test_health_endpoint_returns_503_when_database_ping_fails(self):
        with patch("app.api.routes.get_database", side_effect=RuntimeError("private database details")):
            status, body = await self.client.request("GET", "/api/health")
        self.assertEqual(status, 503)
        self.assertEqual(body["detail"], "The knowledge database is unavailable.")
        self.assertNotIn("private database details", json.dumps(body))

    async def test_health_endpoint_marks_missing_generation_key_as_degraded(self):
        database = type("Database", (), {"command": lambda self, name: {"ok": 1}})()
        with (
            patch("app.api.routes.get_database", return_value=database),
            patch("app.api.routes.settings.gemini_api_key", "  "),
            patch("app.api.routes.settings.openrouter_api_key", "  "),
        ):
            status, body = await self.client.request("GET", "/api/health")
        self.assertEqual(status, 200)
        self.assertEqual(body["status"], "degraded")
        self.assertEqual(body["dependencies"]["answer_generation"], "missing_provider_api_key")

    async def test_empty_retrieval_abstains_without_calling_generation(self):
        with (
            patch("app.services.rag_service.retrieve", return_value=[]),
            patch("app.services.rag_service.generate_grounded_answer", new_callable=AsyncMock) as generate,
        ):
            status, body = await self.client.request("POST", "/api/query", {"query": "CVE-2024-12345"})
        self.assertEqual(status, 200)
        self.assertTrue(body["abstained"])
        self.assertFalse(body["sufficient"])
        self.assertEqual(body["sources"], [])
        self.assertEqual(body["pipeline"]["response_generation"], "Skipped")
        generate.assert_not_awaited()

    async def test_sufficient_evidence_generates_answer_with_matching_citation(self):
        evidence = [{
            "title": "CVE record",
            "source": "CISA KEV",
            "url": "https://example.test/CVE-2024-12345",
            "text": "The vulnerability is actively exploited.",
            "relevance": 0.9,
            "exact_identifier": True,
            "_tokens": {"cve-2024-12345"},
        }]
        with (
            patch("app.services.rag_service.retrieve", return_value=evidence),
            patch("app.services.rag_service.generate_grounded_answer", new_callable=AsyncMock, return_value="It is exploited [E1].") as generate,
        ):
            status, body = await self.client.request("POST", "/api/query", {"query": "CVE-2024-12345"})
        self.assertEqual(status, 200)
        self.assertTrue(body["sufficient"])
        self.assertFalse(body["abstained"])
        self.assertEqual(body["sources"][0]["citation_id"], "E1")
        self.assertEqual(body["answer"], "It is exploited [E1].")
        generate.assert_awaited_once()

    async def test_selected_model_is_used_for_generation_and_reported(self):
        evidence = [{
            "title": "CVE record", "source": "CISA KEV", "text": "The vulnerability is actively exploited.",
            "relevance": 0.9, "exact_identifier": True, "_tokens": {"cve-2024-12345"},
        }]
        with (
            patch("app.services.rag_service.retrieve", return_value=evidence),
            patch("app.services.rag_service.generate_grounded_answer", new_callable=AsyncMock, return_value="It is exploited [E1].") as generate,
        ):
            status, body = await self.client.request("POST", "/api/query", {
                "query": "CVE-2024-12345", "model": "gemini-3.5-flash-lite",
            })
        self.assertEqual(status, 200)
        self.assertEqual(body["model"], "Gemini 3.5 Flash-Lite")
        self.assertEqual(generate.await_args.kwargs["model"], "gemini-3.5-flash-lite")

    async def test_openrouter_model_selection_uses_openrouter_client(self):
        evidence = [{
            "title": "CVE record", "source": "CISA KEV", "text": "The vulnerability is actively exploited.",
            "relevance": 0.9, "exact_identifier": True, "_tokens": {"cve-2024-12345"},
        }]
        with (
            patch("app.services.rag_service.retrieve", return_value=evidence),
            patch("app.services.rag_service.generate_openrouter_answer", new_callable=AsyncMock, return_value="It is exploited [E1].") as generate,
            patch("app.services.rag_service.generate_grounded_answer", new_callable=AsyncMock) as gemini,
        ):
            status, body = await self.client.request("POST", "/api/query", {
                "query": "CVE-2024-12345",
                "model": "openrouter:nvidia/nemotron-3-ultra-550b-a55b:free",
            })
        self.assertEqual(status, 200)
        self.assertEqual(body["model"], "OpenRouter · Nemotron 3 Ultra (free)")
        self.assertEqual(generate.await_args.kwargs["model"], "nvidia/nemotron-3-ultra-550b-a55b:free")
        gemini.assert_not_awaited()

    async def test_query_validation_rejects_unapproved_model(self):
        status, body = await self.client.request("POST", "/api/query", {
            "query": "Explain a security alert", "model": "unapproved-model",
        })
        self.assertEqual(status, 422)
        self.assertTrue(body["detail"])

    async def test_invalid_model_citation_is_replaced_with_safe_abstention(self):
        evidence = [{
            "title": "CVE record", "source": "CISA KEV", "text": "Supported evidence.",
            "relevance": 0.9, "exact_identifier": True, "_tokens": {"cve-2024-12345"},
        }]
        with (
            patch("app.services.rag_service.retrieve", return_value=evidence),
            patch("app.services.rag_service.generate_grounded_answer", new_callable=AsyncMock, return_value="Claim [E9]."),
        ):
            status, body = await self.client.request("POST", "/api/query", {"query": "CVE-2024-12345"})
        self.assertEqual(status, 200)
        self.assertTrue(body["abstained"])
        self.assertIn("couldn't verify", body["answer"])
        self.assertIsNone(body["model"])


    async def test_valid_label_with_unsupported_claim_is_replaced_with_abstention(self):
        evidence = [{
            "title": "CVE-2024-12345 record", "source": "CISA KEV", "text": "Supported evidence.",
            "relevance": 0.9, "exact_identifier": True, "_tokens": {"cve-2024-12345"},
        }]
        with (
            patch("app.services.rag_service.retrieve", return_value=evidence),
            patch("app.services.rag_service.generate_grounded_answer", new_callable=AsyncMock, return_value="CVE-2024-99999 affects Example Server [E1]."),
        ):
            status, body = await self.client.request("POST", "/api/query", {"query": "CVE-2024-12345"})
        self.assertEqual(status, 200)
        self.assertTrue(body["abstained"])
        self.assertIn("couldn't verify", body["answer"])
        self.assertEqual(body["pipeline"]["response_generation"], "Citation validation failed")

    async def test_generation_failure_returns_generic_502(self):
        evidence = [{
            "title": "CVE record", "source": "CISA KEV", "text": "Supported evidence.",
            "relevance": 0.9, "exact_identifier": True, "_tokens": {"cve-2024-12345"},
        }]
        with (
            patch("app.services.rag_service.retrieve", return_value=evidence),
            patch("app.services.rag_service.generate_grounded_answer", new_callable=AsyncMock, side_effect=RuntimeError("private provider details")),
        ):
            status, body = await self.client.request("POST", "/api/query", {"query": "CVE-2024-12345"})
        self.assertEqual(status, 502)
        self.assertEqual(body["detail"], "The answer generation service is temporarily unavailable.")
        self.assertNotIn("private provider details", json.dumps(body))

    async def test_database_failure_returns_generic_503(self):
        with patch("app.services.rag_service.retrieve", side_effect=RuntimeError("private database details")):
            status, body = await self.client.request("POST", "/api/query", {"query": "CVE-2024-12345"})
        self.assertEqual(status, 503)
        self.assertEqual(body["detail"], "The knowledge database is temporarily unavailable.")
        self.assertNotIn("private database details", json.dumps(body))

    async def test_query_validation_rejects_empty_query(self):
        status, body = await self.client.request("POST", "/api/query", {"query": ""})
        self.assertEqual(status, 422)
        self.assertTrue(body["detail"])


if __name__ == "__main__":
    unittest.main()
