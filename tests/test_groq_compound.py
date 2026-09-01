from __future__ import annotations

import unittest
from unittest.mock import Mock, patch

from app.config import Settings
from app.services.groq_compound import GroqCompoundClient


class GroqCompoundClientTests(unittest.TestCase):
    def test_unconfigured_client_does_not_make_request(self) -> None:
        client = GroqCompoundClient(Settings(groq_api_key=None))

        with patch("app.services.groq_compound.httpx.post") as post:
            candidates, meta = client.discover("онлайн казино", 20, "casino")

        post.assert_not_called()
        self.assertEqual(candidates, [])
        self.assertFalse(meta["available"])

    def test_batch_response_keeps_direct_domains_and_sources(self) -> None:
        response = Mock()
        response.raise_for_status.return_value = None
        response.json.return_value = {
            "choices": [
                {
                    "message": {
                        "content": """```json
                        {"candidates":[
                          {"url":"https://live-slots.example/register","domain":"live-slots.example","category":"casino","why":"casino lobby","source_urls":["https://forum.example/report"]},
                          {"url":"not-a-domain","domain":"not-a-domain","category":"casino"}
                        ]}
                        ```""",
                        "executed_tools": [
                            {
                                "type": "search",
                                "results": [
                                    {"url": "https://live-slots.example/register"},
                                    {"url": "https://search-source.example/page"},
                                ],
                            }
                        ],
                    }
                }
            ],
            "usage": {"total_tokens": 100},
        }
        client = GroqCompoundClient(Settings(groq_api_key="test-key", groq_model="groq/compound"))

        with patch("app.services.groq_compound.httpx.post", return_value=response) as post:
            candidates, meta = client.discover("онлайн казино", 20, "casino")

        post.assert_called_once()
        request_kwargs = post.call_args.kwargs
        self.assertEqual(request_kwargs["headers"]["Groq-Model-Version"], "latest")
        self.assertEqual(
            request_kwargs["json"]["compound_custom"]["tools"]["enabled_tools"],
            ["web_search", "visit_website"],
        )
        self.assertIn("онлайн казино", request_kwargs["json"]["messages"][0]["content"])
        self.assertIn("with at most 5 candidates", request_kwargs["json"]["messages"][0]["content"])
        self.assertEqual(request_kwargs["timeout"], 30)
        self.assertEqual([candidate["domain"] for candidate in candidates], ["live-slots.example"])
        self.assertEqual(candidates[0]["source_urls"], ["https://live-slots.example/register"])
        self.assertEqual(
            meta["sources"],
            ["https://live-slots.example/register", "https://search-source.example/page"],
        )
        self.assertEqual(meta["model"], "groq/compound")

    def test_text_answer_is_accepted_only_when_tool_output_confirms_domain(self) -> None:
        content = (
            "1. Live Slots: https://live-slots.example/register\n"
            "2. Invented: https://invented-casino.example"
        )
        executed_tools = [
            {
                "type": "search",
                "output": "Title: Live Slots URL: https://live-slots.example/register Content: casino lobby",
            }
        ]
        sources = GroqCompoundClient._tool_sources(executed_tools)
        candidates = GroqCompoundClient._content_candidates(content, sources)

        self.assertEqual(sources, ["https://live-slots.example/register"])
        self.assertEqual([candidate["domain"] for candidate in candidates], ["live-slots.example"])

    def test_candidate_mentioned_on_public_source_is_supported_by_tool_evidence(self) -> None:
        item = {"url": "https://target-casino.example", "domain": "target-casino.example"}
        evidence = GroqCompoundClient._tool_evidence_text(
            [{"url": "https://forum.example/report", "output": "Complaint about target-casino.example"}]
        )

        self.assertTrue(GroqCompoundClient._candidate_has_tool_evidence(item, {"forum.example"}, evidence))


if __name__ == "__main__":
    unittest.main()
