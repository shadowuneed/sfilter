from __future__ import annotations

import json
import re
from typing import Any

import httpx

from app.config import Settings
from app.services.domains import extract_domain, is_candidate_domain, normalize_url, registered_domain


PUBLIC_URL_RE = re.compile(r"https?://[^\s<>\"')\]}]+", re.IGNORECASE)


class GroqCompoundClient:
    def __init__(self, settings: Settings):
        self.api_key = str(settings.groq_api_key or "").strip()
        self.model = settings.groq_model
        self.model_version = settings.groq_model_version
        self.timeout_seconds = settings.groq_timeout_seconds

    @property
    def available(self) -> bool:
        return bool(self.api_key)

    def discover(self, query: str, limit: int, search_mode: str) -> tuple[list[dict[str, Any]], dict[str, Any]]:
        if not self.available or limit <= 0:
            return [], {"available": self.available, "model": self.model, "sources": []}

        requested = max(5, min(int(limit), 10))
        subject = {
            "casino": "online casino websites and working mirrors",
            "phishing": "phishing websites targeting users",
            "scam": "fraudulent investment websites",
        }.get(search_mode, "suspicious websites matching the investigation")
        prompt = (
            f"Search the current web once for {subject} visible to users in Kazakhstan. "
            f"Return JSON only with at most {requested} candidates containing direct url, domain, category, "
            "why, and source_urls. Do not invent domains and do not return forums, reviews, news, social "
            "networks, search engines, or sports-betting-only bookmakers."
        )
        response = httpx.post(
            "https://api.groq.com/openai/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
                "Groq-Model-Version": self.model_version,
            },
            json={
                "model": self.model,
                "messages": [{"role": "user", "content": prompt}],
                "search_settings": {"country": "kazakhstan"},
                "compound_custom": {"tools": {"enabled_tools": ["web_search"]}},
            },
            timeout=self.timeout_seconds,
        )
        response.raise_for_status()
        payload = response.json()
        message = ((payload.get("choices") or [{}])[0].get("message") or {})
        content = str(message.get("content") or "")
        data = self._parse_json_object(content)
        executed_tools = message.get("executed_tools") or []
        tool_sources = self._tool_sources(executed_tools)
        raw_candidates = list(data.get("candidates") or [])
        raw_candidates.extend(self._content_candidates(content, tool_sources))
        raw_candidates.extend(self._tool_candidates(executed_tools))
        if tool_sources:
            source_domains = {registered_domain(extract_domain(source)) for source in tool_sources}
            raw_candidates = [
                item
                for item in raw_candidates
                if isinstance(item, dict)
                and registered_domain(extract_domain(str(item.get("domain") or item.get("url") or ""))) in source_domains
            ]
        candidates = self._normalize_candidates(raw_candidates, tool_sources, requested)
        return candidates, {
            "available": True,
            "model": self.model,
            "model_version": self.model_version,
            "sources": tool_sources,
            "usage": payload.get("usage") or {},
        }

    @staticmethod
    def _parse_json_object(content: str) -> dict[str, Any]:
        clean = re.sub(r"^```(?:json)?\s*|\s*```$", "", content.strip(), flags=re.IGNORECASE)
        try:
            parsed = json.loads(clean)
            return parsed if isinstance(parsed, dict) else {}
        except json.JSONDecodeError:
            start = clean.find("{")
            end = clean.rfind("}")
            if start < 0 or end <= start:
                return {}
            try:
                parsed = json.loads(clean[start : end + 1])
                return parsed if isinstance(parsed, dict) else {}
            except json.JSONDecodeError:
                return {}

    @staticmethod
    def _tool_sources(executed_tools: Any) -> list[str]:
        sources: list[str] = []

        def visit(value: Any) -> None:
            if isinstance(value, dict):
                for key, item in value.items():
                    if key.lower() in {"url", "link"} and isinstance(item, str) and item.startswith(("http://", "https://")):
                        if item not in sources:
                            sources.append(item)
                    else:
                        visit(item)
            elif isinstance(value, list):
                for item in value:
                    visit(item)
            elif isinstance(value, str):
                for match in PUBLIC_URL_RE.findall(value):
                    url = match.rstrip(".,;:")
                    if url not in sources:
                        sources.append(url)

        visit(executed_tools)
        return sources[:100]

    @staticmethod
    def _content_candidates(content: str, tool_sources: list[str]) -> list[dict[str, Any]]:
        candidates: list[dict[str, Any]] = []
        source_by_domain: dict[str, list[str]] = {}
        for source in tool_sources:
            key = registered_domain(extract_domain(source))
            if key:
                source_by_domain.setdefault(key, []).append(source)
        for match in PUBLIC_URL_RE.finditer(content or ""):
            url = match.group(0).rstrip(".,;:")
            domain = extract_domain(url)
            key = registered_domain(domain)
            if not key or key not in source_by_domain:
                continue
            start = max(0, match.start() - 140)
            end = min(len(content), match.end() + 140)
            context = re.sub(r"\s+", " ", content[start:end]).strip()
            candidates.append(
                {
                    "url": url,
                    "domain": domain,
                    "category": "suspicious",
                    "why": context or "Домен присутствует в подтвержденной выдаче Groq Web Search.",
                    "source_urls": source_by_domain[key][:5],
                }
            )
        return candidates

    @staticmethod
    def _tool_candidates(executed_tools: Any) -> list[dict[str, Any]]:
        candidates: list[dict[str, Any]] = []

        def visit(value: Any) -> None:
            if isinstance(value, dict):
                url = value.get("url")
                if isinstance(url, str) and url.startswith(("http://", "https://")):
                    title = str(value.get("title") or "").strip()
                    content = str(value.get("content") or value.get("snippet") or "").strip()
                    if title or content:
                        candidates.append(
                            {
                                "url": url,
                                "domain": extract_domain(url),
                                "category": "suspicious",
                                "why": " ".join(part for part in (title, content[:500]) if part),
                                "source_urls": [url],
                            }
                        )
                for item in value.values():
                    visit(item)
            elif isinstance(value, list):
                for item in value:
                    visit(item)

        visit(executed_tools)
        return candidates[:100]

    @staticmethod
    def _normalize_candidates(items: Any, default_sources: list[str], limit: int) -> list[dict[str, Any]]:
        normalized: list[dict[str, Any]] = []
        seen: set[str] = set()
        if not isinstance(items, list):
            return normalized
        for raw in items:
            if not isinstance(raw, dict):
                continue
            url = str(raw.get("url") or raw.get("domain") or "").strip()
            domain = extract_domain(str(raw.get("domain") or url))
            if not is_candidate_domain(domain) or domain in seen:
                continue
            seen.add(domain)
            sources = raw.get("source_urls") if isinstance(raw.get("source_urls"), list) else []
            source_urls = [str(item) for item in sources if str(item).startswith(("http://", "https://"))]
            if default_sources:
                source_urls = [item for item in source_urls if item in default_sources]
                if not source_urls:
                    key = registered_domain(domain)
                    source_urls = [
                        item
                        for item in default_sources
                        if registered_domain(extract_domain(item)) == key
                    ][:5]
                if not source_urls:
                    source_urls = default_sources[:10]
            normalized.append(
                {
                    "url": normalize_url(url or domain),
                    "domain": domain,
                    "category": str(raw.get("category") or "suspicious"),
                    "why": str(raw.get("why") or "Домен найден Groq Compound в публичном поиске."),
                    "source_urls": source_urls,
                }
            )
            if len(normalized) >= limit:
                break
        return normalized
