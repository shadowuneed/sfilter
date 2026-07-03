from __future__ import annotations

import hashlib
import json
import re
import threading
import time
from datetime import datetime, timezone
from typing import Any

import httpx

from app.config import Settings
from app.database import Database, redact_string


class GeminiQuotaError(RuntimeError):
    pass


class GeminiAPIError(RuntimeError):
    def __init__(
        self,
        message: str,
        *,
        status_code: int | None = None,
        key_hash: str | None = None,
        retryable: bool = False,
    ):
        super().__init__(redact_string(message))
        self.status_code = status_code
        self.key_hash = key_hash
        self.retryable = retryable


RETRYABLE_STATUS_CODES = {408, 409, 425, 429, 500, 502, 503, 504}
AUTH_STATUS_CODES = {401, 403}


class GeminiClient:
    def __init__(self, settings: Settings, db: Database):
        self.settings = settings
        self.db = db
        self._lock = threading.Lock()
        self._next_key_index = 0

    @property
    def available(self) -> bool:
        return bool(self.settings.gemini_api_keys)

    @property
    def key_hashes(self) -> list[str]:
        return [self._key_hash(key) for key in self.settings.gemini_api_keys]

    @property
    def key_format_ok(self) -> bool:
        return bool(self.settings.gemini_api_keys) and not self.key_format_warnings

    @property
    def key_format_warnings(self) -> list[str]:
        warnings: list[str] = []
        for index, key in enumerate(self.settings.gemini_api_keys, start=1):
            stripped = key.strip()
            label = f"key {index}"
            if not stripped:
                warnings.append(f"{label}: empty")
                continue
            if stripped != key:
                warnings.append(f"{label}: leading or trailing whitespace")
            if stripped[:1] in {"'", '"'} or stripped[-1:] in {"'", '"'}:
                warnings.append(f"{label}: contains literal quotes")
            unwrapped = stripped.strip("'\"")
            if unwrapped.lower().startswith("bearer "):
                warnings.append(f"{label}: contains Bearer prefix")
            if any(char.isspace() for char in stripped):
                warnings.append(f"{label}: contains whitespace")
            if stripped.startswith("[") or stripped.endswith("]"):
                warnings.append(f"{label}: looks like a JSON list")
            if "," in stripped or ";" in stripped:
                warnings.append(f"{label}: contains a separator")
            if len(stripped) < 20:
                warnings.append(f"{label}: too short")
        return warnings

    def generate_json(
        self,
        prompt: str,
        *,
        use_search: bool = True,
        use_url_context: bool = False,
        temperature: float = 0.2,
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        if not self.available:
            raise GeminiQuotaError("GEMINI_API_KEYS is empty")

        last_error: Exception | None = None
        key_count = len(self.settings.gemini_api_keys)
        attempts = max(key_count * 2, 3)
        auth_failures = 0

        for attempt in range(attempts):
            api_key, key_hash = self._reserve_key()
            try:
                return self._request_json(
                    api_key,
                    key_hash,
                    prompt,
                    use_search=use_search,
                    use_url_context=use_url_context,
                    temperature=temperature,
                )
            except GeminiAPIError as exc:
                last_error = exc
                if exc.status_code == 400:
                    raise exc
                if exc.status_code in AUTH_STATUS_CODES:
                    auth_failures += 1
                    if auth_failures >= key_count:
                        raise exc
                    continue
                if not exc.retryable:
                    raise exc
                if attempt < attempts - 1:
                    self._sleep_before_retry(attempt, exc.status_code)
            except (httpx.TimeoutException, httpx.TransportError) as exc:
                last_error = GeminiAPIError(
                    f"Gemini connection error ({type(exc).__name__}): {redact_string(str(exc))}",
                    retryable=True,
                )
                if attempt < attempts - 1:
                    self._sleep_before_retry(attempt, None)

        if last_error:
            raise last_error
        raise GeminiQuotaError("No Gemini API key has remaining local quota")

    def _request_json(
        self,
        api_key: str,
        key_hash: str,
        prompt: str,
        *,
        use_search: bool,
        use_url_context: bool,
        temperature: float,
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        url = (
            "https://generativelanguage.googleapis.com/v1beta/models/"
            f"{self.settings.gemini_model}:generateContent"
        )
        tools: list[dict[str, Any]] = []
        if use_search:
            tools.append({"google_search": {}})
        if use_url_context:
            tools.append({"url_context": {}})

        payload: dict[str, Any] = {
            "contents": [{"role": "user", "parts": [{"text": prompt}]}],
            "generationConfig": {"temperature": temperature},
        }
        if not tools:
            payload["generationConfig"]["responseMimeType"] = "application/json"
        if tools:
            payload["tools"] = tools

        with httpx.Client(timeout=self.settings.gemini_timeout_seconds) as client:
            response = client.post(url, params={"key": api_key}, json=payload)

        if response.status_code >= 400:
            raise self._response_error(response, key_hash)

        try:
            raw = response.json()
        except ValueError as exc:
            raise GeminiAPIError(
                f"Gemini returned a non-JSON response ({type(exc).__name__})",
                key_hash=key_hash,
                retryable=True,
            ) from None

        text = self._extract_text(raw)
        parsed = self._parse_json_text(text)
        meta = {
            "model": self.settings.gemini_model,
            "key_hash": key_hash,
            "grounding_sources": self._extract_grounding_sources(raw),
            "raw_text_length": len(text),
        }
        return parsed, meta

    def _response_error(self, response: httpx.Response, key_hash: str) -> GeminiAPIError:
        status = response.status_code
        reason = response.reason_phrase or "HTTP error"
        body = redact_string(response.text or "").strip().replace("\n", " ")
        if len(body) > 360:
            body = f"{body[:360]}..."
        message = f"Gemini API {status} {reason} (model={self.settings.gemini_model}, key_hash={key_hash})"
        if status in AUTH_STATUS_CODES:
            message += (
                "; ключ отклонен Google. В GEMINI_API_KEYS должен быть API key из Google AI Studio "
                "или Generative Language API, без Bearer, кавычек и переносов. Vertex/OAuth/service-account "
                "токены здесь не подходят. Проверьте, что Generative Language API включен для проекта, "
                "а ограничения ключа разрешают Gemini API."
            )
            if body:
                message += f": {body}"
            return GeminiAPIError(
                message,
                status_code=status,
                key_hash=key_hash,
                retryable=False,
            )
        if status == 503:
            message += "; service is temporarily unavailable, retry will use another key if possible"
        if body:
            message += f": {body}"
        return GeminiAPIError(
            message,
            status_code=status,
            key_hash=key_hash,
            retryable=status in RETRYABLE_STATUS_CODES,
        )

    @staticmethod
    def _sleep_before_retry(attempt: int, status_code: int | None) -> None:
        if attempt < 0:
            return
        base = 4 if status_code in {429, 503} else 2
        delay = min(12, base * (2 ** min(attempt, 2)))
        time.sleep(delay)

    def _reserve_key(self) -> tuple[str, str]:
        with self._lock:
            now = int(time.time())
            minute_window = now // 60
            today = datetime.now(timezone.utc).date().isoformat()
            best_wait: int | None = None
            key_count = len(self.settings.gemini_api_keys)

            for offset in range(key_count):
                index = (self._next_key_index + offset) % key_count
                api_key = self.settings.gemini_api_keys[index]
                key_hash = self._key_hash(api_key)
                row = self.db.usage_row(key_hash) or {
                    "day": today,
                    "day_count": 0,
                    "minute_window": minute_window,
                    "minute_count": 0,
                }

                day_count = 0 if row["day"] != today else int(row["day_count"])
                minute_count = 0 if int(row["minute_window"]) != minute_window else int(row["minute_count"])

                if day_count >= self.settings.gemini_rpd_limit:
                    continue
                if minute_count >= self.settings.gemini_rpm_limit:
                    wait = 60 - (now % 60) + 1
                    best_wait = wait if best_wait is None else min(best_wait, wait)
                    continue

                self.db.upsert_usage(
                    key_hash,
                    today,
                    day_count + 1,
                    minute_window,
                    minute_count + 1,
                )
                self._next_key_index = (index + 1) % key_count
                return api_key, key_hash

        if best_wait is not None and best_wait <= 65:
            time.sleep(best_wait)
            return self._reserve_key()
        raise GeminiQuotaError("Gemini local daily quota exhausted for all configured keys")

    @staticmethod
    def _key_hash(api_key: str) -> str:
        return hashlib.sha256(api_key.encode("utf-8")).hexdigest()[:16]

    @staticmethod
    def _extract_text(raw: dict[str, Any]) -> str:
        parts = raw.get("candidates", [{}])[0].get("content", {}).get("parts", [])
        return "\n".join(part.get("text", "") for part in parts if part.get("text"))

    @staticmethod
    def _parse_json_text(text: str) -> dict[str, Any]:
        cleaned = (text or "").strip()
        if not cleaned:
            return {}
        if cleaned.startswith("```"):
            cleaned = re.sub(r"^```(?:json)?", "", cleaned, flags=re.IGNORECASE).strip()
            cleaned = re.sub(r"```$", "", cleaned).strip()
        try:
            value = json.loads(cleaned)
        except json.JSONDecodeError:
            match = re.search(r"\{.*\}", cleaned, flags=re.DOTALL)
            if not match:
                return {}
            value = json.loads(match.group(0))
        if not isinstance(value, dict):
            return {"items": value}
        return value

    @staticmethod
    def _extract_grounding_sources(raw: dict[str, Any]) -> list[dict[str, str]]:
        sources: list[dict[str, str]] = []
        candidate = raw.get("candidates", [{}])[0]
        grounding = candidate.get("groundingMetadata") or {}
        for chunk in grounding.get("groundingChunks", []) or []:
            web = chunk.get("web") or {}
            uri = web.get("uri")
            if uri:
                sources.append({"url": uri, "title": web.get("title", "")})
        seen: set[str] = set()
        unique: list[dict[str, str]] = []
        for source in sources:
            if source["url"] in seen:
                continue
            seen.add(source["url"])
            unique.append(source)
        return unique
