from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd
from catboost import CatBoostClassifier, Pool

from app.config import Settings
from feature_extraction import (
    CASINO_KEYWORDS,
    FEATURE_COLUMNS,
    KNOWN_SSL_ISSUERS,
    PHISHING_KEYWORDS,
    PYRAMID_KEYWORDS,
    count_keywords,
    extract_content_features,
    extract_features,
    registered_domain,
)


FEATURE_LABELS = {
    "url_length": "длина адреса",
    "hostname_length": "длина домена",
    "path_length": "длина пути страницы",
    "dot_count": "количество точек в адресе",
    "hyphen_count": "дефисы в адресе",
    "slash_count": "сложность пути",
    "digit_count": "цифры в адресе",
    "has_ip_host": "IP вместо домена",
    "has_at_symbol": "символ @ в адресе",
    "subdomain_count": "много уровней в домене",
    "suspicious_tld": "рискованная доменная зона",
    "domain_age_days": "возраст домена",
    "domain_expiry_days": "срок регистрации домена",
    "whois_privacy": "скрытый владелец домена",
    "dns_a_count": "IP-адреса в DNS",
    "dns_mx_count": "почтовые MX-записи",
    "ssl_valid": "SSL-сертификат",
    "ssl_days_to_expiry": "срок SSL-сертификата",
    "ssl_self_signed": "самоподписанный SSL",
    "response_time_ms": "скорость ответа",
    "page_size_bytes": "размер страницы",
    "password_form_count": "форма ввода пароля",
    "iframe_count": "встроенные чужие блоки",
    "external_link_ratio": "доля внешних ссылок",
    "popup_or_redirect": "редиректы или всплывающие окна",
    "casino_keyword_count": "слова казино, ставок или бонусов",
    "pyramid_keyword_count": "обещания дохода или инвестиций",
    "phishing_keyword_count": "слова входа, пароля или кошелька",
}


@dataclass(frozen=True)
class ClassifierStatus:
    enabled: bool
    available: bool
    model_path: str
    classes: list[str]
    error: str | None = None


class DomainMLClassifier:
    def __init__(self, settings: Settings):
        self.settings = settings
        self.model_path = settings.ml_model_path
        self.enabled = settings.ml_enabled
        self.error: str | None = None
        self.model: CatBoostClassifier | None = None
        if not self.enabled:
            return
        try:
            if not self.model_path.exists():
                self.error = f"model file not found: {self.model_path}"
                return
            self.model = CatBoostClassifier()
            self.model.load_model(str(self.model_path))
        except Exception as exc:  # noqa: BLE001
            self.error = f"{type(exc).__name__}: {exc}"
            self.model = None

    @property
    def available(self) -> bool:
        return self.enabled and self.model is not None

    def status(self) -> ClassifierStatus:
        return ClassifierStatus(
            enabled=self.enabled,
            available=self.available,
            model_path=str(self.model_path),
            classes=[str(item) for item in getattr(self.model, "classes_", [])] if self.model else [],
            error=self.error,
        )

    def classify(self, url: str, evidence: Any) -> dict[str, Any]:
        if not self.enabled:
            return {"enabled": False, "available": False, "error": "ML classifier is disabled"}
        if not self.model:
            return {"enabled": True, "available": False, "error": self.error or "ML model is unavailable"}

        try:
            features = self._features_from_evidence(url, evidence)
            frame = pd.DataFrame([{column: features[column] for column in FEATURE_COLUMNS}])
            probabilities = np.asarray(self.model.predict_proba(frame))[0]
            classes = [str(item) for item in self.model.classes_]
            ranked = sorted(zip(classes, probabilities), key=lambda item: float(item[1]), reverse=True)
            label, confidence = ranked[0]
            return {
                "enabled": True,
                "available": True,
                "model": "CatBoostClassifier",
                "model_path": str(self.model_path),
                "feature_count": len(FEATURE_COLUMNS),
                "label": label,
                "confidence": round(float(confidence), 4),
                "probabilities": {name: round(float(value), 4) for name, value in ranked},
                "top_features": self._top_features(frame, features, label, classes),
            }
        except Exception as exc:  # noqa: BLE001
            return {"enabled": True, "available": False, "error": f"{type(exc).__name__}: {exc}"}

    def _features_from_evidence(self, url: str, evidence: Any) -> dict[str, float]:
        final_url = evidence.final_url or url
        features = extract_features(final_url, network=False)
        domain = registered_domain(evidence.domain or features.get("domain") or "")

        html = self._read_html(evidence.html_path)
        text_blob = " ".join(
            str(part or "")
            for part in [
                features.get("text_blob"),
                evidence.title,
                evidence.description,
                evidence.text_excerpt,
            ]
        )
        if html:
            content_features, page_text = extract_content_features(html, final_url, evidence.redirect_count)
            features.update(content_features)
            if page_text:
                text_blob = f"{text_blob} {page_text}"

        tls = evidence.tls or {}
        dns = evidence.dns or {}
        domain_info = evidence.domain_info or {}
        issuer = str(tls.get("issuer") or "").lower()
        subject = str(tls.get("subject") or "").lower()

        features.update(
            {
                "domain_age_days": self._number_or_default(domain_info.get("age_days")),
                "domain_expiry_days": self._expiry_days(domain_info.get("expires_at")),
                "whois_privacy": 0,
                "registrar_country_kz": 1 if domain.endswith(".kz") else 0,
                "whois_available": 0 if domain_info.get("error") else 1,
                "dns_a_count": len(dns.get("records") or []),
                "dns_mx_count": len(dns.get("mx_records") or []),
                "dns_txt_count": 0,
                "has_spf": 0,
                "has_dmarc": 0,
                "ssl_valid": 1 if tls.get("valid") else 0,
                "ssl_days_to_expiry": self._number_or_default(tls.get("expires_in_days")),
                "ssl_self_signed": 1 if issuer and subject and issuer == subject else 0,
                "ssl_issuer_known": 1 if any(token in issuer for token in KNOWN_SSL_ISSUERS) else 0,
                "response_time_ms": self._number_or_default(evidence.response_time_ms),
                "page_size_bytes": self._number_or_default(evidence.page_size_bytes),
                "popup_or_redirect": 1 if evidence.redirect_count > 2 else int(features.get("popup_or_redirect", 0)),
                "casino_keyword_count": count_keywords(text_blob, CASINO_KEYWORDS),
                "pyramid_keyword_count": count_keywords(text_blob, PYRAMID_KEYWORDS),
                "phishing_keyword_count": count_keywords(text_blob, PHISHING_KEYWORDS),
            }
        )

        return {name: self._number_or_default(features.get(name)) for name in FEATURE_COLUMNS}

    def _read_html(self, html_path: str | None) -> str:
        if not html_path:
            return ""
        path = Path(html_path.replace("\\", "/"))
        if not path.is_absolute():
            path = self.settings.evidence_dir / path.name
        try:
            return path.read_text(encoding="utf-8", errors="ignore")[:1_000_000]
        except OSError:
            return ""

    @staticmethod
    def _number_or_default(value: Any, default: float = -1) -> float:
        try:
            if value is None:
                return default
            number = float(value)
            if np.isnan(number):
                return default
            return number
        except (TypeError, ValueError):
            return default

    @staticmethod
    def _expiry_days(value: Any) -> float:
        if not value:
            return -1
        try:
            expires = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
            return float((expires - datetime.now(timezone.utc)).days)
        except ValueError:
            return -1

    def _top_features(
        self,
        frame: pd.DataFrame,
        raw_features: dict[str, float],
        label: str,
        classes: list[str],
    ) -> list[dict[str, Any]]:
        if not self.model:
            return []
        try:
            values = np.asarray(self.model.get_feature_importance(Pool(frame), type="ShapValues"))
            if values.ndim == 3:
                class_index = classes.index(label) if label in classes else 0
                row = values[0, class_index, :-1]
            elif values.ndim == 2:
                row = values[0, :-1]
            else:
                return []
        except Exception:  # noqa: BLE001
            return []

        selected: list[dict[str, Any]] = []
        for index in np.argsort(np.abs(row))[::-1]:
            feature = FEATURE_COLUMNS[int(index)]
            value = raw_features.get(feature)
            if feature == "ssl_valid" and float(value or 0) == 1:
                continue
            selected.append(
                {
                    "feature": feature,
                    "label": FEATURE_LABELS.get(feature, feature),
                    "value": value,
                    "impact": round(float(row[int(index)]), 4),
                }
            )
            if len(selected) >= 6:
                break
        return selected
