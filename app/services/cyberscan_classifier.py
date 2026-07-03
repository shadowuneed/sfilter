from __future__ import annotations

import warnings
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import joblib
import numpy as np
from sklearn.exceptions import InconsistentVersionWarning

from app.config import Settings


FEATURE_LABELS = {
    "url_length": "длина адреса",
    "num_dots": "количество точек в адресе",
    "num_hyphens": "дефисы в адресе",
    "num_digits": "цифры в адресе",
    "has_ip": "IP вместо домена",
    "subdomain_count": "много уровней в домене",
    "suspicious_tld": "рискованная доменная зона",
    "path_length": "длина пути страницы",
    "num_query_params": "параметры в адресе",
    "special_chars_count": "служебные символы в адресе",
    "has_dns": "наличие DNS",
    "has_mx": "почтовые MX-записи",
    "num_ip_addresses": "IP-адреса в DNS",
    "domain_age_days": "возраст домена",
    "is_private_whois": "скрытый владелец домена",
    "days_to_expiry": "срок регистрации домена",
    "ssl_valid": "SSL-сертификат",
    "ssl_days_until_expiry": "срок SSL-сертификата",
    "num_forms": "формы на странице",
    "num_password_forms": "форма ввода пароля",
    "num_external_scripts": "внешние скрипты",
    "num_external_resources": "внешние ресурсы",
    "scam_word_count": "слова риска на странице",
    "has_brand_impersonation": "упоминание чужого бренда",
    "num_suspicious_patterns": "подозрительный JavaScript",
    "num_iframes": "встроенные чужие блоки",
    "has_meta_refresh": "автоматический редирект",
    "has_redirect": "редирект",
    "num_hidden_elements": "скрытые элементы страницы",
    "num_external_links": "много внешних ссылок",
    "casino_keywords_count": "слова казино, ставок или бонусов",
    "has_casino_in_url": "казино или ставки в адресе",
    "casino_confidence_score": "уверенность по казино-маркерам",
}


@dataclass(frozen=True)
class CyberScanStatus:
    enabled: bool
    available: bool
    model_path: str
    structural_features: list[str]
    error: str | None = None


class CyberScanClassifier:
    def __init__(self, settings: Settings):
        self.settings = settings
        self.enabled = settings.ml_enabled
        self.model_path = settings.cyberscan_model_path
        self.error: str | None = None
        self.model: Any | None = None
        self.scaler: Any | None = None
        self.structural_features: list[str] = []
        self.feature_weights: dict[str, float] = {}
        if not self.enabled:
            return
        self._load()

    @property
    def available(self) -> bool:
        return self.enabled and self.model is not None and bool(self.structural_features)

    def status(self) -> CyberScanStatus:
        return CyberScanStatus(
            enabled=self.enabled,
            available=self.available,
            model_path=str(self.model_path),
            structural_features=self.structural_features,
            error=self.error,
        )

    def classify(self, url: str, evidence: Any, content_ai: dict[str, Any]) -> dict[str, Any]:
        if not self.enabled:
            return {"enabled": False, "available": False, "error": "CyberScan ML is disabled"}
        if not self.available:
            return {"enabled": True, "available": False, "error": self.error or "CyberScan ML is unavailable"}

        try:
            raw_features = content_ai.get("features") or {}
            vector = np.array(
                [[self._number(raw_features.get(name)) for name in self.structural_features]],
                dtype=float,
            )
            transformed = self.scaler.transform(vector) if self.scaler is not None else vector
            predicted = self.model.predict(transformed)[0]
            probabilities = np.asarray(self.model.predict_proba(transformed))[0]
            classes = [int(item) for item in getattr(self.model, "classes_", range(len(probabilities)))]
            probability_map = {
                str(class_name): round(float(probability), 4)
                for class_name, probability in zip(classes, probabilities)
            }
            suspicious_probability = float(probabilities[classes.index(1)]) if 1 in classes else float(max(probabilities))
            label = "suspicious" if int(predicted) == 1 else "legit"
            confidence = suspicious_probability if label == "suspicious" else 1 - suspicious_probability
            return {
                "enabled": True,
                "available": True,
                "model": "CyberScan RandomForest",
                "model_path": str(self.model_path),
                "feature_count": len(self.structural_features),
                "label": label,
                "confidence": round(max(0.0, min(1.0, confidence)), 4),
                "suspicious_probability": round(suspicious_probability, 4),
                "probabilities": probability_map,
                "top_features": self._top_features(raw_features),
                "source": "Zorenko-Viktoria/CyberScan-Ai cyberscan_model.pkl",
            }
        except Exception as exc:  # noqa: BLE001
            return {"enabled": True, "available": False, "error": f"{type(exc).__name__}: {exc}"}

    def _load(self) -> None:
        path = Path(self.model_path)
        if not path.exists():
            self.error = f"model file not found: {path}"
            return
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", InconsistentVersionWarning)
                payload = joblib.load(path)
            self.model = payload["model"]
            self.scaler = payload.get("scaler")
            self.structural_features = [str(item) for item in payload.get("structural_features", [])]
            self.feature_weights = dict(payload.get("feature_weights") or {})
            expected = int(getattr(self.model, "n_features_in_", len(self.structural_features)))
            if expected != len(self.structural_features):
                self.error = f"model expects {expected} features, got {len(self.structural_features)}"
                self.model = None
        except Exception as exc:  # noqa: BLE001
            self.error = f"{type(exc).__name__}: {exc}"
            self.model = None

    def _top_features(self, features: dict[str, Any]) -> list[dict[str, Any]]:
        priority = [
            "casino_confidence_score",
            "casino_keywords_count",
            "num_password_forms",
            "has_brand_impersonation",
            "num_suspicious_patterns",
            "has_casino_in_url",
            "suspicious_tld",
            "domain_age_days",
            "num_external_links",
            "num_iframes",
            "has_meta_refresh",
            "num_hidden_elements",
            "url_length",
        ]
        selected: list[dict[str, Any]] = []
        for name in priority:
            if name not in features:
                continue
            if name == "ssl_valid":
                continue
            value = self._number(features.get(name))
            if value == 0:
                continue
            selected.append({"feature": name, "label": FEATURE_LABELS.get(name, name), "value": value})
        if len(selected) < 6:
            for name in self.structural_features:
                if name == "ssl_valid":
                    continue
                if name in {item["feature"] for item in selected}:
                    continue
                value = self._number(features.get(name))
                if value == 0:
                    continue
                selected.append({"feature": name, "label": FEATURE_LABELS.get(name, name), "value": value})
                if len(selected) >= 6:
                    break
        return selected[:6]

    @staticmethod
    def _number(value: Any) -> float:
        try:
            if value is None:
                return 0.0
            number = float(value)
            if np.isnan(number) or np.isinf(number):
                return 0.0
            return number
        except (TypeError, ValueError):
            return 0.0
