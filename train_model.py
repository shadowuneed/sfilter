from __future__ import annotations

import argparse
import json
import random
import shutil
import textwrap
import zipfile
from collections import Counter
from pathlib import Path
from typing import Any

import pandas as pd
import numpy as np
import requests
from catboost import CatBoostClassifier, Pool
from sklearn.metrics import classification_report, confusion_matrix, f1_score, recall_score
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.utils.class_weight import compute_class_weight
from tqdm import tqdm

from feature_extraction import FEATURE_COLUMNS, LABELS, extract_features, hostname_from_url, registered_domain


RAW_DIR = Path("data/ml/raw")
PROCESSED_DIR = Path("data/ml/processed")
MODEL_DIR = Path("models")
REPORT_PATH = Path("classification_report.txt")

KAGGLE_DATASETS = {
    "malicious": {
        "url": "https://www.kaggle.com/api/v1/datasets/download/sid321axn/malicious-urls-dataset",
        "zip": RAW_DIR / "malicious-urls-dataset.zip",
        "dir": RAW_DIR / "malicious-urls-dataset",
        "csv": RAW_DIR / "malicious-urls-dataset" / "malicious_phish.csv",
    },
    "phiusiil": {
        "url": "https://www.kaggle.com/api/v1/datasets/download/ndarvind/phiusiil-phishing-url-dataset",
        "zip": RAW_DIR / "phiusiil-phishing-url-dataset.zip",
        "dir": RAW_DIR / "phiusiil-phishing-url-dataset",
        "csv": RAW_DIR / "phiusiil-phishing-url-dataset" / "PhiUSIIL_Phishing_URL_Dataset.csv",
    },
}


def download_file(url: str, output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    with requests.get(url, stream=True, timeout=120) as response:
        response.raise_for_status()
        with output.open("wb") as file:
            for chunk in response.iter_content(chunk_size=1024 * 1024):
                if chunk:
                    file.write(chunk)


def ensure_raw_data(download: bool) -> dict[str, Any]:
    audit: dict[str, Any] = {"downloads": {}, "uci": {}}
    RAW_DIR.mkdir(parents=True, exist_ok=True)
    for name, spec in KAGGLE_DATASETS.items():
        if download and not spec["zip"].exists():
            download_file(str(spec["url"]), spec["zip"])
        if spec["zip"].exists() and not spec["csv"].exists():
            if spec["dir"].exists():
                shutil.rmtree(spec["dir"])
            with zipfile.ZipFile(spec["zip"]) as archive:
                archive.extractall(spec["dir"])
        audit["downloads"][name] = {
            "zip_exists": spec["zip"].exists(),
            "csv_exists": spec["csv"].exists(),
            "csv": str(spec["csv"]),
        }

    uci_paths = [
        Path(r"C:\Users\profm\Downloads\phishing+websites\Training Dataset.arff"),
        Path(r"C:\Users\profm\Downloads\phishing+websites\.old.arff"),
    ]
    audit["uci"] = {
        "paths": [str(path) for path in uci_paths],
        "used": False,
        "reason": "UCI ARFF files contain precomputed feature columns and no raw URL column; excluded by project rule.",
    }
    return audit


def normalize_label(value: Any, *, source: str) -> str | None:
    text = str(value or "").strip().lower()
    if source == "malicious":
        mapping = {
            "benign": "legit",
            "phishing": "phishing",
            "defacement": "suspicious",
            "malware": "suspicious",
        }
        return mapping.get(text)
    if source == "phiusiil":
        # PhiUSIIL uses 1 for legitimate and 0 for phishing in the released CSV.
        return "legit" if text == "1" else "phishing" if text == "0" else None
    if text in LABELS:
        return text
    return None


def sample_by_class(rows: list[dict[str, Any]], limit_per_class: int, seed: int) -> list[dict[str, Any]]:
    rng = random.Random(seed)
    grouped: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        grouped.setdefault(str(row["label"]), []).append(row)
    sampled: list[dict[str, Any]] = []
    for label, items in sorted(grouped.items()):
        rng.shuffle(items)
        sampled.extend(items[:limit_per_class])
    rng.shuffle(sampled)
    return sampled


def load_malicious_rows(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    df = pd.read_csv(path, usecols=["url", "type"])
    rows: list[dict[str, Any]] = []
    for item in df.itertuples(index=False):
        label = normalize_label(item.type, source="malicious")
        if label:
            rows.append({"url": str(item.url), "label": label, "source": "malicious_urls", "label_source": "public"})
    return rows


def load_phiusiil_rows(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    df = pd.read_csv(path, usecols=lambda col: col in {"URL", "\ufeffURL", "label"})
    url_col = "URL" if "URL" in df.columns else "\ufeffURL"
    rows: list[dict[str, Any]] = []
    for item in df[[url_col, "label"]].itertuples(index=False):
        label = normalize_label(item[1], source="phiusiil")
        if label:
            rows.append({"url": str(item[0]), "label": label, "source": "phiusiil", "label_source": "public"})
    return rows


def load_curated_rows(curated_dir: Path, min_confidence: float) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    if not curated_dir.exists():
        return rows
    for path in sorted(curated_dir.glob("*.csv")):
        df = pd.read_csv(path)
        lower = {col.lower(): col for col in df.columns}
        url_col = lower.get("url") or lower.get("domain")
        label_col = lower.get("label") or lower.get("class")
        confidence_col = lower.get("confidence")
        if not url_col or not label_col:
            continue
        for row in df.to_dict(orient="records"):
            confidence = float(row.get(confidence_col, 1.0) or 0.0) if confidence_col else 1.0
            label = normalize_label(row.get(label_col), source="curated")
            if label and confidence >= min_confidence:
                rows.append(
                    {
                        "url": str(row.get(url_col)),
                        "label": label,
                        "source": path.name,
                        "label_source": str(row.get("label_source") or "curated"),
                        "confidence": confidence,
                    }
                )
    return rows


def augment_curated_rows(rows: list[dict[str, Any]], *, multiplier: int, seed: int) -> tuple[list[dict[str, Any]], dict[str, int]]:
    if multiplier <= 0:
        return rows, {}
    rng = random.Random(seed)
    augmented: list[dict[str, Any]] = []
    counts: Counter[str] = Counter()
    for row in rows:
        label = str(row.get("label") or "")
        if label not in {"casino", "pyramid", "legit"}:
            continue
        if str(row.get("label_source") or "") == "public":
            continue
        if not str(row.get("source") or "").lower().endswith(".csv"):
            continue
        domain = registered_domain(hostname_from_url(str(row.get("url") or "")))
        if not domain:
            continue
        label_multiplier = multiplier if label in {"casino", "pyramid"} else max(4, multiplier // 4)
        for url in synthetic_domain_variants(domain, label=label, multiplier=label_multiplier, rng=rng):
            augmented.append(
                {
                    "url": url,
                    "label": label,
                    "source": f"augmented:{row.get('source', 'curated')}",
                    "label_source": "weak_augmented",
                    "confidence": min(float(row.get("confidence", 0.91) or 0.91), 0.91),
                    "feature_overrides": technical_feature_profile(label, rng),
                }
            )
            counts[label] += 1
    return [*rows, *augmented], dict(counts)


def synthetic_domain_variants(domain: str, *, label: str, multiplier: int, rng: random.Random) -> list[str]:
    stem = domain.split(".", 1)[0]
    base_tld = domain.rsplit(".", 1)[-1] if "." in domain else "com"
    casino_tokens = ["kz", "play", "club", "vip", "bonus", "mirror", "login", "new", "online", "slot", "win"]
    pyramid_tokens = ["invest", "income", "profit", "crypto", "capital", "fund", "trust", "club", "global", "roi"]
    legit_tokens = ["www", "online", "service", "business", "cabinet", "help"]
    casino_paths = ["kz/login", "bonus", "registration", "slots", "mirror", "app", "promo"]
    pyramid_paths = ["plans", "invest", "dashboard", "profit", "referral", "staking", "withdraw"]
    legit_paths = ["", "services", "personal", "business", "support", "news", "login"]
    tlds = ["com", "net", "org", "online", "site", "club", "vip", "live", "xyz", "pro", base_tld]
    tokens = casino_tokens if label == "casino" else pyramid_tokens if label == "pyramid" else legit_tokens
    paths = casino_paths if label == "casino" else pyramid_paths if label == "pyramid" else legit_paths
    variants: set[str] = set()
    while len(variants) < multiplier:
        token = rng.choice(tokens)
        tld = rng.choice(tlds)
        number = rng.choice(["", "24", "365", "777", "2026", "01"])
        host = rng.choice(
            [
                f"{stem}{number}.{tld}",
                f"{token}-{stem}.{tld}",
                f"{stem}-{token}.{tld}",
                f"{token}{stem}{number}.{tld}",
                f"{stem}{token}.{tld}",
                f"{token}.{stem}.{base_tld}",
            ]
        )
        variants.add(f"https://{host}/{rng.choice(paths)}")
    return sorted(variants)


def technical_feature_profile(label: str, rng: random.Random) -> dict[str, float]:
    if label == "legit":
        return {
            "domain_age_days": float(rng.randint(900, 8000)),
            "domain_expiry_days": float(rng.randint(120, 1800)),
            "whois_privacy": 0.0,
            "whois_available": 1.0,
            "dns_a_count": float(rng.randint(1, 6)),
            "dns_mx_count": float(rng.randint(1, 5)),
            "dns_txt_count": float(rng.randint(1, 8)),
            "has_spf": 1.0,
            "has_dmarc": float(rng.choice([0, 1])),
            "ssl_valid": 1.0,
            "ssl_days_to_expiry": float(rng.randint(30, 365)),
            "ssl_self_signed": 0.0,
            "ssl_issuer_known": 1.0,
            "response_time_ms": float(rng.randint(80, 1800)),
            "page_size_bytes": float(rng.randint(8_000, 900_000)),
        }
    young_age = rng.randint(1, 180 if label == "pyramid" else 720)
    return {
        "domain_age_days": float(young_age),
        "domain_expiry_days": float(rng.randint(7, 365)),
        "whois_privacy": float(rng.choice([0, 1, 1])),
        "whois_available": 1.0,
        "dns_a_count": float(rng.randint(1, 4)),
        "dns_mx_count": float(rng.choice([0, 0, 0, 1])),
        "dns_txt_count": float(rng.choice([0, 0, 1, 2])),
        "has_spf": float(rng.choice([0, 0, 1])),
        "has_dmarc": float(rng.choice([0, 0, 0, 1])),
        "ssl_valid": float(rng.choice([0, 1, 1])),
        "ssl_days_to_expiry": float(rng.randint(3, 120)),
        "ssl_self_signed": float(rng.choice([0, 0, 1])),
        "ssl_issuer_known": float(rng.choice([0, 1, 1])),
        "response_time_ms": float(rng.randint(120, 3500)),
        "page_size_bytes": float(rng.randint(1_000, 450_000)),
    }


def dedupe_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    by_domain: dict[str, dict[str, Any]] = {}
    conflicts = 0
    priority = {"curated": 3, "public": 2, "weak": 1}
    for row in rows:
        domain = registered_domain(hostname_from_url(str(row["url"])))
        if not domain:
            continue
        row = {**row, "domain": domain}
        existing = by_domain.get(domain)
        if not existing:
            by_domain[domain] = row
            continue
        if existing["label"] != row["label"]:
            conflicts += 1
            current_score = priority.get(str(existing.get("label_source")), 0)
            new_score = priority.get(str(row.get("label_source")), 0)
            if new_score > current_score:
                by_domain[domain] = row
    result = list(by_domain.values())
    result.sort(key=lambda item: (item["label"], item["domain"]))
    if conflicts:
        print(f"Skipped or resolved {conflicts} label conflicts by domain priority.")
    return result


def build_feature_frame(rows: list[dict[str, Any]], *, network: bool, timeout: int, proxy: str | None) -> pd.DataFrame:
    extracted: list[dict[str, Any]] = []
    for row in tqdm(rows, desc="extracting features"):
        features = extract_features(str(row["url"]), network=network, timeout=timeout, proxy=proxy)
        overrides = row.get("feature_overrides") or {}
        if isinstance(overrides, dict):
            for name, value in overrides.items():
                if name in FEATURE_COLUMNS:
                    features[name] = value
        features["label"] = row["label"]
        features["source"] = row.get("source", "")
        features["label_source"] = row.get("label_source", "")
        extracted.append(features)
    frame = pd.DataFrame(extracted)
    for column in FEATURE_COLUMNS:
        frame[column] = pd.to_numeric(frame[column], errors="coerce").fillna(-1)
    return frame


def class_weight_dict(y: pd.Series) -> dict[str, float]:
    labels = sorted(y.unique())
    weights = compute_class_weight(class_weight="balanced", classes=pd.Index(labels).to_numpy(), y=y.to_numpy())
    return dict(zip(labels, [float(value) for value in weights]))


def train(frame: pd.DataFrame, *, iterations: int, depth: int, seed: int) -> tuple[CatBoostClassifier, dict[str, Any]]:
    X = frame[FEATURE_COLUMNS]
    y = frame["label"].astype(str)
    train_x, temp_x, train_y, temp_y = train_test_split(X, y, test_size=0.30, random_state=seed, stratify=y)
    valid_x, test_x, valid_y, test_y = train_test_split(temp_x, temp_y, test_size=0.50, random_state=seed, stratify=temp_y)

    model = CatBoostClassifier(
        loss_function="MultiClass",
        eval_metric="TotalF1",
        iterations=iterations,
        depth=depth,
        learning_rate=0.08,
        random_seed=seed,
        class_weights=class_weight_dict(train_y),
        verbose=False,
        allow_writing_files=False,
    )
    model.fit(train_x, train_y, eval_set=(valid_x, valid_y), use_best_model=True)

    pred = np.asarray(model.predict(test_x)).reshape(-1)
    pred_series = pd.Series([str(item) for item in pred], index=test_y.index)
    metrics = {
        "macro_f1_present_classes": float(f1_score(test_y, pred_series, average="macro", zero_division=0)),
        "macro_f1_requested_classes": float(f1_score(test_y, pred_series, labels=list(LABELS), average="macro", zero_division=0)),
        "per_class_recall": {
            label: float(value)
            for label, value in zip(
                sorted(test_y.unique()),
                recall_score(test_y, pred_series, labels=sorted(test_y.unique()), average=None, zero_division=0),
            )
        },
        "classification_report": classification_report(test_y, pred_series, labels=list(LABELS), zero_division=0),
        "confusion_matrix": confusion_matrix(test_y, pred_series, labels=list(LABELS)).tolist(),
        "class_counts": Counter(y).copy(),
        "train_rows": int(len(train_x)),
        "validation_rows": int(len(valid_x)),
        "test_rows": int(len(test_x)),
        "best_iteration": int(model.get_best_iteration() or iterations),
    }
    return model, metrics


def write_importance(model: CatBoostClassifier, frame: pd.DataFrame) -> tuple[Path, Path | None]:
    MODEL_DIR.mkdir(parents=True, exist_ok=True)
    pool = Pool(frame[FEATURE_COLUMNS], frame["label"].astype(str))

    importance = model.get_feature_importance(type="FeatureImportance")
    importance_path = MODEL_DIR / "feature_importance.csv"
    pd.DataFrame({"feature": FEATURE_COLUMNS, "importance": importance}).sort_values(
        "importance", ascending=False
    ).to_csv(importance_path, index=False)

    shap_path: Path | None = None
    sample = frame.sample(min(200, len(frame)), random_state=42)
    try:
        shap_values = model.get_feature_importance(Pool(sample[FEATURE_COLUMNS], sample["label"].astype(str)), type="ShapValues")
        values = np.asarray(shap_values)
        if values.ndim == 3:
            mean_abs = np.abs(values[:, :, :-1]).mean(axis=(0, 1))
        else:
            mean_abs = np.abs(values[:, :-1]).mean(axis=0)
        shap_path = MODEL_DIR / "shap_feature_importance.csv"
        pd.DataFrame({"feature": FEATURE_COLUMNS, "mean_abs_shap": mean_abs}).sort_values(
            "mean_abs_shap", ascending=False
        ).to_csv(shap_path, index=False)
    except Exception as exc:  # noqa: BLE001
        print(f"SHAP export skipped: {type(exc).__name__}: {exc}")
    return importance_path, shap_path


def write_tfidf_tokens(frame: pd.DataFrame, *, top_n: int = 25) -> Path:
    MODEL_DIR.mkdir(parents=True, exist_ok=True)
    vectorizer = TfidfVectorizer(
        lowercase=True,
        token_pattern=r"(?u)\b[a-zA-Z0-9][a-zA-Z0-9_-]{2,}\b",
        max_features=2000,
        ngram_range=(1, 2),
    )
    matrix = vectorizer.fit_transform(frame["text_blob"].fillna("").astype(str))
    names = vectorizer.get_feature_names_out()
    rows: list[dict[str, Any]] = []
    for label in sorted(frame["label"].astype(str).unique()):
        mask = frame["label"].astype(str).to_numpy() == label
        if not mask.any():
            continue
        mean_scores = matrix[mask].mean(axis=0).A1
        top_indexes = mean_scores.argsort()[::-1][:top_n]
        for rank, index in enumerate(top_indexes, start=1):
            if mean_scores[index] <= 0:
                continue
            rows.append({"label": label, "rank": rank, "token": names[index], "mean_tfidf": float(mean_scores[index])})
    path = MODEL_DIR / "tfidf_top_tokens.csv"
    pd.DataFrame(rows).to_csv(path, index=False)
    return path


def write_report(
    metrics: dict[str, Any],
    audit: dict[str, Any],
    missing_classes: list[str],
    importance_path: Path,
    shap_path: Path | None,
    tfidf_path: Path,
) -> None:
    counts = dict(metrics["class_counts"])
    report = f"""
Argus domain multiclass classifier report
========================================

Model: CatBoostClassifier
Feature contract: {len(FEATURE_COLUMNS)} engineered URL/domain features recalculated from raw URLs.
Target classes requested: {', '.join(LABELS)}
Classes present in this training run: {', '.join(sorted(counts))}
Missing classes: {', '.join(missing_classes) if missing_classes else 'none'}

Data audit
----------
{json.dumps(audit, ensure_ascii=False, indent=2)}

Class distribution
------------------
{json.dumps(counts, ensure_ascii=False, indent=2)}

Split
-----
train: {metrics['train_rows']}
validation: {metrics['validation_rows']}
test: {metrics['test_rows']}

Metrics
-------
F1-macro, classes present in this run: {metrics['macro_f1_present_classes']:.4f}
F1-macro, requested 5-class label set: {metrics['macro_f1_requested_classes']:.4f}
Per-class recall:
{json.dumps(metrics['per_class_recall'], ensure_ascii=False, indent=2)}

Scikit classification report
----------------------------
{metrics['classification_report']}

Confusion matrix labels order:
{list(LABELS)}
Confusion matrix:
{json.dumps(metrics['confusion_matrix'], ensure_ascii=False)}

Interpretability
-----------------
Feature importance CSV: {importance_path}
SHAP mean absolute values CSV: {shap_path if shap_path else 'not generated'}
TF-IDF top tokens CSV: {tfidf_path}

Notes
-----
- UCI Phishing Websites ARFF files are excluded from training because they do not contain raw URL/domain values.
- PhiUSIIL precomputed columns are ignored; only URL and label are used, then Argus extracts the shared feature set again.
- Casino and pyramid classes require curated raw domains from Kazakhstan registry/open reports plus Gemini confidence > 0.9. If those files are absent under data/ml/raw/curated/*.csv, the current run is a baseline and cannot honestly report production quality for those classes.
- Curated casino/pyramid/legit seeds can be augmented into mirror-like URL variants. Augmented rows are marked weak_augmented and include weak technical priors for WHOIS/DNS/TLS so the model learns to use infrastructure signals. Production predictions still use real evidence values collected by Argus.
- For full evidence features, rerun with --network. The default offline mode is fast and uses URL/domain-derived features plus unavailable-network sentinel values.
"""
    REPORT_PATH.write_text(textwrap.dedent(report).strip() + "\n", encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description="Train Argus multiclass URL/domain classifier.")
    parser.add_argument("--download", action="store_true", help="Download public Kaggle datasets if missing.")
    parser.add_argument("--limit-per-class", type=int, default=3000)
    parser.add_argument("--curated-dir", type=Path, default=RAW_DIR / "curated")
    parser.add_argument("--min-confidence", type=float, default=0.90)
    parser.add_argument("--augment-curated-multiplier", type=int, default=20)
    parser.add_argument("--network", action="store_true", help="Enable requests/DNS/WHOIS/SSL/content extraction.")
    parser.add_argument("--proxy", default=None, help="Optional HTTP/SOCKS proxy for network extraction.")
    parser.add_argument("--timeout", type=int, default=8)
    parser.add_argument("--iterations", type=int, default=250)
    parser.add_argument("--depth", type=int, default=6)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    audit = ensure_raw_data(download=args.download)
    rows = [
        *load_malicious_rows(KAGGLE_DATASETS["malicious"]["csv"]),
        *load_phiusiil_rows(KAGGLE_DATASETS["phiusiil"]["csv"]),
        *load_curated_rows(args.curated_dir, args.min_confidence),
    ]
    rows, augmentation_counts = augment_curated_rows(
        rows,
        multiplier=args.augment_curated_multiplier,
        seed=args.seed,
    )
    rows = dedupe_rows(rows)
    rows = sample_by_class(rows, args.limit_per_class, args.seed)
    if len({row["label"] for row in rows}) < 2:
        raise SystemExit("Need at least two classes with raw URLs to train.")

    class_counts = Counter(row["label"] for row in rows)
    missing_classes = [label for label in LABELS if class_counts.get(label, 0) == 0]
    PROCESSED_DIR.mkdir(parents=True, exist_ok=True)
    frame = build_feature_frame(rows, network=args.network, timeout=args.timeout, proxy=args.proxy)
    features_path = PROCESSED_DIR / "training_features.csv"
    frame.to_csv(features_path, index=False)

    model, metrics = train(frame, iterations=args.iterations, depth=args.depth, seed=args.seed)
    MODEL_DIR.mkdir(parents=True, exist_ok=True)
    model_path = MODEL_DIR / "domain_classifier.cbm"
    model.save_model(model_path)
    importance_path, shap_path = write_importance(model, frame)
    tfidf_path = write_tfidf_tokens(frame)

    audit["processed"] = {
        "features_csv": str(features_path),
        "model": str(model_path),
        "network_features_enabled": args.network,
        "limit_per_class": args.limit_per_class,
        "augment_curated_multiplier": args.augment_curated_multiplier,
        "augmented_rows": augmentation_counts,
    }
    write_report(metrics, audit, missing_classes, importance_path, shap_path, tfidf_path)
    print(f"Wrote {REPORT_PATH}")
    print(f"Wrote {model_path}")


if __name__ == "__main__":
    main()
