import json
import csv
from datetime import datetime, timezone
from pathlib import Path

import joblib
import pandas as pd
from flask import Flask, request, jsonify
from flask_cors import CORS
from urllib.parse import urlparse

try:
    from .feature_extraction import extract_features_with_reasons
except ImportError:
    from feature_extraction import extract_features_with_reasons



app = Flask(__name__)
CORS(app)


BASE_DIR     = Path(__file__).resolve().parent.parent
MODEL_PATH   = BASE_DIR / "model" / "model.pkl"
META_PATH    = BASE_DIR / "model" / "model_meta.pkl"
REPORTS_DIR  = BASE_DIR / "reports"
REPORTS_CSV  = REPORTS_DIR / "reported_urls.csv"
REPORTS_JSON = REPORTS_DIR / "reported_urls.json"

REPORTS_DIR.mkdir(exist_ok=True)


model         = joblib.load(MODEL_PATH)
metadata      = joblib.load(META_PATH)
feature_names = metadata["feature_names"]


TRUSTED_DOMAINS = {
    "google.com", "youtube.com", "wikipedia.org", "microsoft.com",
    "github.com", "stackoverflow.com", "openai.com", "amazon.com",
    "apple.com", "linkedin.com", "twitter.com", "x.com", "reddit.com",
    "netflix.com", "spotify.com", "instagram.com", "facebook.com",
}


def is_trusted_domain(url: str) -> bool:
    host = (urlparse(url).hostname or "").lower()
    return bool(host) and any(
        host == d or host.endswith(f".{d}") for d in TRUSTED_DOMAINS
    )


def get_risk_level(confidence: float, label: str) -> str:
    if label == "legitimate":
        return "Low Risk"
    if confidence >= 0.80:
        return "High Risk"
    if confidence >= 0.50:
        return "Medium Risk"
    return "Low Risk"



REASON_MAP = {
    "Domain uses direct IP address":
        "Website uses a raw IP address instead of a domain name",
    "Very long URL":
        "Unusually long URL — a common phishing obfuscation technique",
    "URL shortener detected":
        "URL shortening service detected — hides the true destination",
    "Contains '@' symbol in URL":
        "URL contains '@' symbol — used to deceive browsers",
    "Has suspicious double-slash redirect":
        "Suspicious redirect pattern found in the URL path",
    "Domain contains '-' pattern":
        "Domain uses hyphens to mimic legitimate sites (e.g. paypal-secure.com)",
    "Too many subdomains":
        "Excessive subdomains detected — common in phishing URLs",
    "Not using HTTPS":
        "Website is not secured with HTTPS encryption",
    "Suspicious 'https' token in domain":
        "Fake 'https' keyword embedded in domain name to appear secure",
    "Page appears to submit data through email":
        "Form submits data via email — highly suspicious behaviour",
    "Trusted allowlist domain":
        "Domain is on the verified trusted allowlist",
    "Suspicious top-level domain (TLD) detected":
        "Domain uses a TLD commonly associated with free/phishing sites",
    "Multiple redirect patterns in URL path":
        "Multiple redirect patterns detected in the URL path",
}


def humanize_reasons(reasons: list) -> list:
    return [REASON_MAP.get(r, r) for r in reasons]



@app.route("/predict", methods=["POST"])
def predict():
    data = request.get_json(silent=True) or {}
    url  = data.get("url", "").strip()

    if not url:
        return jsonify({"error": "url is required"}), 400

    if is_trusted_domain(url):
        return jsonify({
            "prediction": 1,
            "label":      "legitimate",
            "confidence": 1.0,
            "reasons":    ["Trusted allowlist domain"],
            "riskLevel":  "Low Risk",
        })


    extracted, raw_reasons = extract_features_with_reasons(url)
    ordered  = [extracted.get(name, 1) for name in feature_names]
    df       = pd.DataFrame([ordered], columns=feature_names)

  
    prediction  = int(model.predict(df)[0])
    proba       = model.predict_proba(df)[0]
    confidence  = float(proba[list(model.classes_).index(prediction)])


    label      = "phishing" if prediction == -1 else "legitimate"
    reasons    = humanize_reasons(raw_reasons[:3])
    risk_level = get_risk_level(confidence, label)

    return jsonify({
        "prediction": prediction,
        "label":      label,
        "confidence": round(confidence, 4),
        "reasons":    reasons,
        "riskLevel":  risk_level,
    })


@app.route("/report", methods=["POST"])
def report():
    data = request.get_json(silent=True) or {}
    url  = data.get("url", "").strip()

    if not url:
        return jsonify({"error": "url is required"}), 400

    timestamp  = datetime.now(timezone.utc).isoformat()
    label      = data.get("label", "unknown")
    confidence = data.get("confidence")
    reasons    = data.get("reasons", [])

    entry = {
        "url": url, "timestamp": timestamp,
        "label": label, "confidence": confidence, "reasons": reasons,
    }

    existing = []
    if REPORTS_JSON.exists():
        try:
            with open(REPORTS_JSON, "r", encoding="utf-8") as f:
                existing = json.load(f)
        except (json.JSONDecodeError, IOError):
            existing = []
    existing.append(entry)
    with open(REPORTS_JSON, "w", encoding="utf-8") as f:
        json.dump(existing, f, indent=2, ensure_ascii=False)


    csv_exists = REPORTS_CSV.exists()
    with open(REPORTS_CSV, "a", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(
            f, fieldnames=["url", "timestamp", "label", "confidence", "reasons"]
        )
        if not csv_exists:
            writer.writeheader()
        writer.writerow({
            "url":        url,
            "timestamp":  timestamp,
            "label":      label,
            "confidence": confidence if confidence is not None else "",
            "reasons":    "; ".join(reasons) if isinstance(reasons, list) else str(reasons),
        })

    return jsonify({"status": "reported", "message": "URL reported successfully"})



if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
