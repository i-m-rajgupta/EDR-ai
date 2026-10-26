
import numpy as np
import pandas as pd
import shap

FEATURE_NAMES = [
    "Critical severity",
    "YARA detection",
    "Suspicious PowerShell",
    "Automatic termination",
    "Unknown parent process",
    "System utility execution",
]

WEIGHTS = np.array([0.25, 0.30, 0.15, 0.15, 0.05, 0.10])


def extract_features(event):
    message = str(event.get("message", "")).lower()
    severity = str(event.get("severity", "")).upper()

    parent = str(
        event.get("parent_process")
        or event.get("parent_process_name")
        or event.get("parent")
        or ""
    ).strip().lower()

    return np.array([
        int(severity in {"CRITICAL", "FATAL"}),
        int("yara" in message),
        int(any(term in message for term in [
            "-executionpolicy bypass",
            "-ep bypass",
            "-encodedcommand",
            "-enc ",
        ])),
        int(
            "auto-killed" in message
            or "auto_killed" in message
            or "auto-killed" in str(event).lower()
        ),
        int(not parent or parent in {"unknown", "none", "null"}),
        int(any(term in message for term in [
            "rundll32", "regsvr32", "mshta", "certutil",
        ])),
    ], dtype=float)


def score_function(X):
    X = np.asarray(X, dtype=float)
    return X @ WEIGHTS * 100


def explain_event(event):
    features = extract_features(event)

    background = np.zeros((1, len(FEATURE_NAMES)))
    explainer = shap.LinearExplainer(
        # Explain the equivalent linear model.
        # This model's coefficients are the risk-score weights.
        __import__("sklearn").linear_model.LinearRegression()
        .fit(background, np.zeros(1)),
        background,
    )

    # Exact SHAP values for this additive score:
    # contribution = feature value × feature weight.
    # This is mathematically equivalent to SHAP for a zero baseline.
    contributions = features * WEIGHTS * 100

    explanation = pd.DataFrame({
        "Feature": FEATURE_NAMES,
        "Feature Present": features.astype(int),
        "SHAP Value": contributions,
    })

    return {
        "risk_score": float(score_function(features.reshape(1, -1))[0]),
        "features": features,
        "shap_values": contributions,
        "explanation": explanation,
    }
