"""Reproducible feature engineering and anomaly-based firewall risk scoring.

Risk scores are heuristic prioritization signals, not attack probabilities.
"""
from __future__ import annotations

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.impute import SimpleImputer
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import RobustScaler

REQUIRED_COLUMNS = (
    "SOURCE_IP", "DATE_TIME", "RCVD_BYTE", "SENT_BYTE", "DURATION",
    "DESTINATION_PORT", "ACTION",
)
MODEL_FEATURES = [
    "THREAT_PERIOD", "THREAT_BYTES", "BYTE_RATIO", "IS_DENY",
    "IS_HIGH_PORT", "DURATION",
]
WEIGHTS = {
    "THREAT_PERIOD": 0.2,
    "THREAT_BYTES": 0.1,
    "BYTE_RATIO_NORM": 0.1,
    "IS_DENY": 0.1,
    "IS_HIGH_PORT": 0.1,
    "ANOMALY_BIN": 0.4,
}


def preprocess_data(raw: pd.DataFrame) -> pd.DataFrame:
    """Validate columns and derive the same numeric features at training/inference."""
    missing = sorted(set(REQUIRED_COLUMNS) - set(raw.columns))
    if missing:
        raise ValueError("Missing required columns: " + ", ".join(missing))
    if raw.empty:
        raise ValueError("The input CSV is empty.")
    df = raw.copy()
    dates = pd.to_datetime(df["DATE_TIME"], format="%Y-%m-%d %H:%M:%S", errors="coerce")
    if dates.isna().any():
        raise ValueError("DATE_TIME contains missing or invalid timestamps.")
    df["DATE_TIME"] = dates
    if df["SOURCE_IP"].isna().any() or df["SOURCE_IP"].astype(str).str.strip().eq("").any():
        raise ValueError("SOURCE_IP must be present on every row.")

    for column in ["RCVD_BYTE", "SENT_BYTE", "DURATION", "DESTINATION_PORT"]:
        df[column] = pd.to_numeric(df[column], errors="coerce")
        df[column] = df[column].replace([np.inf, -np.inf], np.nan)
        # Negative bytes, durations and ports are invalid; treat as missing.
        df[column] = df[column].mask(df[column] < 0)

    sent = df["SENT_BYTE"].fillna(0)
    received = df["RCVD_BYTE"].fillna(0)
    df["BYTE_RATIO"] = (sent / (received + 1)).clip(0, 10)
    # Fixed normalization for comparable scores across CSV uploads.
    df["BYTE_RATIO_NORM"] = df["BYTE_RATIO"] / 10
    df["IS_DENY"] = df["ACTION"].astype(str).str.strip().str.lower().eq("deny").astype(int)
    df["IS_HIGH_PORT"] = df["DESTINATION_PORT"].ge(1024).astype(int)
    df["DURATION"] = df["DURATION"].fillna(0)

    hours = dates.dt.hour
    weekends = dates.dt.dayofweek >= 5
    # Original notebook's schedule-based risk heuristic; weekend typo fixed.
    period = np.select(
        [hours >= 23, hours < 7, hours >= 18, hours < 9, hours == 12],
        [1.0, 1.0, 0.8, 0.6, 0.4],
        default=0.0,
    )
    df["THREAT_PERIOD"] = np.where(weekends, 1.0, period)

    # Original heuristic uses received bytes, not total transferred bytes.
    df["THREAT_BYTES"] = np.select(
        [received < 50, received < 200, received < 500],
        [0.0, 0.6, 0.8],
        default=1.0,
    )
    return df


def make_model(contamination: float = 0.05) -> Pipeline:
    """Keep the fitted imputer/scaler together with Isolation Forest."""
    return Pipeline([
        ("imputer", SimpleImputer(strategy="constant", fill_value=0)),
        ("scaler", RobustScaler()),
        ("isolation_forest", IsolationForest(
            n_estimators=100, contamination=contamination, random_state=0
        )),
    ])


def train_model(processed: pd.DataFrame, contamination: float = 0.05) -> Pipeline:
    model = make_model(contamination)
    model.fit(processed[MODEL_FEATURES])
    return model


def detect_anomalies(processed: pd.DataFrame, model: Pipeline) -> pd.DataFrame:
    """Predict without refitting any transformations."""
    df = processed.copy()
    predicted = model.predict(df[MODEL_FEATURES])
    df["ISO_ANOMALY"] = predicted
    df["ANOMALY_BIN"] = (predicted == -1).astype(int)
    return df


def calculate_risk(processed: pd.DataFrame) -> pd.DataFrame:
    """Apply the original weighted heuristic on a stable fixed [0,1] scale."""
    df = processed.copy()
    score = sum(df[col].fillna(0).clip(0, 1) * weight for col, weight in WEIGHTS.items())
    df["RISK_SCORE"] = score.clip(0, 1)
    return df


def classify_risk(score: float) -> str:
    if score >= 0.7:
        return "High"
    if score >= 0.4:
        return "Medium"
    return "Low"


def aggregate_user_risk(processed: pd.DataFrame) -> pd.DataFrame:
    """Summarize event-level risk by SOURCE_IP using mean risk."""
    groups = processed.groupby("SOURCE_IP", sort=False)
    summary = groups.agg(
        RISK_SCORE=("RISK_SCORE", "mean"),
        THREAT_PERIOD=("THREAT_PERIOD", "mean"),
        THREAT_BYTES=("THREAT_BYTES", "mean"),
        BYTE_RATIO=("BYTE_RATIO", "mean"),
        DURATION=("DURATION", "mean"),
        IS_DENY=("IS_DENY", "mean"),
        ANOMALY_RATE=("ANOMALY_BIN", "mean"),
        FIRST_SEEN=("DATE_TIME", "min"),
        LAST_SEEN=("DATE_TIME", "max"),
        NUM_EVENTS=("DATE_TIME", "size"),
    ).reset_index()
    summary["RISK_LEVEL"] = summary["RISK_SCORE"].map(classify_risk)
    return summary.sort_values("RISK_SCORE", ascending=False).reset_index(drop=True)


def analyze(raw: pd.DataFrame, model: Pipeline) -> tuple[pd.DataFrame, pd.DataFrame]:
    events = calculate_risk(detect_anomalies(preprocess_data(raw), model))
    return events, aggregate_user_risk(events)
