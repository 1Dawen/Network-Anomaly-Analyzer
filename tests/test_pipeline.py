import pandas as pd
import pytest

from risk_pipeline import (
    MODEL_FEATURES, aggregate_user_risk, analyze, calculate_risk,
    classify_risk, detect_anomalies, preprocess_data, train_model,
)


def rows():
    return pd.DataFrame({
        "SOURCE_IP": ["192.0.2.1", "192.0.2.1", "192.0.2.2", "192.0.2.3"],
        "DATE_TIME": ["2025-04-05 23:00:00", "2025-04-07 10:00:00", "2025-04-07 12:00:00", "2025-04-07 18:00:00"],
        "RCVD_BYTE": [2000, 1, 125, 300],
        "SENT_BYTE": [4000, 1, 300, 900],
        "DURATION": [100, 3, 20, 42],
        "DESTINATION_PORT": [8080, 443, 22, 5432],
        "ACTION": ["deny", "accept", "deny", "accept"],
    })


def test_weekend_period_and_bytes():
    df = preprocess_data(rows())
    assert df.loc[0, "THREAT_PERIOD"] == 1.0
    assert df.loc[1, "THREAT_PERIOD"] == 0.0
    assert df.loc[2, "THREAT_BYTES"] == 0.6
    assert df.loc[0, "IS_DENY"] == 1


def test_missing_column():
    with pytest.raises(ValueError, match="DESTINATION_PORT"):
        preprocess_data(rows().drop(columns="DESTINATION_PORT"))


def test_invalid_timestamp():
    bad = rows()
    bad.loc[0, "DATE_TIME"] = "not a timestamp"
    with pytest.raises(ValueError, match="DATE_TIME"):
        preprocess_data(bad)


def test_train_predict_and_aggregate():
    raw = rows()
    processed = preprocess_data(raw)
    model = train_model(processed, contamination=0.25)
    events, users = analyze(raw, model)
    assert len(events) == 4
    assert len(users) == 3
    assert set(events["ISO_ANOMALY"].unique()).issubset({-1, 1})
    assert events["RISK_SCORE"].between(0, 1).all()
    assert users["NUM_EVENTS"].sum() == 4
    assert users["RISK_LEVEL"].isin(["Low", "Medium", "High"]).all()
    assert list(model.feature_names_in_) == MODEL_FEATURES if hasattr(model, "feature_names_in_") else True


def test_scores_do_not_change_with_batch_composition():
    processed = preprocess_data(rows())
    marked = processed.copy()
    marked["ANOMALY_BIN"] = [1, 0, 0, 1]
    one = calculate_risk(marked.iloc[[0]])["RISK_SCORE"].iloc[0]
    batch = calculate_risk(marked)["RISK_SCORE"].iloc[0]
    assert one == batch


def test_inference_uses_fitted_scaler():
    processed = preprocess_data(rows())
    model = train_model(processed, contamination=0.25)
    one = detect_anomalies(processed.iloc[[0]], model)["ISO_ANOMALY"].iloc[0]
    batch = detect_anomalies(processed, model)["ISO_ANOMALY"].iloc[0]
    assert one == batch


def test_thresholds():
    assert classify_risk(0.7) == "High"
    assert classify_risk(0.4) == "Medium"
    assert classify_risk(0.399) == "Low"
