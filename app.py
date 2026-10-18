"""Streamlit dashboard for the firewall risk scoring demonstration."""
from pathlib import Path

import joblib
import pandas as pd
import streamlit as st

from risk_pipeline import analyze

BASE_DIR = Path(__file__).resolve().parent
MODEL_PATH = BASE_DIR / "artifacts" / "model.joblib"
SAMPLE_PATH = BASE_DIR / "data" / "sample_firewall_logs.csv"

st.set_page_config(page_title="Firewall Risk Analyzer", layout="wide")
st.title("Firewall Risk Analyzer")
st.caption("Academic demonstration. Anomalies and heuristic risk scores do not confirm malicious activity.")

if not MODEL_PATH.exists():
    st.error("No trained model found. Run `python train.py --data data/sample_firewall_logs.csv` first.")
    st.stop()


@st.cache_resource
def load_model(path: str):
    # Load only models you trained or trust. joblib/pickle can execute code.
    return joblib.load(path)


model = load_model(str(MODEL_PATH))
st.write("Upload a compatible CSV or try the synthetic sample included in this repository.")
use_demo = st.checkbox("Use synthetic sample data")
uploaded = st.file_uploader("Firewall log CSV", type=["csv"], disabled=use_demo)

if use_demo or uploaded is not None:
    try:
        if use_demo:
            raw = pd.read_csv(SAMPLE_PATH)
        else:
            raw = pd.read_csv(uploaded, low_memory=False)
        events, users = analyze(raw, model)
    except (ValueError, KeyError, pd.errors.ParserError) as exc:
        st.error(f"Unable to process CSV: {exc}")
        st.stop()

    c1, c2, c3 = st.columns(3)
    c1.metric("Events", f"{len(events):,}")
    c2.metric("Source IPs", f"{len(users):,}")
    c3.metric("Outlier events", f"{int(events['ANOMALY_BIN'].sum()):,}")

    st.subheader("Highest-risk source IPs")
    st.dataframe(users.head(20), use_container_width=True)
    st.bar_chart(users.set_index("SOURCE_IP")["RISK_SCORE"].head(15))

    st.download_button(
        "Download user risk summary (CSV)",
        data=users.to_csv(index=False).encode("utf-8"),
        file_name="user_risk_summary.csv",
        mime="text/csv",
    )
    with st.expander("Risk score and assumptions"):
        st.write(
            "Per-event risk = 0.2 * time heuristic + 0.1 * received-byte heuristic "
            "+ 0.1 * capped byte ratio + 0.1 * denied action + 0.1 * high port "
            "+ 0.4 * Isolation Forest flag. User risk is mean event risk. "
            "High >= 0.7; Medium >= 0.4; Low otherwise. These are not calibrated probabilities."
        )
