import streamlit as st
import numpy as np
import torch
import matplotlib.pyplot as plt

# -----------------------------
# IMPORT YOUR FUNCTIONS
# -----------------------------
# You will replace these with your actual functions
from detection import run_probe_detection

# -----------------------------
# PAGE CONFIG
# -----------------------------
st.set_page_config(
    page_title="Graph-Based Zero-Day IDS",
    layout="wide"
)

st.title("🔐 Graph-Based Zero-Day Intrusion Detection System")
st.markdown("**Probe Attack Detection using Bipartite Graph Autoencoders**")

st.divider()

# -----------------------------
# SIDEBAR CONTROLS
# -----------------------------
st.sidebar.header("Configuration")

threshold_percentile = st.sidebar.slider(
    "Anomaly Threshold Percentile",
    min_value=80,
    max_value=99,
    value=90
)

run_button = st.sidebar.button("🚀 Run Probe Detection")

# -----------------------------
# MAIN LOGIC
# -----------------------------
if run_button:
    with st.spinner("Running detection pipeline..."):
        results = run_probe_detection(threshold_percentile)

    st.success("Detection completed successfully!")

    # -----------------------------
    # METRICS
    # -----------------------------
    col1, col2, col3, col4 = st.columns(4)

    col1.metric("AUROC", f"{results['auroc']:.3f}")
    col2.metric("Precision", f"{results['precision']:.3f}")
    col3.metric("Recall", f"{results['recall']:.3f}")
    col4.metric("FPR", f"{results['fpr']:.3f}")

    st.divider()

    # -----------------------------
    # DETECTED HOSTS
    # -----------------------------
    st.subheader("🚨 Detected Probe Hosts")

    if len(results["detected_hosts"]) == 0:
        st.info("No probe hosts detected at this threshold.")
    else:
        st.write(results["detected_hosts"])

    # -----------------------------
    # OPTIONAL: SCORE DISTRIBUTION
    # -----------------------------
    st.subheader("📊 Anomaly Score Distribution")

    fig, ax = plt.subplots()
    ax.hist(results["scores"], bins=50)
    ax.axvline(results["threshold"], color="red", linestyle="--", label="Threshold")
    ax.legend()

    st.pyplot(fig)
