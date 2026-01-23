import streamlit as st
import pandas as pd
import numpy as np

# --------------------------------------------------
# Import your model inference function
# --------------------------------------------------
from model.model import detect_probe   # adjust import if needed

# --------------------------------------------------
# UI CONFIG
# --------------------------------------------------
st.set_page_config(
    page_title="Bipartite Graph Zero-Day IDS",
    layout="centered"
)

st.title("🚨 Bipartite Graph Based Zero-Day Attack Detection")
st.caption("Probe attack detection using unsupervised graph autoencoder")

st.divider()

# --------------------------------------------------
# INPUT SECTION
# --------------------------------------------------
st.subheader("📥 Input Network Traffic")

uploaded_file = st.file_uploader(
    "Upload network traffic file (CSV)",
    type=["csv"]
)

if uploaded_file:
    data = pd.read_csv(uploaded_file)
    st.write("Preview of input data:")
    st.dataframe(data.head())

    if st.button("🔍 Run Detection"):
        with st.spinner("Running anomaly detection..."):

            # --------------------------------------------------
            # MODEL INFERENCE
            # --------------------------------------------------
            anomaly_score = detect_probe(data)

            # Threshold (use what you already decided experimentally)
            THRESHOLD = 0.75

            st.divider()
            st.subheader("📊 Detection Result")

            st.metric(
                label="Anomaly Score",
                value=round(anomaly_score, 4)
            )

            st.metric(
                label="Threshold",
                value=THRESHOLD
            )

            if anomaly_score > THRESHOLD:
                st.error("🚨 PROBE ATTACK DETECTED")
            else:
                st.success("✅ Normal Traffic")

else:
    st.info("Upload a CSV file to start detection.")
