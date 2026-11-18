"""
AI-Based Intrusion Detection Module for NETGUARD AI
Implements Logistic Regression, Decision Tree, Random Forest, and Isolation Forest models.
"""

import time
import numpy as np
import pandas as pd
from sklearn.linear_model import LogisticRegression
from sklearn.tree import DecisionTreeClassifier, export_text
from sklearn.ensemble import RandomForestClassifier, IsolationForest


def train_models(X_train: pd.DataFrame, y_train: pd.Series, random_state: int = 42) -> dict:
    """
    Trains Logistic Regression, Decision Tree, Random Forest, and Isolation Forest models.
    Returns dictionary of trained models.
    """
    models = {}

    # 1. Logistic Regression (Benchmark)
    lr = LogisticRegression(max_iter=500, random_state=random_state)
    lr.fit(X_train, y_train)
    models["logistic_regression"] = lr

    # 2. Decision Tree (Explainable)
    dt = DecisionTreeClassifier(max_depth=6, min_samples_split=4, random_state=random_state)
    dt.fit(X_train, y_train)
    models["decision_tree"] = dt

    # 3. Random Forest (Ensemble)
    rf = RandomForestClassifier(n_estimators=50, max_depth=6, random_state=random_state)
    rf.fit(X_train, y_train)
    models["random_forest"] = rf

    # 4. Isolation Forest (Unsupervised Anomaly Detection)
    iso = IsolationForest(n_estimators=50, contamination=0.25, random_state=random_state)
    iso.fit(X_train)
    models["isolation_forest"] = iso

    return models


def determine_flow_severity(row: pd.Series, predicted_label: str, confidence: float) -> tuple[str, str]:
    """
    Computes explainable severity level and rationale.
    """
    if predicted_label != "SUSPICIOUS":
        return "LOW", "Baseline normal network communication."

    dst_port = row.get("Destination_Port", 80)
    flow_rate = row.get("Flow_Rate", 0)
    packet_count = row.get("Packet_Count", 1)
    attack_cat = row.get("Attack_Category", "Unknown")

    if attack_cat == "DoS / DDoS" or flow_rate > 500000 or packet_count > 500:
        return "CRITICAL", f"Severe traffic volumetric flood ({packet_count} packets, {round(flow_rate/1024, 1)} KB/s)."

    if attack_cat == "Botnet / C2" or dst_port == 4444:
        return "CRITICAL", f"Potential Command & Control beaconing detected on port {dst_port}."

    if attack_cat == "Brute Force" or dst_port in [22, 3389, 445]:
        return "HIGH", f"Credential brute-force targeting administrative service on port {dst_port}."

    if attack_cat == "Web Attack" or (row.get("Byte_Count", 0) > 10000 and dst_port in [80, 443, 8080]):
        return "HIGH", f"Abnormal HTTP request size ({round(row.get('Byte_Count', 0)/1024, 1)} KB) targeting web service on port {dst_port}."

    if attack_cat == "Port Scan" or (packet_count <= 3 and row.get("Flow_Duration", 0) < 0.05):
        return "MEDIUM", f"Rapid single-probe connection to port {dst_port}, indicative of port sweep enumeration."

    if confidence > 0.8:
        return "MEDIUM", f"High ML model confidence ({round(confidence * 100)}%) detecting anomalous traffic signature."

    return "LOW", f"Minor statistical flow anomaly (Confidence: {round(confidence * 100)}%)."


def run_model_inference(model_name: str, model, X_eval: pd.DataFrame, orig_df: pd.DataFrame) -> pd.DataFrame:
    """
    Runs intrusion detection inference and attaches prediction labels, confidences, and severity ratings.
    """
    results_df = orig_df.copy()

    if model_name == "isolation_forest":
        raw_preds = model.predict(X_eval) # -1 is anomaly, 1 is normal
        scores = -model.score_samples(X_eval) # higher score = more anomalous
        labels = ["SUSPICIOUS" if p == -1 else "NORMAL" for p in raw_preds]
        confidences = [round(float(s), 3) for s in scores]
    else:
        raw_preds = model.predict(X_eval)
        probs = model.predict_proba(X_eval)
        labels = ["SUSPICIOUS" if p == 1 else "NORMAL" for p in raw_preds]
        confidences = [round(float(probs[i][raw_preds[i]]), 3) for i in range(len(raw_preds))]

    results_df["Predicted_Label"] = labels
    results_df["Confidence"] = confidences
    results_df["Model_Used"] = model_name

    severities = []
    reasons = []
    for idx, row in results_df.iterrows():
        sev, reason = determine_flow_severity(row, row["Predicted_Label"], row["Confidence"])
        severities.append(sev)
        reasons.append(reason)

    results_df["Severity"] = severities
    results_df["Detection_Reason"] = reasons

    return results_df
