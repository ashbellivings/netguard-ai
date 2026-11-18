"""
Data Preprocessing Module for NETGUARD AI
Performs data cleaning, imputation, categorical encoding, scaling, and train/test splitting.
Guarantees strict data leakage prevention by fitting scalers strictly on training data.
"""

import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import MinMaxScaler


def standardize_label(val):
    if pd.isna(val):
        return "NORMAL"
    v = str(val).strip().upper()
    if v in ["NORMAL", "BENIGN", "0", "SAFE", "LEGITIMATE"]:
        return "NORMAL"
    return "SUSPICIOUS"


def preprocess_network_data(df: pd.DataFrame, train_ratio: float = 0.75, random_state: int = 42):
    """
    Cleans raw network traffic data, encodes categorical features, and performs
    a leak-free stratified train/test split.
    """
    cleaned_df = df.copy()

    # 1. Deduplication
    initial_count = len(cleaned_df)
    subset_cols = [c for c in ["Source_IP", "Source_Port", "Destination_IP", "Destination_Port", "Protocol", "Timestamp"] if c in cleaned_df.columns]
    if len(subset_cols) >= 3:
        cleaned_df = cleaned_df.drop_duplicates(subset=subset_cols).reset_index(drop=True)
    duplicates_removed = initial_count - len(cleaned_df)

    # 2. Ensure required numeric/port columns exist & impute invalid values
    if "Destination_Port" not in cleaned_df.columns:
        cleaned_df["Destination_Port"] = 80
    if "Flow_Duration" not in cleaned_df.columns:
        cleaned_df["Flow_Duration"] = 0.5
    if "Packet_Count" not in cleaned_df.columns:
        cleaned_df["Packet_Count"] = 10
    if "Byte_Count" not in cleaned_df.columns:
        cleaned_df["Byte_Count"] = cleaned_df["Packet_Count"] * 64
    if "Flow_Rate" not in cleaned_df.columns:
        cleaned_df["Flow_Rate"] = 0.0

    numeric_cols = ["Flow_Duration", "Packet_Count", "Byte_Count", "Flow_Rate", "Source_Port", "Destination_Port"]
    for col in numeric_cols:
        if col in cleaned_df.columns:
            cleaned_df[col] = pd.to_numeric(cleaned_df[col], errors='coerce')
            median_val = cleaned_df[col].median()
            cleaned_df[col] = cleaned_df[col].fillna(median_val if not pd.isna(median_val) else 0)
            cleaned_df[col] = cleaned_df[col].clip(lower=0)

    # Recompute flow rate if missing/zero
    dur_safe = cleaned_df["Flow_Duration"].replace(0, 0.001)
    cleaned_df["Flow_Rate"] = np.where(cleaned_df["Flow_Rate"] <= 0, cleaned_df["Byte_Count"] / dur_safe, cleaned_df["Flow_Rate"])

    # 3. Standardize labels
    if "Label" in cleaned_df.columns:
        cleaned_df["Label"] = cleaned_df["Label"].apply(standardize_label)
    else:
        cleaned_df["Label"] = "NORMAL"

    # 4. Feature Selection & One-Hot Encoding
    # Log-transform skewed volume features
    cleaned_df["Log_Packet_Count"] = np.log1p(cleaned_df["Packet_Count"])
    cleaned_df["Log_Byte_Count"] = np.log1p(cleaned_df["Byte_Count"])
    cleaned_df["Log_Flow_Rate"] = np.log1p(cleaned_df["Flow_Rate"])

    # Categorical Protocol Encoding
    if "Protocol" in cleaned_df.columns:
        cleaned_df["Proto_TCP"] = (cleaned_df["Protocol"].astype(str).str.upper() == "TCP").astype(int)
        cleaned_df["Proto_UDP"] = (cleaned_df["Protocol"].astype(str).str.upper() == "UDP").astype(int)
        cleaned_df["Proto_ICMP"] = (cleaned_df["Protocol"].astype(str).str.upper() == "ICMP").astype(int)
    else:
        cleaned_df["Proto_TCP"] = 1
        cleaned_df["Proto_UDP"] = 0
        cleaned_df["Proto_ICMP"] = 0

    feature_cols = [
        "Flow_Duration",
        "Log_Packet_Count",
        "Log_Byte_Count",
        "Log_Flow_Rate",
        "Destination_Port",
        "Proto_TCP",
        "Proto_UDP",
        "Proto_ICMP"
    ]

    # Destination Port fallback
    if "Destination_Port" not in cleaned_df.columns:
        cleaned_df["Destination_Port"] = 80

    X = cleaned_df[feature_cols]
    y = (cleaned_df["Label"] == "SUSPICIOUS").astype(int)

    # 5. Stratified Train / Test Split
    stratify = y if len(y.unique()) > 1 else None
    X_train_raw, X_test_raw, y_train, y_test, train_idx, test_idx = train_test_split(
        X, y, cleaned_df.index, train_size=train_ratio, random_state=random_state, stratify=stratify
    )

    # 6. Fit Scaler SOLELY on Training Split (Prevent Data Leakage)
    scaler = MinMaxScaler()
    scale_cols = ["Flow_Duration", "Log_Packet_Count", "Log_Byte_Count", "Log_Flow_Rate", "Destination_Port"]

    X_train = X_train_raw.copy()
    X_test = X_test_raw.copy()

    X_train[scale_cols] = scaler.fit_transform(X_train_raw[scale_cols])
    X_test[scale_cols] = scaler.transform(X_test_raw[scale_cols])

    train_df = cleaned_df.loc[train_idx].copy()
    test_df = cleaned_df.loc[test_idx].copy()

    normal_count = int((cleaned_df["Label"] == "NORMAL").sum())
    sus_count = int((cleaned_df["Label"] == "SUSPICIOUS").sum())

    summary = {
        "initial_rows": initial_count,
        "cleaned_rows": len(cleaned_df),
        "duplicates_removed": duplicates_removed,
        "train_rows": len(X_train),
        "test_rows": len(X_test),
        "normal_count": normal_count,
        "suspicious_count": sus_count,
        "imbalance_ratio": round(normal_count / max(sus_count, 1), 2),
        "features_used": feature_cols,
        "scaling_method": "Log1p Transformation + Min-Max Normalization",
        "leakage_safeguards": [
            "MinMaxScaler fitted strictly on training subset",
            "Stratified split preserves class ratio between train and test sets",
            "Non-network metadata (IPs, timestamps) excluded from feature matrix",
        ]
    }

    return cleaned_df, X_train, X_test, y_train, y_test, train_df, test_df, scaler, summary
