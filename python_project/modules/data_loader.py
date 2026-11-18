"""
Data Loader Module for NETGUARD AI
Handles CSV upload, built-in demo dataset, column normalization, and data quality assessment.
"""

import os
import pandas as pd
import numpy as np

# Column aliases for automatic schema mapping
COLUMN_ALIASES = {
    "Timestamp": ["timestamp", "time", "flow_start_time", "date", "ts", "stime"],
    "Source_IP": ["src_ip", "source_ip", "srcip", "src_addr", "source_address", "saddr", "id.orig_h"],
    "Destination_IP": ["dst_ip", "destination_ip", "dstip", "dst_addr", "dest_address", "daddr", "id.resp_h"],
    "Source_Port": ["src_port", "source_port", "sport", "srcport", "id.orig_p"],
    "Destination_Port": ["dst_port", "destination_port", "dport", "dstport", "id.resp_p"],
    "Protocol": ["protocol", "proto"],
    "Flow_Duration": ["flow_duration", "duration", "dur", "tot_duration"],
    "Packet_Count": ["packet_count", "tot_pkts", "total_packets", "spkts", "dpkts", "packets", "tot_fwd_pkts"],
    "Byte_Count": ["byte_count", "tot_bytes", "total_bytes", "sbytes", "dbytes", "bytes", "totlen_fwd_pkts"],
    "Flow_Rate": ["flow_rate", "flow_bytes_s", "flow_byts_s", "rate", "byte_rate"],
    "Label": ["label", "attack", "class", "threat", "is_attack", "target"],
    "Attack_Category": ["attack_cat", "attack_category", "subcategory", "type", "attack_type"]
}


def auto_map_columns(df: pd.DataFrame) -> tuple[pd.DataFrame, dict, list]:
    """
    Automatically maps uploaded DataFrame columns to standard NETGUARD AI schema.
    Returns: (renamed_df, mapping_dict, missing_required_columns)
    """
    mapping = {}
    cleaned_cols = {col: col.lower().replace(" ", "").replace("_", "").replace("-", "").replace(".", "") for col in df.columns}

    for std_col, aliases in COLUMN_ALIASES.items():
        clean_aliases = [a.replace(" ", "").replace("_", "").replace("-", "").replace(".", "") for a in aliases]
        for orig_col, clean_orig in cleaned_cols.items():
            if clean_orig in clean_aliases or clean_orig == std_col.lower():
                mapping[orig_col] = std_col
                break

    mapped_df = df.rename(columns=mapping)
    
    # Check required columns
    required = ["Source_IP", "Destination_IP", "Protocol", "Flow_Duration", "Packet_Count", "Byte_Count"]
    missing_required = [col for col in required if col not in mapped_df.columns]

    return mapped_df, mapping, missing_required


def assess_data_quality(df: pd.DataFrame) -> dict:
    """
    Computes data quality metrics: missing values, duplicates, invalid numerics, label consistency.
    """
    total_rows = len(df)
    total_cols = len(df.columns)
    missing_count = int(df.isnull().sum().sum())
    
    # Duplicate check on 5-tuple if available, otherwise full row
    five_tuple = ["Source_IP", "Source_Port", "Destination_IP", "Destination_Port", "Protocol"]
    avail_tuple = [c for c in five_tuple if c in df.columns]
    if len(avail_tuple) >= 3:
        duplicate_count = int(df.duplicated(subset=avail_tuple).sum())
    else:
        duplicate_count = int(df.duplicated().sum())

    # Invalid numerics (negative values in duration, packets, bytes)
    invalid_numerics = 0
    numeric_cols = ["Flow_Duration", "Packet_Count", "Byte_Count", "Flow_Rate", "Source_Port", "Destination_Port"]
    for col in numeric_cols:
        if col in df.columns:
            s = pd.to_numeric(df[col], errors='coerce')
            invalid_numerics += int((s < 0).sum() + s.isna().sum())

    # Label consistency
    inconsistent_labels = 0
    if "Label" in df.columns:
        valid_labels = {"NORMAL", "SUSPICIOUS", "BENIGN", "ATTACK", "0", "1"}
        raw_labels = df["Label"].astype(str).str.upper().str.strip()
        inconsistent_labels = int((~raw_labels.isin(valid_labels)).sum())

    # Quality score (0 to 100)
    penalty = (missing_count / max(total_rows * total_cols, 1)) * 30 + \
              (duplicate_count / max(total_rows, 1)) * 25 + \
              (invalid_numerics / max(total_rows * len(numeric_cols), 1)) * 30
    quality_score = max(0, min(100, int(100 - penalty)))

    return {
        "total_rows": total_rows,
        "total_columns": total_cols,
        "missing_values": missing_count,
        "duplicates": duplicate_count,
        "invalid_numerics": invalid_numerics,
        "inconsistent_labels": inconsistent_labels,
        "quality_score": quality_score,
        "dtypes": {col: str(dtype) for col, dtype in df.dtypes.items()}
    }


def load_demo_dataset(file_path: str = None) -> pd.DataFrame:
    """
    Loads the built-in synthetic network demonstration dataset.
    """
    if file_path is None or not os.path.exists(file_path):
        cur_dir = os.path.dirname(os.path.abspath(__file__))
        file_path = os.path.join(os.path.dirname(cur_dir), "data", "sample_network_traffic.csv")

    df = pd.read_csv(file_path)
    return df
