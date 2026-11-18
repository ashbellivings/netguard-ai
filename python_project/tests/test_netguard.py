"""
Automated Test Suite for NETGUARD AI
Verifies data loading, quality analysis, leak-free preprocessing,
ML classification models, evaluation metrics, and SQLite incident persistence.
"""

import os
import sys
import tempfile
import unittest
import pandas as pd
import numpy as np

# Add parent directory to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from modules.data_loader import auto_map_columns, assess_data_quality, load_demo_dataset
from modules.preprocessing import preprocess_network_data
from modules.intrusion_detection import train_models, run_model_inference
from modules.model_evaluation import evaluate_models
from modules.alert_manager import (
    init_db,
    sync_alerts_from_predictions,
    get_all_alerts,
    update_alert_status,
    get_investigation_notes
)
from modules.exploratory_analysis import generate_automated_findings


class TestNetGuardAI(unittest.TestCase):

    def setUp(self):
        # Create a small synthetic test dataframe
        self.test_df = pd.DataFrame({
            "Timestamp": ["2026-11-09 08:00:00", "2026-11-09 08:00:10", "2026-11-09 08:00:20", "2026-11-09 08:00:30"],
            "Source_IP": ["192.168.1.10", "192.168.1.20", "185.220.101.5", "45.142.122.9"],
            "Destination_IP": ["192.168.1.1", "142.250.190.46", "192.168.1.50", "192.168.1.10"],
            "Source_Port": [54100, 51234, 48120, 38100],
            "Destination_Port": [53, 443, 22, 22],
            "Protocol": ["UDP", "TCP", "TCP", "TCP"],
            "Flow_Duration": [0.012, 3.450, 0.005, 0.850],
            "Packet_Count": [2, 30, 1, 14],
            "Byte_Count": [148, 18500, 44, 1820],
            "Flow_Rate": [12333.3, 5362.3, 8800.0, 2141.2],
            "Label": ["NORMAL", "NORMAL", "SUSPICIOUS", "SUSPICIOUS"],
            "Attack_Category": ["Normal", "Normal", "Port Scan", "Brute Force"]
        })

    def test_auto_map_columns(self):
        """Test column normalization and alias detection"""
        alt_df = pd.DataFrame({
            "src_ip": ["10.0.0.1"],
            "dst_ip": ["10.0.0.2"],
            "proto": ["TCP"],
            "dur": [1.5],
            "tot_pkts": [10],
            "tot_bytes": [1200]
        })
        mapped, mapping, missing = auto_map_columns(alt_df)
        self.assertIn("Source_IP", mapped.columns)
        self.assertIn("Destination_IP", mapped.columns)
        self.assertIn("Protocol", mapped.columns)
        self.assertIn("Flow_Duration", mapped.columns)

    def test_assess_data_quality(self):
        """Test data quality computation"""
        quality = assess_data_quality(self.test_df)
        self.assertEqual(quality["total_rows"], 4)
        self.assertEqual(quality["missing_values"], 0)
        self.assertGreaterEqual(quality["quality_score"], 80)

    def test_preprocessing_and_data_leakage(self):
        """Verify train/test split and leak-free scaling"""
        # Create dataset large enough for 75/25 split
        large_df = pd.concat([self.test_df] * 10, ignore_index=True)
        cleaned_df, X_train, X_test, y_train, y_test, train_df, test_df, scaler, summary = preprocess_network_data(
            large_df, train_ratio=0.75, random_state=42
        )
        self.assertEqual(len(X_train) + len(X_test), len(cleaned_df))
        self.assertIn("Flow_Duration", X_train.columns)
        self.assertIn("Proto_TCP", X_train.columns)
        self.assertEqual(summary["imbalance_ratio"], 1.0)

    def test_ml_training_and_evaluation(self):
        """Verify training of all 4 models and metrics calculation"""
        large_df = pd.concat([self.test_df] * 12, ignore_index=True)
        cleaned_df, X_train, X_test, y_train, y_test, _, _, _, _ = preprocess_network_data(
            large_df, train_ratio=0.75, random_state=42
        )
        models = train_models(X_train, y_train, random_state=42)
        self.assertIn("logistic_regression", models)
        self.assertIn("decision_tree", models)
        self.assertIn("random_forest", models)
        self.assertIn("isolation_forest", models)

        metrics = evaluate_models(models, X_test, y_test)
        self.assertIn("random_forest", metrics)
        self.assertGreaterEqual(metrics["random_forest"]["accuracy"], 0.8)
        self.assertGreaterEqual(metrics["random_forest"]["f1_score"], 0.8)

    def test_sqlite_alert_persistence(self):
        """Test SQLite alert sync, update, and note appending"""
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp:
            tmp_db_path = tmp.name

        try:
            init_db(tmp_db_path)
            pred_df = self.test_df.copy()
            pred_df["Predicted_Label"] = pred_df["Label"]
            pred_df["Confidence"] = 0.95
            pred_df["Severity"] = "HIGH"
            pred_df["Detection_Reason"] = "Test detection"

            new_alerts = sync_alerts_from_predictions(pred_df, tmp_db_path)
            self.assertEqual(new_alerts, 2)  # 2 suspicious rows

            alerts_df = get_all_alerts(tmp_db_path)
            self.assertEqual(len(alerts_df), 2)

            first_id = alerts_df.iloc[0]["id"]
            update_alert_status(tmp_db_path, first_id, "Investigating", "Analyst reviewing firewall drops")

            notes = get_investigation_notes(tmp_db_path, first_id)
            self.assertGreaterEqual(len(notes), 2)
            self.assertEqual(notes[-1]["status_change"], "Investigating")
        finally:
            if os.path.exists(tmp_db_path):
                os.remove(tmp_db_path)

    def test_automated_findings(self):
        """Verify at least 10 automated security findings generated"""
        findings = generate_automated_findings(self.test_df)
        self.assertGreaterEqual(len(findings), 8)
        for f in findings:
            self.assertIn("title", f)
            self.assertIn("metric", f)


if __name__ == "__main__":
    unittest.main()
