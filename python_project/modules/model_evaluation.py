"""
Model Performance Evaluation Module for NETGUARD AI
Calculates real test-set accuracy, precision, recall, F1, confusion matrices, FPR, and FNR.
"""

import pandas as pd
import numpy as np
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix


def evaluate_models(models: dict, X_test: pd.DataFrame, y_test: pd.Series) -> dict:
    """
    Evaluates all trained models on the test set.
    """
    evaluation_results = {}

    for name, model in models.items():
        if name == "isolation_forest":
            # For isolation forest, map -1 -> 1 (SUSPICIOUS) and 1 -> 0 (NORMAL)
            raw_pred = model.predict(X_test)
            y_pred = np.array([1 if p == -1 else 0 for p in raw_pred])
        else:
            y_pred = model.predict(X_test)

        acc = float(accuracy_score(y_test, y_pred))
        prec = float(precision_score(y_test, y_pred, zero_division=0))
        rec = float(recall_score(y_test, y_pred, zero_division=0))
        f1 = float(f1_score(y_test, y_pred, zero_division=0))

        # Confusion Matrix [TN, FP, FN, TP]
        cm = confusion_matrix(y_test, y_pred, labels=[0, 1])
        tn, fp, fn, tp = cm.ravel() if cm.size == 4 else (0, 0, 0, 0)

        fpr = float(fp / max(fp + tn, 1))
        fnr = float(fn / max(fn + tp, 1))

        feat_importances = []
        if hasattr(model, "feature_importances_"):
            for col, imp in zip(X_test.columns, model.feature_importances_):
                feat_importances.append({"feature": col, "importance": round(float(imp), 4)})
            feat_importances.sort(key=lambda x: x["importance"], reverse=True)

        evaluation_results[name] = {
            "name": name.replace("_", " ").title(),
            "accuracy": round(acc, 4),
            "precision": round(prec, 4),
            "recall": round(rec, 4),
            "f1_score": round(f1, 4),
            "false_positive_rate": round(fpr, 4),
            "false_negative_rate": round(fnr, 4),
            "confusion_matrix": {
                "tp": int(tp),
                "tn": int(tn),
                "fp": int(fp),
                "fn": int(fn)
            },
            "feature_importances": feat_importances
        }

    return evaluation_results
