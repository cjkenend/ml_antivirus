# phase2/evaluate.py

# Imports
import os
import pandas as pd
import numpy as np
import joblib
from pathlib import Path
from dotenv import load_dotenv
from sklearn.metrics import (
    classification_report, f1_score,
    precision_score, recall_score,
    accuracy_score, confusion_matrix
)
from sklearn.model_selection import cross_val_score
from sklearn.preprocessing import StandardScaler

# Load env
load_dotenv()
OUTPUT_DIR = Path(os.getenv("OUTPUT_DIR", "data"))


def evaluate_all():
    print("[Eval] Loading splits...")
    X_train = pd.read_csv(OUTPUT_DIR / "X_train.csv")
    X_test  = pd.read_csv(OUTPUT_DIR / "X_test.csv")
    y_train = pd.read_csv(OUTPUT_DIR / "y_train.csv").squeeze()
    y_test  = pd.read_csv(OUTPUT_DIR / "y_test.csv").squeeze()

    X_full = pd.concat([X_train, X_test])
    y_full = pd.concat([y_train, y_test])

    # Load models
    rf     = joblib.load(OUTPUT_DIR / "rf_model.joblib")
    xgb    = joblib.load(OUTPUT_DIR / "xgb_model.joblib")
    svm    = joblib.load(OUTPUT_DIR / "svm_model.joblib")
    scaler = joblib.load(OUTPUT_DIR / "svm_scaler.joblib")

    X_test_scaled  = scaler.transform(X_test)
    X_full_scaled  = scaler.transform(X_full)

    results = []

    for name, model, X_t, X_f in [
        ("Random Forest", rf,  X_test,       X_full),
        ("XGBoost",       xgb, X_test,       X_full),
        ("SVM",           svm, X_test_scaled, X_full_scaled),
    ]:
        y_pred = model.predict(X_t)
        row = {
            "Model":     name,
            "Accuracy":  accuracy_score(y_test, y_pred),
            "Precision": precision_score(y_test, y_pred, zero_division=0),
            "Recall":    recall_score(y_test, y_pred, zero_division=0),
            "F1":        f1_score(y_test, y_pred, zero_division=0),
        }

        # k-fold
        kfold_f1 = cross_val_score(model, X_f, y_full, cv=5, scoring="f1", n_jobs=-1)
        row["KFold F1 Mean"] = kfold_f1.mean()
        row["KFold F1 Std"]  = kfold_f1.std()
        results.append(row)

    # Print comparison table
    results_df = pd.DataFrame(results).set_index("Model")
    print("\n[Eval] ── Baseline Model Comparison ──")
    print(results_df.to_string())

    # Save results
    results_df.to_csv(OUTPUT_DIR / "baseline_results.csv")
    print(f"\n[Eval] Results saved → {OUTPUT_DIR}/baseline_results.csv")
    return results_df


if __name__ == "__main__":
    evaluate_all()