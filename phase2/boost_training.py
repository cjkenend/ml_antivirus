import os
import pandas as pd
import numpy as np
import joblib
from pathlib import Path
from dotenv import load_dotenv
from xgboost import XGBClassifier
from sklearn.metrics import classification_report, f1_score, confusion_matrix
from sklearn.model_selection import cross_val_score

# Load env
load_dotenv()
OUTPUT_DIR = Path(os.getenv("OUTPUT_DIR", "data"))


def train_xgboost():
    # Load data
    print("[XGB] Loading splits...")
    X_train = pd.read_csv(OUTPUT_DIR / "X_train.csv")
    X_test  = pd.read_csv(OUTPUT_DIR / "X_test.csv")
    y_train = pd.read_csv(OUTPUT_DIR / "y_train.csv").squeeze()
    y_test  = pd.read_csv(OUTPUT_DIR / "y_test.csv").squeeze()

    # Fix imbalances
    scale = (y_train == 0).sum() / (y_train == 1).sum()

    # Start training
    print("[XGB] Training XGBoost")
    xgb = XGBClassifier(
        n_estimators=100,
        random_state=42,
        scale_pos_weight=scale,  
        eval_metric="logloss",
        n_jobs=-1
    )
    xgb.fit(X_train, y_train)

    # Evaluate
    y_pred = xgb.predict(X_test)
    print("\n[XGB] Classification Report:")
    print(classification_report(y_test, y_pred))
    print(f"[XGB] Confusion Matrix:\n{confusion_matrix(y_test, y_pred)}")

    # K-fold cross validation
    print("\n[XGB] Running 5-fold Cross Validation")
    X_full = pd.concat([X_train, X_test])
    y_full = pd.concat([y_train, y_test])

    for metric in ["f1", "precision", "recall", "accuracy"]:
        scores = cross_val_score(xgb, X_full, y_full, cv=5, scoring=metric, n_jobs=-1)
        print(f"[XGB] {metric:10s}: {scores.mean():.4f} ± {scores.std():.4f}")

    # Save model
    model_path = OUTPUT_DIR / "xgb_model.joblib"
    joblib.dump(xgb, model_path)
    print(f"\n[XGB] Model saved → {model_path}")
    return xgb


if __name__ == "__main__":
    train_xgboost()