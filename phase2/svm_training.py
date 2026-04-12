# phase2/svm_model.py

# Imports
import os
import pandas as pd
import numpy as np
import joblib
from pathlib import Path
from dotenv import load_dotenv
from sklearn.svm import SVC
from sklearn.metrics import classification_report, f1_score, confusion_matrix
from sklearn.model_selection import cross_val_score
from sklearn.preprocessing import StandardScaler

# Load env
load_dotenv()
OUTPUT_DIR = Path(os.getenv("OUTPUT_DIR", "data"))


def train_svm():
    print("[SVM] Loading splits")
    X_train = pd.read_csv(OUTPUT_DIR / "X_train.csv")
    X_test  = pd.read_csv(OUTPUT_DIR / "X_test.csv")
    y_train = pd.read_csv(OUTPUT_DIR / "y_train.csv").squeeze()
    y_test  = pd.read_csv(OUTPUT_DIR / "y_test.csv").squeeze()

    # SVM requires scale
    print("[SVM] Scaling features")
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled  = scaler.transform(X_test)

    print("[SVM] Training SVM")
    svm = SVC(
        kernel="rbf",
        random_state=42,
        class_weight="balanced",  # handles imbalanced malware/benign ratio
        probability=True          # needed for some evaluation metrics
    )
    svm.fit(X_train_scaled, y_train)

    # Evaluate
    y_pred = svm.predict(X_test_scaled)
    print("\n[SVM] Classification Report:")
    print(classification_report(y_test, y_pred))
    print(f"[SVM] Confusion Matrix:\n{confusion_matrix(y_test, y_pred)}")

    # k-fold cross validation
    print("\n[SVM] Running 5-fold Cross Validation")
    X_full = pd.concat([X_train, X_test])
    y_full = pd.concat([y_train, y_test])
    X_full_scaled = scaler.fit_transform(X_full)

    for metric in ["f1", "precision", "recall", "accuracy"]:
        scores = cross_val_score(svm, X_full_scaled, y_full, cv=5, scoring=metric, n_jobs=-1)
        print(f"[SVM] {metric:10s}: {scores.mean():.4f} ± {scores.std():.4f}")

    # Save model and scaler
    joblib.dump(svm,    OUTPUT_DIR / "svm_model.joblib")
    joblib.dump(scaler, OUTPUT_DIR / "svm_scaler.joblib")
    print(f"\n[SVM] Model saved → {OUTPUT_DIR}/svm_model.joblib")
    return svm


if __name__ == "__main__":
    train_svm()