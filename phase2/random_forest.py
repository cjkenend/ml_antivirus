import os
import pandas as pd
import numpy as np
import joblib
from pathlib import Path
from dotenv import load_dotenv
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, f1_score, confusion_matrix
from sklearn.model_selection import cross_val_score


# Load env
load_dotenv()
OUTPUT_DIR = Path(os.getenv("OUTPUT_DIR", "data"))


def train_rand_forest():
    # load splits
    print("[RF] Loading splits...")
    X_train = pd.read_csv(OUTPUT_DIR / "X_train.csv")
    X_test  = pd.read_csv(OUTPUT_DIR / "X_test.csv")
    y_train = pd.read_csv(OUTPUT_DIR / "y_train.csv").squeeze()
    y_test  = pd.read_csv(OUTPUT_DIR / "y_test.csv").squeeze()

    # Start Random Forest Training 
    print("[RF] Training Random Forest...")
    rf = RandomForestClassifier(
        n_estimators=100,
        random_state=42,
        n_jobs=-1,          
        class_weight="balanced"  #Make it balanced
    )
    rf.fit(X_train, y_train)

    # Evaluating 
    y_pred = rf.predict(X_test)
    print("\n[RF] Classification Report:")
    print(classification_report(y_test, y_pred))
    print(f"[RF] Confusion Matrix:\n{confusion_matrix(y_test, y_pred)}")

    # K-Fold evaluation 
    print("\n[RF] Running 5-fold Cross Validation...")
    X_full = pd.concat([X_train, X_test])
    y_full = pd.concat([y_train, y_test])

    # Display metrics 
    for metric in ["f1", "precision", "recall", "accuracy"]:
        scores = cross_val_score(rf, X_full, y_full, cv=5, scoring=metric, n_jobs=-1)
        print(f"[RF] {metric:10s}: {scores.mean():.4f} ± {scores.std():.4f}")
    
    # Save 
    model_path = OUTPUT_DIR / "rf_model.joblib"
    joblib.dump(rf, model_path)
    print(f"\n[RF] Model saved → {model_path}")
    return rf

if __name__ == "__main__":
    train_rand_forest()