import os
import pandas as pd
import numpy as np
from pathlib import Path
from dotenv import load_dotenv
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
import joblib

# Load env
load_dotenv()
OUTPUT_DIR = Path(os.getenv("OUTPUT_DIR", "data"))


# Trains the data and saves it for the other functions to call 
def train_data(dataset_path: str = "data/unified_dataset.csv"):
    print("[Train Data] Loading unified dataset...")
    df = pd.read_csv(dataset_path)

    # Print shape of data 
    print(f"[Train Data] Dataset shape: {df.shape}")
    print(f"[Train Data] Label distribution:\n{df['is_malware'].value_counts()}")

    # Seperate features 
    X = df.drop(columns=["is_malware"])
    y = df["is_malware"]

    # Drop the non numeric results 
    non_numeric = X.select_dtypes(exclude="number").columns.tolist()
    if non_numeric:
        print(f"[Train Data] Dropping non-numeric columns: {non_numeric}")
        X = X.drop(columns=non_numeric)

    # Make the training/Test split 
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    print(f"[Train Data] Train size: {X_train.shape}, Test size: {X_test.shape}")

    # Save results 
    X_train.to_csv(OUTPUT_DIR / "X_train.csv", index=False)
    X_test.to_csv(OUTPUT_DIR  / "X_test.csv",  index=False)
    y_train.to_csv(OUTPUT_DIR / "y_train.csv", index=False)
    y_test.to_csv(OUTPUT_DIR  / "y_test.csv",  index=False)

    print(f"[Train Data] Saved splits → {OUTPUT_DIR}")
    return X_train, X_test, y_train, y_test

if __name__ == "__main__":
    train_data()