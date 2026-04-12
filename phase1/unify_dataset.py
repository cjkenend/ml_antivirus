import pandas as pd 
from pathlib import Path
from sklearn.preprocessing import StandardScaler 


def unify_dataset():
    # Import data
    cvss = pd.read_csv("data/cvss_features.csv")
    sigs = pd.read_csv("data/signature_features.csv")

    # Current shape of data 
    print(f"[Unify Data] CVSS Shape: {cvss.shape}")
    print(f"[Unify Data] Signature Shape: {sigs.shape}")

    # Align datasets and combine
    cvss, sigs = cvss.align(sigs, join="outer", axis=1, fill_value=0)
    combined = pd.concat([ cvss, sigs], ignore_index=True)

    # Scale numeric columns (Exclude malware label)
    num_cols = combined.select_dtypes(include="number").columns.tolist()
    if "is_malware" in num_cols:
        num_cols.remove("is_malware")
    
    scaler = StandardScaler()
    combined[num_cols] = scaler.fit_transform(combined[num_cols])

    combined.to_csv("data/unified_dataset.csv", index=False)
    print(f"[Unify Data] Unified dataset: {combined.shape}")
    print(f"[Unify Data] Saved → data/unified_dataset.csv")
    return combined


if __name__ == "__main__":
    unify_dataset()
