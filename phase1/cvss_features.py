import json 
import os
import pandas as pd 
import numpy as np 
from dotenv import load_dotenv
from pathlib import Path 
from tqdm import tqdm


# Load env 
load_dotenv()

# Pull needed variables 
OUTPUT_DIR = Path(os.getenv("OUTPUT_DIR", "data"))



def build_cvss_feature(cve_path: str = "data/cve_nvd.json") -> pd.DataFrame:
    # Goal of the function is to go through the nvd cve_nvd file that we have and categorize it 

    ###########################
    # Helper things for later #
    ########################### 

    # Vector Map - Context: https://nvd.nist.gov/vuln-metrics/cvss
    cvss_vector_map = {
        "AV":  "attack_vector",       # N=Network, A=Adjacent, L=Local, P=Physical
        "AC":  "attack_complexity",   # L=Low, H=High
        "PR":  "privs_required",      # N=None, L=Low, H=High
        "UI":  "user_interaction",    # N=None, R=Required
        "S":   "scope",               # U=Unchanged, C=Changed
        "C":   "confidentiality",     # N=None, L=Low, H=High
        "I":   "integrity",           # N=None, L=Low, H=High
        "A":   "availability",        # N=None, L=Low, H=High
    }
    severity_order = {
        "LOW": 1,
        "MEDIUM": 2,
        "HIGH": 3,
        "CRITICAL": 4
    }

    # Helper parse function 
    def parse_vector(vect):
        # Goal is to parse a vector into workable values 

        # Check if valid first 
        if not vect or not isinstance(vect, str):
            return {}
        # Read through section, skip first instance (Don't needed CVSS Score at this point)
        parts = {}
        for seg in vect.split("/")[1:]:
            if ":" in seg:
                k, val = seg.split(":", 1)
                
                # Check if in vector map 
                if k in cvss_vector_map:
                    parts[cvss_vector_map[k]] = val 
        return parts 

    ##################
    # Function Start #
    ##################
    steps = [
        "Loading data",
        "Filtering nulls",
        "Building cvss_score",
        "Parsing vectors",
        "Encoding severity",
        "One-hot encoding",
        "Extracting time features",
        "Dropping columns",
    ]

    with tqdm(total=len(steps), desc="[Build_CVSS_Feature Features]", unit="step") as pbar:

        # Load the data 
        pbar.set_description(f"[Build_CVSS_Feature] {steps[0]}")
        cves = json.loads(Path(cve_path).read_text())
        if not cves:
            print(f"[Build_CVSS_Feature] Unable to load data from {cve_path}")
        df = pd.DataFrame(cves)
        pbar.update(1)

        # Basic filtering - No CVSS Scores
        pbar.set_description(f"[Build_CVSS_Feature] {steps[1]}")
        df = df[df["cvss_v3_score"].notna() | df["cvss_v2_score"].notna()].copy()
        pbar.update(1)

        # Assign missing v3 scores with the v2 score for simplicity 
        pbar.set_description(f"[Build_CVSS_Feature] {steps[2]}")
        df["cvss_score"] = df["cvss_v3_score"].fillna(df["cvss_v2_score"])
        pbar.update(1)

        # Parse through the data now with helper function
        pbar.set_description(f"[Build_CVSS_Feature] {steps[3]}") 
        vector_df = df["cvss_v3_vector"].apply(parse_vector).apply(pd.Series)
        df = pd.concat([df, vector_df], axis=1)
        pbar.update(1)

        # Assign Severity ratings (Context: Link above vector map)
        pbar.set_description(f"[Build_CVSS_Feature] {steps[4]}")
        df["severity_encoded"] = df["cvss_v3_severity"].map(severity_order).fillna(0)
        pbar.update(1)

        # Encode the Vector 
        pbar.set_description(f"[Build_CVSS_Feature] {steps[5]}")
        cat_cols = list(cvss_vector_map.values())
        df = pd.get_dummies(df, columns=[col for col in cat_cols if col in df.columns])
        pbar.update(1)

        # Pull out the time features 
        pbar.set_description(f"[Build_CVSS_Feature] {steps[6]}")
        df["published"] = pd.to_datetime(df["published"], errors="coerce")
        df["pub_year"] = df["published"].dt.year 
        df["pub_month"] = df["published"].dt.month
        df["days_since_pub"] = (pd.Timestamp.now() - df["published"]).dt.days
        pbar.update(1)

        # Drop unneeded 
        pbar.set_description(f"[Build_CVSS_Feature] {steps[7]}")  
        drop_cols = ["published", "lastModified", "description", "cvss_v3_vector", "cvss_v3_score", "cvss_v2_score", "cvss_v3_severity"]
        df = df.drop(columns=[col for col in drop_cols if col in df.columns])
        pbar.update(1)

        print(f"[Build_CVSS_Feature] Feature matrix: {df.shape}")
        print(f"[Build_CVSS_Feature] Columns: {list(df.columns)}")

    return df

if __name__ == "__main__":
    print(OUTPUT_DIR)
    df = build_cvss_feature()
    df.to_csv("data/cvss_features.csv", index=False)
    print(f"[Build_CVSS_Feature] Saved to {OUTPUT_DIR}/cvss_features.csv")