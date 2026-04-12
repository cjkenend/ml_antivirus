import json
import hashlib
import numpy as np
import pandas as pd
from pathlib import Path


VECTOR_LENGTH = 512     # Fixed value length of Vector. Not needed now but CNN will need it 


####################
# Helper Functions #
####################

def byte_encode_signture(content: bytes, length: int = VECTOR_LENGTH) -> np.array:
    # Goal is to Convert from raw byte to vector length 

    # Make the conversion 
    conv_arr =  np.frombuffer(content[:length], dtype=np.uint8).astype(np.float32)

    # Pad with 0s if not 512 
    if len(conv_arr) < length:
        conv_arr = np.pad(conv_arr, (0, length - len(conv_arr)))
    
    # Normalize [0,1] and return 
    return conv_arr / 255.0 

def extract_signature_meta(path: str, source: str, is_malware: int) -> dict:
    # Goal is to extract features from the metadata 

    # Get the file extension 
    extension = Path(path).suffix.lower()

    # Infer the OS Type. Basically just going for files that only exist on that OS 
    # NOTE: For the sake of simplistity BSD OS is going to be grouped into Linux
    os_type = "Unknown"
    if any(x in path.lower() for x in ["windows", "win32", "pe", ".exe", ".dll", ".bat"]):
        os_type = "windows"
    elif any(x in path.lower() for x in ["linux", "elf", ".sh", "unix"]):
        os_type = "linux"
    elif any(x in path.lower() for x in ["macos", "osx", ".dylib", "mac"]):
        os_type = "macos"

    # Do the same for malware types 
    malware_type = "unknown"
    malware_families = [
        "ransomware", 
        "trojan", 
        "worm", 
        "rootkit", 
        "spyware",
        "adware", 
        "backdoor", 
        "botnet", 
        "keylogger", 
        "dropper"
    ]

    # Loop through and check 
    for family in malware_families:
        if family in path.lower():
            # Found it 
            malware_type = family 
            break 

    # Now just return in JSON format 
    return {
        "path":         path,
        "source":       source,
        "extension":    extension,
        "os_type":      os_type,
        "malware_type": malware_type,
        "is_malware":   is_malware,   # label: 1 = malware, 0 = benign
        "path_depth":   len(Path(path).parts),
        "filename_len": len(Path(path).name),
    }

def build_signature_features() -> pd.DataFrame:
    # Goal is to put together all of the features of the data 

    records = [] 


    # Load the Malware data features (Add a check here and then API call if not found?)
    sources = [
        ("data/vsunderground_index.json", "vxunderground", 1),
        ("data/virussign_index.json",     "virussign",     1),
    ]

    # Loop through and call functions 
    for filepath, source, label in sources:

        # Check if exists
        if not Path(filepath).exists():
            print(f"[build_signature_features] Skipping {filepath} — not found")
            continue
        
        # Pull the entries 
        entries = json.loads(Path(filepath).read_text())
        for entry in entries:
            records.append(extract_signature_meta(entry["path"], source, label))
        print(f"[build_signature_features] Loaded {len(entries)} entries from {source}")

    # Save entries - Probably add a check here that it's not empty
    df = pd.DataFrame(records)

    # Encode it 
    df = pd.get_dummies(df, columns=["os_type", "malware_type", "extension", "source"])

    # Debug: Print Shape 
    print(f"[build_signature_features] Signature feature matrix: {df.shape}")
    return df


if __name__ == "__main__":
    #print(OUTPUT_DIR)
    df = build_signature_features()
    df.to_csv("data/signature_features.csv", index=False)
    print("[build_signature_features] Saved → data/signature_features.csv")