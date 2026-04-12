# Goal of this script is to handle all of the data collection for the project from the various links
#


# Imports
import os 
import time
import json
import requests         # Needed for APIs
import subprocess       # Needed for cvd -> json 
import re               # Needed for CVE Details
from pathlib import Path 
from dotenv import load_dotenv
from urllib.parse import urlencode  # Needed for specific NIST URL making 
from datetime import datetime, timedelta




# Load Env
load_dotenv()


# Assign variables 
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN", "")
NVD_API_KEY = os.getenv("NVD_API_KEY", "")
OUTPUT_DIR = Path(os.getenv("OUTPUT_DIR", "data"))

VX_LIMIT = int(os.getenv("VX_LIMIT", 200))
VS_LIMIT = int(os.getenv("VS_LIMIT", 200))

CVE_PAGES = int(os.getenv("CVE_PAGES", 5))
CVE_RES_PER_PAGE = int(os.getenv("CVE_RES_PER_PAGE", 200))
CVE_DETAILS_YEAR = int(os.getenv("CVE_DETAILS_YEAR", 2024))

CVE_START_DATE = os.getenv("CVE_START_DATE", "2020-01-01")
CVE_END_DATE = os.getenv("CVE_END_DATE", "2024-01-01")





# Make sure the output dir exits 
OUTPUT_DIR.mkdir(exist_ok=True)


# Set Headers with the tokens if you have them 
HEADERS_GN = {"Authorization": f"token {GITHUB_TOKEN}"} if GITHUB_TOKEN else {}
HEADERS_NVD = {"apiKey": NVD_API_KEY} if NVD_API_KEY else {}

#########################################
# GitHub Caller functions for API Pulls #
#########################################
def fetch_github_files(owner: str, repo: str, branch: str = "main") -> list[dict]:
    
    # Make URL and fetch file list
    url = f"https://api.github.com/repos/{owner}/{repo}/git/trees/{branch}?recursive=1"
    resp = requests.get(url, headers=HEADERS_GN)

    # Pull the status
    resp.raise_for_status()

    # Return the list looking for blob items 
    return [ item for item in resp.json().get("tree", []) if item["type"] == "blob"]

def download_github_files(ower: str, repo: str, branch: str = "main") -> bytes | None:

    # Make URL and fetch files
    url = f"https://raw.githubusercontent.com/{owner}/{repo}/master/{path}"
    resp = requests.get(url, headers=HEADERS_GN)

    # Check status and return if 200 
    return resp.content if resp.status == 200 else None 

#########################
# Data Format Functions #
#########################
def unpack_cvd(cvd_path: Path) -> Path | None:
    # Configure output dir and make it
    out_dir = cvd_path.parent / cvd_path.stem
    out_dir.mkdir(exist_ok=True) 

    abs_cvd = cvd_path.resolve()

    print(f"Unpacking {cvd_path.name} into {out_dir}")
    results = subprocess.run(
        ["sigtool", "--unpack", str(abs_cvd)],
        cwd=str(out_dir),
        capture_output=True,
        text=True
    )
    if results.returncode == 0:
        print(f"Unpacked successfully")
        return out_dir
    else:
        print(f"sigtool error: {results.stderr}")
        return None

#############
# API Calls #
#############

# Working 
def collect_vxunderground() -> list[dict]:
    print("[VXUnderground] Collection File Tree")

    # Pull files and convert to JSON 
    files = fetch_github_files("vxunderground", "MalwareSourceCode")

    records = [
        {
            "source": "vxunderground",
            "path": f["path"],
            "size": f.get("size", 0),
            "sha": f["sha"],
            "url": f"https://github.com/vxunderground/MalwareSourceCode/blob/master/{['path']}"
        } for f in files[:VX_LIMIT]
    ]
    # Save file
    out = OUTPUT_DIR / "vsunderground_index.json"
    out.write_text(json.dumps(records, indent=2))
    print(f"[vxunderground] Saved {len(records)} records → {out}")
    return records

# Working
def collect_clamav_signatures() -> dict:
    print("Collecting ClamAV Signatures")

    # Set url then pull the various API gateways 
    results = {}
    base = "https://database.clamav.net"

    # Set Headers
    clam_headers = {
        "User-Agent": "ClamAV/1.0.0 (OS: linux-gnu; ARCH: x86_64; CPU: x86_64)"
    }

    # Loop through gateways 
    for name, filename in {"main": "main.cvd", "daily": "daily.cvd"}.items():
        resp = requests.get(f"{base}/{filename}", headers=clam_headers, stream=True)
        print(f"Trying: {base}/{filename}")
        # Check code and proced depending on code 
        if resp.status_code == 200:
            # Valid go write data 
            dest = OUTPUT_DIR / filename 
            with open(dest,"wb") as file:
                # Write chunk by chunk now of file 
                for chunk in resp.iter_content(chunk_size=8192):
                    file.write(chunk)
            print(f"[ClamAV] {filename} saved ({dest.stat().st_size / 1e6:.1f} MB)")

            # Unpack the binary now 
            unpacked_dir = unpack_cvd(dest)
            results[name] = {
                "cvd":      str(dest),
                "unpacked": str(unpacked_dir) if unpacked_dir else None
            }
            downloaded = True
            break
        else: 
            print(f"[ClamAV] Failed to Fetch {filename}: {resp.status_code}")
    return results 

# Working
def collect_virussign() -> list[dict]:
    print("[VirusSign] Fetching file tree")

    # Set url and pull the files 
    files = fetch_github_files("VirusSign", "malware-samples")
    records = [
        {
            "source": "virussign",
            "path": f["path"],
            "size": f.get("size", 0),
            "sha": f["sha"],
            "url": f"https://github.com/VirusSign/malware-samples/blob/master/{f['path']}"
        }
        for f in files[:VS_LIMIT]
    ]

    # Save to output 
    out = OUTPUT_DIR / "virussign_index.json"
    out.write_text(json.dumps(records, indent=2))
    print(f"[VirusSign] Saved {len(records)} records → {out}")
    return records

# Working 
def collect_cvd_nist() -> list[dict] | None: 
    print("[NIST] Fetching file tree")

    # Set URL 
    base = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    all_cves = []

    # Approved NIST Header 
    nist_headers = {**HEADERS_NVD, "User-Agent": "curl/8.5.0"}

    # NIST requirement -> API Calls with a time frame have 120 days only... Breaking up into chunks 
    start = datetime.strptime(CVE_START_DATE, "%Y-%m-%d")
    end = datetime.strptime(CVE_END_DATE,   "%Y-%m-%d")
    delta = timedelta(days=119)

    chunks = []
    current = start 
    while current < end:
        chunk_end = min(current + delta, end)
        chunks.append((current, chunk_end))
        current = chunk_end + timedelta(days=1)

    # Loop through request chunks 
    for chunk_start, chunk_end in chunks:
        # Make the start and end dates 
        start_str = chunk_start.strftime("%Y-%m-%dT00:00:00.000")
        end_str   = chunk_end.strftime("%Y-%m-%dT23:59:59.999")
        page      = 0

        # Now loop through pages 
        while page < CVE_PAGES:
            # Set the parameters and make a request 
            url = (
                f"{base}"
                f"?pubStartDate={start_str}"
                f"&pubEndDate={end_str}"
                f"&resultsPerPage={CVE_RES_PER_PAGE}"
                f"&startIndex={page * CVE_RES_PER_PAGE}"
            )
            resp = requests.get(url, headers=nist_headers)

            # Debug
            print(f"[NIST] Actual URL: {resp.url}")
            print(f"[NIST] Status: {resp.status_code}")
            print(f"[NIST] HEADERS_NVD value: {HEADERS_NVD}")

            # Check if limit was hit 
            if resp.status_code == 429:
                print(f"[NIST] Rate limited — waiting 30 seconds...")
                time.sleep(30)
                resp = requests.get(url, headers=nist_headers)

            # Check status and pull data 
            if resp.status_code != 200:
                print(f"[NIST] API Failed with code: {resp.status_code}")
                return None 
            
            # Pull data
            data = resp.json()
            vulns = data.get("vulnerabilities", [])
            total = data.get("totalResults", 0)
            
            for item in vulns:
                # Check formatting with first vuns 
                if vulns and len(all_cves) == 0:
                    first = vulns[0]
                    cve_sample = first.get("cve", {})
                    print(f"[NIST] Sample keys in item: {list(first.keys())}")
                    print(f"[NIST] Sample keys in cve: {list(cve_sample.keys())}")
                    print(f"[NIST] Sample metrics: {cve_sample.get('metrics', 'NOT FOUND')}")

                # Pull data from the item and put into JSON format 
                cve = item.get("cve", {})
                metrics = cve.get("metrics", {})
                cvss_v3 = metrics.get("cvssMetricV31", [{}])[0].get("cvssData", {})
                cvss_v2 = metrics.get("cvssMetricV2",  [{}])[0].get("cvssData", {})


                all_cves.append({
                    "id":               cve.get("id"),
                    "published":        cve.get("published"),
                    "lastModified":     cve.get("lastModified"),
                    "description":      next((d["value"] for d in cve.get("descriptions", []) if d["lang"] == "en"), ""),
                    "cvss_v3_score":    cvss_v3.get("baseScore"),
                    "cvss_v3_severity": cvss_v3.get("baseSeverity"),
                    "cvss_v3_vector":   cvss_v3.get("vectorString"),
                    "cvss_v2_score":    cvss_v2.get("baseScore"),
                })
            
            # Check amount fetched and if we need to do another fetch depending on CVE_PAGES
            fetched = (page * CVE_RES_PER_PAGE) + len(vulns)
            print(f"[NIST] {start_str[:10]} to {end_str[:10]} | {fetched}/{total}")

            if fetched >= total or not vulns:
                break

            # Need to add a delay also if no API key to meet up with the robots.txt time
            page += 1
            time.sleep(8.0 if not NVD_API_KEY else 0.6)
        
    # Save results now 
    out = OUTPUT_DIR / "cve_nvd.json"
    out.write_text(json.dumps(all_cves, indent=2))
    print(f"[CVE/NVD] Saved {len(all_cves)} CVEs → {out}")
    return all_cves

def collect_benign_repos(benign_limit: int = 10000) -> list[dict]:
    # Collect the random benging repos I was able to come across of various sources 
    print("[Benign] Fetching benign source code file trees")

    # Well known repos 
    benign_repos = [
        ("torvalds",    "linux",        "master"),
        ("python",      "cpython",      "main"),
        ("curl",        "curl",         "master"),
        ("nginx",       "nginx",        "master"),
        ("git",         "git",          "master"),
        ("redis",       "redis",        "unstable"),
        ("postgres",    "postgres",     "master"),
        ("sqlite",      "sqlite",       "master"),
        ("openssl",     "openssl",      "master"),
        ("apache",      "httpd",        "trunk"),
        ("microsoft", "vscode",        "main"),    
        ("facebook",  "react",         "main"),     
        ("golang",    "go",            "master"),
        ("rust-lang", "rust",          "master"),   
        ("kubernetes","kubernetes",    "master"),  
        ("nodejs",    "node",          "main")
    ]

    all_records = []

    # Loop through and pull 
    for owner, repo, branch in benign_repos:
        try:
            print(f"[Benign] Fetching {owner}/{repo}")

            # Fetch and go through limit 
            files = fetch_github_files(owner, repo, branch=branch)
            for f in files[:benign_limit]:
                all_records.append({
                    "source":   "benign_github",
                    "repo":     f"{owner}/{repo}",
                    "path":     f["path"],
                    "size":     f.get("size",0),
                    "sha":      f["sha"],
                    "is_malware":   0,
                    "url":      f"https://github.com/{owner}/{repo}/blob/{branch}/{f['path']}"
                })
            
            print(f"[Benign] {owner}/{repo} — {min(len(files), benign_limit)} files indexed")

            # Sleep to not get blocked
            time.sleep(1.0)
        
        except Exception as e:
            print(f"[Benign] Failed {owner}/{repo}: {e}")
            continue
    
    # Save 
    out = OUTPUT_DIR / "benign_github_index.json"
    out.write_text(json.dumps(all_records, indent=2))
    print(f"[Benign] Saved {len(all_records)} benign records → {out}")
    return all_records

# Collect sorel_benign (industry standard) not really needed
# def collect_sorel_benign() -> list[dict]:
#     # Industry standard benign malware to test on 
#     print("[SOREL] Fetching SOREL-20M benign file index")

#     # Repos to pull  
#     sorel_repos = [
#         ("sophos-ai", "SOREL-20M", "main")
#     ]

#     all_records = []

#     # Fetch files 
#     for owner, repo, branch in sorel_repos: 
#         # Pull files 
#         files = fetch_github_files(owner, repo, branch=branch)
        
#         # Filter to just metadata/index files, not the actual binaries
#         meta_files = [f for f in files if f["path"].endswith((".json", ".csv", ".tsv", ".txt"))]
        
#         # Loop through and format data
#         for f in meta_files:
#             all_records.append({
#                 "source":     "sorel20m",
#                 "path":       f["path"],
#                 "size":       f.get("size", 0),
#                 "sha":        f["sha"],
#                 "is_malware": 0,
#                 "url":        f"https://github.com/{owner}/{repo}/blob/{branch}/{f['path']}"
#             })
#         print(f"[SOREL] Indexed {len(all_records)} metadata files")
    
#     # Save files
#     out = OUTPUT_DIR / "sorel_benign_index.json"
#     out.write_text(json.dumps(all_records, indent=2))
#     print(f"[SOREL] Saved {len(all_records)} records → {out}")
#     return all_records


# Ended up not working, NISt should be enough but if more input data is needed then swap over to NIST
# def collect_cvedetails() -> list[dict]:
#     print(f"[CVEDetails] Scraping {CVE_DETAILS_YEAR} summary...")

#     # Build URL and make the request 
#     url = f"https://www.cvedetails.com/browse-by-date.php?do=viewdate&date={CVE_DETAILS_YEAR}"

#     # Make headers 
#     cve_headers = {
#         "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
#         "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
#         "Accept-Language": "en-US,en;q=0.5",
#         "Accept-Encoding": "gzip, deflate, br",
#         "Connection": "keep-alive",
#     }

#     resp = requests.get(url, headers=cve_headers)
#     print(f"[CVEDetails] Status: {resp.status_code}")
#     print(f"[CVEDetails] Response preview: {resp.text[:500]}")

#     # Pull the cve ids and format to json 
#     cve_ids = list(dict.fromkeys(re.findall(r'CVE-\d{4}-\d+', resp.text)))
#     records = [
#         {
#             "id": cid, "year": CVE_DETAILS_YEAR, "source": "cvedetails"
#         } for cid in cve_ids
#     ]

#     # Save 
#     out = OUTPUT_DIR / f"cvedetails_{CVE_DETAILS_YEAR}.json"
#     out.write_text(json.dumps(records, indent=2))

#     return records 

# Main function 
if __name__ == "__main__":
    print("Starting Data Collection")

    # Call the data functions 
        # VXUnderground
    vx_data = collect_vxunderground()
    #print(vx_data)

        # ClamAV 
    #clam_data = collect_clamav_signatures()
    #print(clam_data)
    

        # VirusSign
    vs_data = collect_virussign()
    #print(vs_data)

        # NIST
    #nist_data = collect_cvd_nist()
    #print(nist_data)

        # CVE Details 
    #cve_details = collect_cvedetails()
    #print(cve_details)


    ########### Bengin Data ############
    github_bengin = collect_benign_repos()
    #print(github_bengin)

    # Sorel data 
    sorel_benign = collect_sorel_benign()
    #print(sorel_benign)