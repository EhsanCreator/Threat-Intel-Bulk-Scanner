import requests
import pandas as pd
import math
import concurrent.futures
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import urllib3
from dateutil import parser


urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# --- API ---
OPENTIP_API_KEY = "YOUR_KASPERSKY_KEY_HERE"
HA_API_KEY = "YOUR_HYBRID_ANALYSIS_KEY_HERE"

# --- input ---
EXCEL_FILE_PATH = "YOUR_FILE_HERE"
MD5_COLUMN_NAME = "MD5_COLUMN"
MAX_WORKERS = 4 

def format_size(size_bytes):
    if not size_bytes or size_bytes == 0: return "0 B"
    size_name = ("B", "KB", "MB", "GB", "TB")
    i = int(math.floor(math.log(size_bytes, 1024)))
    p = math.pow(1024, i)
    s = round(size_bytes / p, 2)
    return f"{s} {size_name[i]}"

def format_ha_timestamp(ts_string):
    if not ts_string: return "N/A"
    try:
        dt = parser.parse(ts_string)
        return dt.strftime('%Y-%m-%d %H:%M') # مثلا: 2025-11-26 20:24
    except:
        return ts_string.replace("T", " ").split("+")[0].split(".")[0]

def create_session():
    session = requests.Session()
    retries = Retry(total=3, backoff_factor=1, status_forcelist=[500, 502, 503, 504])
    adapter = HTTPAdapter(max_retries=retries)
    session.mount('https://', adapter)
    session.headers.update({
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
        "Accept": "application/json",
        "Connection": "keep-alive"
    })
    return session

# ---------------- KASPERSKY OPENTIP ----------------
def check_opentip(session, file_hash):
    url = f"https://opentip.kaspersky.com/api/v1/search/hash?request={file_hash}"
    headers = {"x-api-key": OPENTIP_API_KEY}
    
    try:
        response = session.get(url, headers=headers, timeout=15, verify=False)
        if response.status_code == 200:
            data = response.json()
            zone = data.get("Zone", "Unknown")
            status_map = {"Green": "Clean", "Red": "Malicious", "Yellow": "Suspicious", "Orange": "Adware/Riskware"}
            kt_status = status_map.get(zone, zone)
            
            general_info = data.get("FileGeneralInfo", {})
            kt_format = general_info.get("Type", "N/A")
            kt_size = format_size(general_info.get("Size", 0))
            sha256 = general_info.get("Sha256", None)
            
            detections = data.get("DetectionsInfo", [])
            det_names = ", ".join([d.get("DetectionName", "") for d in detections]) if detections else "Clean"
            
            return {
                "kt_status": kt_status,
                "kt_format": kt_format,
                "kt_size": kt_size,
                "kt_detections": det_names,
                "derived_sha256": sha256
            }
        elif response.status_code == 404:
            return {"kt_status": "Not Found", "kt_format": "N/A", "kt_size": "N/A", "kt_detections": "N/A", "derived_sha256": None}
        else:
            return {"kt_status": f"Err {response.status_code}", "kt_format": "-", "kt_size": "-", "kt_detections": "-", "derived_sha256": None}
    except Exception:
        return {"kt_status": "Net Error", "kt_format": "-", "kt_size": "-", "kt_detections": "-", "derived_sha256": None}

# ---------------- HYBRID ANALYSIS (IMPROVED) ----------------
def check_hybrid_analysis(session, sha256_hash):
    if not sha256_hash:
        return {"ha_timestamp": "-", "ha_input": "-", "ha_verdict": "Skipped", "ha_tags": "-"}

    url = f"https://hybrid-analysis.com/api/v2/overview/{sha256_hash}"
    headers = {"api-key": HA_API_KEY}
    
    try:
        response = session.get(url, headers=headers, timeout=20, verify=False)
        
        if response.status_code == 200:
            report = response.json()
            
            timestamp = format_ha_timestamp(report.get("analysis_start_time"))
            
            filename = report.get("submit_name")
            filetype = report.get("type", "Unknown")
            if filename and filename != "N/A":
                ha_input_str = f"{filename}"
            else:
Executable
                ha_input_str = filetype.split(",")[0] 

            raw_verdict = report.get("verdict", "unknown")
            if raw_verdict == "no specific threat":
                verdict = "Clean"
            elif raw_verdict == "malicious":
                verdict = "Malicious"
            else:
                verdict = raw_verdict.title()

            tags_set = set()
            
            if report.get("vx_family"): tags_set.add(f"#{report.get('vx_family')}")
            
            for tag in report.get("classification_tags", []):
                tags_set.add(f"#{tag}")
                
            for sig in report.get("signatures", []):
                name = sig.get("name") if isinstance(sig, dict) else str(sig)
                if name: tags_set.add(f"#{name.replace(' ', '_')}")
            
            for attack in report.get("mitre_attcks", []):
                 t_id = attack.get("attck_id")
                 if t_id: tags_set.add(f"#{t_id}")

            if tags_set:
                ha_tags_str = ", ".join(list(tags_set)[:10])
            else:
                ha_tags_str = "No Indicators" if verdict == "Clean" else "-"

            return {
                "ha_timestamp": timestamp,
                "ha_input": ha_input_str,
                "ha_verdict": verdict,
                "ha_tags": ha_tags_str
            }
        
        elif response.status_code == 404:
             return {"ha_timestamp": "Not Found", "ha_input": "-", "ha_verdict": "Not Found", "ha_tags": "-"}
        else:
            return {"ha_timestamp": f"Err {response.status_code}", "ha_input": "-", "ha_verdict": "Err", "ha_tags": "-"}
            
    except Exception:
        return {"ha_timestamp": "Net Error", "ha_input": "-", "ha_verdict": "Conn Error", "ha_tags": "-"}


# --- PROCESSOR ---
def process_single_row(row_data):
    md5_hash = str(row_data['hash']).strip()
    index = row_data['index']
    
    if len(md5_hash) != 32:
        return {"index": index, "kt_status": "Invalid", "ha_verdict": "Invalid"}

    session = create_session()

    kt_res = check_opentip(session, md5_hash)
    sha256 = kt_res.pop("derived_sha256", None)
    
    ha_res = check_hybrid_analysis(session, sha256)
    
    combined = {**kt_res, **ha_res}
    combined['index'] = index
    
    print(f"[{index}] {md5_hash} -> KT: {kt_res.get('kt_status')} | HA: {ha_res.get('ha_verdict')}")
    
    session.close()
    return combined

# --- MAIN ---
if __name__ == "__main__":
    print(f"[*] Reading data from '{EXCEL_FILE_PATH}'...")
    try:
        df = pd.read_excel(EXCEL_FILE_PATH)
    except FileNotFoundError:
        print(f"[!] Error: File not found.")
        exit()

    if MD5_COLUMN_NAME not in df.columns:
        print(f"[!] Error: Column '{MD5_COLUMN_NAME}' missing.")
        exit()

    tasks = []
    for index, row in df.iterrows():
        tasks.append({'hash': row[MD5_COLUMN_NAME], 'index': index})

    print(f"[*] Starting Scan with {MAX_WORKERS} threads...")

    results_list = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_to_hash = {executor.submit(process_single_row, task): task for task in tasks}
        for future in concurrent.futures.as_completed(future_to_hash):
            try:
                results_list.append(future.result())
            except Exception as exc:
                print(f"[!] Thread Exception: {exc}")

    print("\n[*] Saving results...")
    results_list.sort(key=lambda x: x['index'])
    for res in results_list: del res['index']

    results_df = pd.DataFrame(results_list)
    df = pd.concat([df, results_df], axis=1)

    df.to_excel(EXCEL_FILE_PATH, index=False)
    print(f"\n[SUCCESS] Updated '{EXCEL_FILE_PATH}'.")