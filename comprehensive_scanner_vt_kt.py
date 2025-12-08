import requests
import pandas as pd
import time
import datetime
import json

# ---  API ---
VT_API_KEY = "YOUR_VIRUSTOTAL_KEY_HERE"
OPENTIP_API_KEY = "YOUR_KASPERSKY_KEY_HERE"

# --- input ---
EXCEL_FILE_PATH = "YOUR_FILE_HERE"
MD5_COLUMN_NAME = "MD5_COLUMN"

def format_size(size_bytes):
    if not size_bytes or size_bytes == 0: return "0 B"
    import math
    size_name = ("B", "KB", "MB", "GB", "TB")
    i = int(math.floor(math.log(size_bytes, 1024)))
    p = math.pow(1024, i)
    s = round(size_bytes / p, 2)
    return f"{s} {size_name[i]}"

def format_timestamp(ts):
    if not ts: return "N/A"
    return datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')

def check_virustotal(api_key, file_hash):
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"x-apikey": api_key}
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            result = response.json().get("data", {}).get("attributes", {})
            stats = result.get("last_analysis_stats", {})
            positives = stats.get("malicious", 0) + stats.get("suspicious", 0)
            total = sum(stats.values())
            file_name = result.get("meaningful_name", result.get("names", ["N/A"])[0])
            file_size = format_size(result.get("size", 0))
            last_analysis_date = format_timestamp(result.get("last_analysis_date"))
            signature_info = "Signed" if result.get("signature_info") else "Not Signed"
            return {
                "vt_detections": f"{positives}/{total}", 
                "vt_file_name": file_name,
                "vt_file_size": file_size, 
                "vt_is_signed": signature_info,
                "vt_last_analysis": last_analysis_date, 
                "vt_status": "OK"
            }
        elif response.status_code == 404:
            return {"vt_status": "Not Found"}
        elif response.status_code == 403:
            return {"vt_status": "Error 403: Forbidden"}
        else:
            return {"vt_status": f"Error: {response.status_code}"}
    except requests.exceptions.RequestException as e:
        return {"vt_status": f"Network Error: {e}"}

def check_opentip(api_key, file_hash):
    url = f"https://opentip.kaspersky.com/api/v1/search/hash?request={file_hash}"
    headers = {"x-api-key": api_key}
    
    try:
        response = requests.get(url, headers=headers)
        
        if response.status_code == 200:
            data = response.json()
            
            zone = data.get("Zone", "Unknown")
            status_map = {"Green": "Clean", "Red": "Malicious", "Yellow": "Suspicious", "Orange": "Adware/Riskware"}
            kt_status = status_map.get(zone, zone)

            general_info = data.get("FileGeneralInfo", {})
            kt_format = general_info.get("Type", "N/A") # exe x64
            kt_size = format_size(general_info.get("Size", 0)) # Size converted

            sig_info = data.get("ContentInfo", {}).get("SignatureInfo", {})
            if not sig_info: 
                sig_info = data.get("SignatureInfo", {})
                
            signer = sig_info.get("Signer", "Not Signed") if sig_info else "No Signature Data"

            detections = data.get("DetectionsInfo", [])
            if detections:
                det_names = ", ".join([d.get("DetectionName", "") for d in detections])
            else:
                det_names = "No data found"

            dynamic_analysis = data.get("DynamicAnalysisInfo", {})
            if dynamic_analysis:
                behaviors = dynamic_analysis.get("Behaviors", [])
                if behaviors:
                    dyn_summary = f"{len(behaviors)} behaviors detected"
                else:
                    dyn_summary = "Analyzed (No specific tag)"
            else:
                dyn_summary = "No data found"

            return {
                "kt_result": "OK",
                "kt_status": kt_status,      # Clean / Malicious
                "kt_format": kt_format,      # exe x64
                "kt_size": kt_size,          # 78.05 KB
                "kt_signer": signer,         # Microsoft Windows Publisher
                "kt_detections": det_names,  # Detection names
                "kt_dynamic": dyn_summary    # Dynamic analysis summary
            }

        elif response.status_code == 404:
            return {
                "kt_result": "Not Found", "kt_status": "N/A", "kt_format": "N/A", 
                "kt_size": "N/A", "kt_signer": "N/A", "kt_detections": "N/A", "kt_dynamic": "N/A"
            }
        elif response.status_code == 403:
             return {"kt_result": "Error 403: Forbidden (Check API Key)"}
        else:
            return {"kt_result": f"Error: {response.status_code}"}
            
    except requests.exceptions.RequestException as e:
        return {"kt_result": f"Network Error: {e}"}


print(f"[*] Reading data from '{EXCEL_FILE_PATH}'...")
try:
    df = pd.read_excel(EXCEL_FILE_PATH)
except FileNotFoundError:
    print(f"[!] Error: The file '{EXCEL_FILE_PATH}' was not found.")
    exit()

if MD5_COLUMN_NAME not in df.columns:
    print(f"[!] Error: Column '{MD5_COLUMN_NAME}' not found in the Excel file.")
    exit()

all_results = []
total_hashes = len(df)

print(f"[*] Found {total_hashes} hashes. Starting scan with VT and OpenTIP...")

for index, row in df.iterrows():
    md5_hash = row[MD5_COLUMN_NAME]
    
    print(f"[{index + 1}/{total_hashes}] Scanning: {md5_hash}")
    
    if not isinstance(md5_hash, str) or len(md5_hash) != 32:
        print("    -> Skipping invalid entry.")
        all_results.append({"vt_status": "Invalid MD5", "kt_result": "Invalid MD5"})
        continue

    vt_result = check_virustotal(VT_API_KEY, md5_hash)
    
    kt_result = check_opentip(OPENTIP_API_KEY, md5_hash)
    
    combined_result = {**vt_result, **kt_result}
    all_results.append(combined_result)
    
    print(f"    -> VT Status: {vt_result.get('vt_status', 'Unknown')} | KT Status: {kt_result.get('kt_result', 'Unknown')} - {kt_result.get('kt_status', '')}")
    print("-" * 50)
    
    time.sleep(16)

print("\n[*] All scans complete. Adding new columns to the DataFrame...")

results_df = pd.DataFrame(all_results)

df = pd.concat([df, results_df], axis=1)

print(f"[*] Saving updated data back to '{EXCEL_FILE_PATH}'...")
df.to_excel(EXCEL_FILE_PATH, index=False)

print(f"\n[SUCCESS] The file '{EXCEL_FILE_PATH}' has been successfully updated with VT and OpenTIP results.")