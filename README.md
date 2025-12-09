# 🛡️ Threat Intel Bulk Scanner

This repository contains Python tools designed for SOC analysts and Threat Hunters to bulk scan file hashes (MD5) using multiple Threat Intelligence APIs.

The project includes two specialized scanners depending on your needs:

## 📂 Included Scanners

### 1. Fast Scanner (`fast_scanner_ha_kt.py`) 🚀
Best for high-volume scanning without strict rate limits.
- **Engines:** Kaspersky OpenTIP + Hybrid Analysis.
- **Key Feature:** Uses a **Smart-Chain technique**. It queries Kaspersky to retrieve the SHA256 of the file, then uses that SHA256 to query Hybrid Analysis (bypassing HA's free tier MD5 limitations).
- **Speed:** Fast (Multi-threaded).
- **Output:** Verdicts, Threat Tags, timestamps.

### 2. Comprehensive Scanner (`comprehensive_scanner_vt_kt.py`) 🔍
Best for deep analysis when VirusTotal data is required.
- **Engines:** VirusTotal + Kaspersky OpenTIP.
- **Constraint:** Respects VirusTotal's free tier rate limit (4 requests/min), so it includes a built-in delay.
- **Output:** VT Detections (x/y), Signed status, File size, meaningful names.

## 📋 Prerequisites

- Python 3.x
- API Keys for the respective services (VirusTotal, Kaspersky, Hybrid Analysis).

## ⚙️ Installation

1. Clone the repo or download the files.
2. Install dependencies:
   ```bash
   pip install -r requirements.txt

 # 🏃‍♂️ Usage
1. Prepare an Excel file (e.g., dc_md5.xlsx) containing a column named md5.
2. Open the desired script (fast_scanner_ha_kt.py or comprehensive_scanner_vt_kt.py).
3. Insert your API Keys in the configuration section at the top of the file:
   ```bash
   OPENTIP_API_KEY = "YOUR_KEY"
   HA_API_KEY = "YOUR_KEY"
   #etc...

4. Run the script:
   ```bash
   python fast_scanner_ha_kt.py

5. The script will automatically update your Excel file with new columns containing the scan results.

 # ⚠️ Disclaimer
This tool is for educational and defensive purposes. Please ensure you comply with the API Terms of Service of VirusTotal, Kaspersky, and Hybrid Analysis.
