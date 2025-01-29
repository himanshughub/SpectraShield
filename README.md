[zip]: https://github.com/himanshughub/SpectraShield/archive/refs/heads/main.zip

# Spectra Shield - Threat Hunting Tool (v1.0)
[![Download SpectraShield.zip](https://img.shields.io/badge/download-SpectraShield.zip-blue?style=flat-square&color=yellow)](https://github.com/himanshughub/SpectraShield/releases/download/SpectraShield_v1.0/SpectraShield-main.zip)
[![Release Version](https://img.shields.io/github/v/release/himanshughub/SpectraShield.svg)](https://github.com/himanshughub/SpectraShield/releases/tag/SpectraShield_v1.0)
[![Downloads latest](https://img.shields.io/github/downloads/himanshughub/SpectraShield/latest/total?style=flat-square&color=green&logo=github)](https://github.com/himanshughub/SpectraShield/releases/latest)
[![Downloads total](https://img.shields.io/github/downloads/himanshughub/SpectraShield/total?style=flat-square&color=blueviolet&logo=github)](https://github.com/himanshughub/SpectraShield/releases)
[![License](https://img.shields.io/badge/License-GPL--3.0-blue)](https://github.com/himanshughub/SpectraShield/blob/main/LICENSE)

<img src="spectra-shield-logo.svg" alt="Screenshot of the tool" width="50%">

## About Spectra Shield:
Spectra_Shield is an advanced open-source threat hunting tool designed to enhance
threat detection capabilities in cybersecurity operations. It is specifically
engineered to cover loopholes of CrowdStrike where its threat intelligence
database is not comprehensive to find various known malicious processes.
By leveraging multiple threat intelligence sources, including VirusTotal API,
Abuse.ch API, and custom threat intelligence databases, Spectra_Shield provides
a comprehensive solution for identifying malicious processes executed on machines,
filling critical gaps in existing security infrastructures.

## Key Features:
- Integration with VirusTotal API for extensive threat analysis
- Utilization of Abuse.ch API for up-to-date threat intelligence
- Custom hash list investigation for tailored threat detection
- Full scan capability combining all available investigation methods

![Spectra_Shield_recording_gif](https://github.com/himanshughub/SpectraShield/raw/main/Screenshots/Spectra_Shield_recording.gif)

![Spectra_Shield_excel_Sheet_view_recording_gif](https://github.com/himanshughub/SpectraShield/blob/main/Screenshots/Spectra_Shield_excel_Sheet_view_recording.gif)

## 📚 Library Versions
- jq: jq-1.6
- csv: 1.0
- json: 2.0.9
- pytz: 2024.2
- requests: 2.32.3
- colorama: 0.4.6
- openpyxl: 3.1.5
- prettytable: 3.11.0
- alive_progress: 3.1.5

## Installation

Navigate to the Spectra_Shield directory and run:

 ```bash
    sudo make
 ```

⚙️ This command will automatically set up all required libraries with their specified versions.


## Table of Contents

🔍 1. Query SIEM

📥 2. Export Results

📁 3. File Placement

▶️  4. Run the Script


## Usage Instructions

**Step 1: Query SIEM**

Run the following CrowdStrike advanced SIEM query:

 ```bash
#repo="base_sensor" cid="XXXXXXXXXXXXXXXXXXXX"
| in(aid, values=["*"], ignoreCase=true)
| groupBy(SHA256HashData, function=collect([SHA256HashData, FileName, ComputerName, LocalAddressIP4, aid, cid, FilePath]), limit=max)
 ```
![CrowdStrike_query_snap](https://github.com/user-attachments/assets/abca40e9-2668-4362-8101-58eae76f212b)

> **Important Notes:**

- Replace XXXXXXXXXXXXXXXXXXXX with your CrowdStrike CID ID
- CrowdStrike has a maximum limit of 20,000 results per query
- The query is designed to look for unique hash values to minimize duplicate results
- For environments with 50+ computers:
- Query results may reach the limit when looking at logs spanning more than 6 hours
- It's recommended to limit the query duration window to 6 hours
- Break down larger time spans into multiple 6-hour queries if needed


**Step 2: Export Results**

After running the query, export the results in CSV format
Name the file for example as: <mark>CrowdStrike_exported_data.csv</mark>

**Step 3: File Placement**
Place the exported CSV file in the Spectra_Shield directory.

**Step 4: Run the Script**
Run the following command:
 ```bash
python3 Spectra_Shield.py --api-keys 111323455342255322
 ```

> **Note:**

- 111323455342255322 is a dummy API key. You can obtain a VT API key by creating a free account on [VirusTotal](https://www.virustotal.com/gui/home/upload)

Follow the prompts:

Enter your choice (1-5): X

Enter the full path to your CSV file which you have downloaded from the CrowdStrike, for example: <mark>CrowdStrike_exported_data.csv</mark>

## Automated Process
After completing these steps, the script will automatically:

- Check each hash from the CSV file against the threat intelligence platform
- Collect and analyze the results
- Save the findings to "<mark>SpectraShield_Dashboard.xlsx</mark>" in the Spectra Shield directory


## Add exclusions or exceptions to reduce false positives from being updated in the dashboard:

You can exclude or make exceptions for specific hashes/process names from appearing in your results dashboard.
To add exclusions:

- Navigate to the data/ directory

- Add exclusions to the following files:
  
<mark>list_of_false_positive_hashes.txt</mark>: For excluding specific hashes from dashboard results

<mark>list_of_false_positive_process_name.txt</mark>: For excluding specific process names from dashboard results

## What to expect in future version of this tool...

- Adding more threat intelligence platform APIs integration such as Any.run, ctx.io, AlienVault, malshare.com, etc.
- Increasing the performace by using parallel processing.
- Adding AI and ML capabilities to provide insights on processes that conflict with the business environment, such as third-party VPNs, gaming applications, forensics tools, pentesting tools and more.

## Citation
If you found this repository helpful, please cite my Github repository link & name in your post :)
```bash
Repository Link: https://github.com/himanshughub/SpectraShield/
Author name:Himanshu Kumar
Author LinkedIn Profile: https://www.linkedin.com/in/himanshuk8
```


