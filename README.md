# Spectra Shield

<img src="spectra-shield-logo.svg" alt="Screenshot of the tool" width="50%">

## About Spectra_Shield:
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
Name the file exactly as: CrowdStrike_exported_data.csv

**Step 3: File Placement**
Place the exported CSV file in the Spectra_Shield directory.

**Step 4: Run the Script**
Run the following command:
 ```bash
python3 Spectra_Shield.py --api-keys 111323455342255322
 ```

> **Note:**

- 111323455342255322 is a dummy API key. You can obtain a VT API key by creating a free account on VirusTotal

Follow the prompts:

Enter your choice (1-5): X
Enter the full path to your CSV file: CrowdStrike_exported_data.csv

## Automated Process
After completing these steps, the script will automatically:

- Check each hash from the CSV file against the threat intelligence platform
- Collect and analyze the results
- Save the findings to SpectraShield_Dashboard.xlsx in the Spectra Shield directory

## Add exclusions or exceptions to reduce false positives from being updated in the dashboard:

You can exclude or make exceptions for specific hashes/process names from appearing in your results dashboard.
To add exclusions:

- Navigate to the data/ directory

- Add exclusions to the following files:
  
**list_of_false_positive_hashes.txt: For excluding specific hashes**
  
**list_of_false_positive_process_name.txt: For excluding specific process names**

