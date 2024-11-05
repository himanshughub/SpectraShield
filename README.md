Spectra Shield 🛡️

📚 Library Versions Utilized in the Script:
jq: jq-1.6
csv: 1.0
json: 2.0.9
pytz: 2024.2
requests: 2.32.3
colorama: 0.4.6
openpyxl: 3.1.5
prettytable: 3.11.0
alive_progress: 3.1.5

<Installation:->
Navigate to the Spectra_Shield directory and run:
----------------------
Command:- sudo make
----------------------

⚙️  This command will automatically set up all required libraries with their specified versions.

#Table of Contents

<Usage Instructions:->

🔍 Step 1: Query SIEM
📥 Step 2: Export Results
📁 Step 3: File Placement
▶️  Step 4: Run the Script


#Usage Instructions
<🔍 Step 1: Query SIEM:->
Run the following CrowdStrike advanced SIEM query:
--------------------------------------------------------------------------------------------------------------------------------
repo=base_sensor cid="XXXXXXXXXXXXXXXXXXXX"
| in(aid, values=["*"], ignoreCase=true)
| groupBy(SHA256HashData, function=collect([SHA256HashData, FileName, ComputerName, LocalAddressIP4, aid, cid, FilePath]), limit=max)
--------------------------------------------------------------------------------------------------------------------------------

⚠️ Important Notes:
  - Replace XXXXXXXXXXXXXXXXXXXX with your actual CID ID.
  - CrowdStrike has a maximum limit of 20,000 results per query
  - The query is designed to look for unique hash values to minimize duplicate results
  - For environments with 50+ computers:
    - Query results may reach the limit when looking at logs spanning more than 6 hours
    - It's recommended to limit the query duration window to 6 hours
    - Break down larger time spans into multiple 6-hour queries if needed


<📥 Step 2: Export Results:->
After running the query, export the results in CSV format
Name the file exactly as: CrowdStrike_exported_data.csv


<📁 Step 3: File Placement:->
Place the exported CSV file in the Spectra_Shield directory.


<▶️  Step 4: Run the Spectra Shield Script:->

------------------------------------------------
Command:- python3 Spectra_Shield.py --api-keys 111323455342255322

where, 111323455342255322 is a dummy API key
You may obtain the VT API key by creating a free account on https://www.virustotal.com/gui/join-us
------------------------------------------------

    - Enter your choice (1-5): X
    - Please enter the full path to your CSV file: CrowdStrike_exported_data.csv


==================================================================================================
After completing these steps, the script will automatically:

1. Check each hash from the CSV file against the threat intelligence platform
2. Collect and analyze the results
3. Save the findings to `SpectraShield_Dashboard.xlsx` in the Spectra Shield directory


## Excluding Results
You can exclude or make exceptions for specific hashes/process names from appearing in your results dashboard. To do this:

1. Navigate to the `data/` directory
2. Add exclusions to the following files:
   - `list_of_false_positive_hashes.txt`: For excluding specific hashes
   - `list_of_false_positive_process_name.txt`: For excluding specific process names

==================================================================================================
