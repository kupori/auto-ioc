# auto-ioc

1. takes in a xlsx files containing IOCs (url/ip/hashes) and churns out comma delimited csv(s) for each unique ioc type
2. automatically import IOCs to ESM(s) via API calls 

**long term todo:**
* more fields (source, campaign name, cve etc)

---

**auto_ioc.py**

Generating the .csv files

1. Put .xlsx file into same folder as auto_ioc.py / .exe
2. Run auto_ioc.py / .exe
3. output folder containing csv files will be created
   * a copy of the original .xlsx will be created
   * if .xlsx was encrypted, pw will be saved into saved-pw.txt
   * pw.txt will be cleared

If the file is encrypted, two options:

* copy and paste the password into pw.txt
* enter the password into the command line when prompted

Troubleshooting

- If legitimate data is being classified as unknown, the sheet name is probably not recognised, refer to steps below to add it in
- If data appears in both classified data and unknown, check xlsx for duplicates

---

Adding new Sheet Names

1. Navigate to dependancies folder
2. Open sheet_address /sheet_hash
3. Add the new sheet name in a new line (IN ALL CAPITAL LETTERS)
4. Save & Close

---
