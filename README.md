# ToolShellFinder: CVE-2025-53770 & CVE-2025-53771 Detection

A PowerShell script for **detecting indicators of compromise (IoCs) for CVE-2025-53770 and CVE-2025-53771** in Microsoft IIS logs.  
This script is hacked together to help DFIR teams, sysadmins, and security professionals identify suspicious activity associated with these vulnerabilities in SharePoint environments.

**Version PS5 is being replaced by version PS7**
- Version PS7 will only work in PowerShell 7 (https://learn.microsoft.com/en-us/powershell/scripting/install/installing-powershell-on-windows?view=powershell-7.5#zip)

## Table of Contents

- [Background](#background)
- [What This Script Does](#what-this-script-does)
- [Usage](#usage)
- [Indicators of Compromise](#indicators-of-compromise)

---

## Background

**CVE-2025-53770** and **CVE-2025-53771** are recently disclosed vulnerabilities affecting Microsoft SharePoint, potentially allowing remote code execution and exploitation via crafted requests to `/ToolPane.aspx`, suspicious uploads, or exploitation of ViewState parameters. Attackers may leave forensic traces in IIS logs.

---

## What This Script Does

- **Recursively scans IIS log files** for patterns linked to exploitation attempts of these CVEs.
- **Identifies and collects matches** for four major sets of IoCs (see below).
- **Outputs a summary table** of detected events and exports detailed results to CSV for further analysis.

---

## Usage

1. **Copy the script to your investigation workstation.**
2. **Set the `$logRoot` path** at the top of the script if your IIS logs are not in `C:\inetpub\logs\LogFiles`.
3. **Run the script in a PowerShell window:**

   ```powershell
   .\toolshellfinder.ps1
   ```

   ---

## Indicators of Compromise

1. **ToolPane Exploitation Attempts (POST)**
- HTTP Method: POST
- Path: /_layouts/15/ToolPane.aspx or /_layouts/16/ToolPane.aspx
- Query String: Contains DisplayMode=Edit&a=/ToolPane.aspx
- Referer: Contains /_layouts/SignOut.aspx

2. **Suspicious File Drops (GET)**
- HTTP Method: GET
- Referer: Contains /_layouts/SignOut.aspx
- Path: Matches suspicious files in /layouts/15/ or /layouts/16/ (e.g., spinstall.aspx, debug_dev.js, etc.)

3. **start.aspx Enumeration (GET, Suspicious User-Agent)**
- HTTP Method: GET
- Path: /_layouts/15/start.aspx or /_layouts/16/start.aspx
- User-Agent: Contains curl, powershell, or python (case-insensitive, anywhere in UA string)

4. **Malicious success.aspx & ViewState (Suspicious User-Agent & Query)**
- Path: /_layouts/15/success.aspx or /_layouts/16/success.aspx
- Query String: Starts with a long __VIEWSTATE= value (≥40 chars, indicative of payloads)
- User-Agent: Contains curl, powershell, or python

---


