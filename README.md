# 🛠️ ToolShellFinder: CVE-2025-53770 & CVE-2025-53771 Detection

A high-performance PowerShell 7+ script for scanning IIS logs to detect signs of exploitation related to **ToolShell**, specifically targeting the zero-day vulnerabilities **CVE-2025-53770** and **CVE-2025-53771** in Microsoft SharePoint.

This script is hacked together to help DFIR teams, sysadmins, and security professionals identify suspicious activity associated with these vulnerabilities in SharePoint environments and is ideal for defenders who prefer native PowerShell.

**Version PS5 is being replaced by version PS7**
- Version PS7 will only work in PowerShell 7+ (https://learn.microsoft.com/en-us/powershell/scripting/install/installing-powershell-on-windows?view=powershell-7.5#zip)

## 📘 Table of Contents

- [Background](#background)
- [Key Features](#key-features)
- [Requirements](#requirements)
- [How to Use](#how-to-use)
- [Detection Logic](#detection-logic)
- [References](#references)
- [Summary](#summary)

---

## ⚠️ Background

**CVE-2025-53770** and **CVE-2025-53771** are recently disclosed vulnerabilities affecting Microsoft SharePoint, potentially allowing remote code execution and exploitation via crafted requests to `/ToolPane.aspx`, suspicious uploads, or exploitation of ViewState parameters. Attackers may leave forensic traces in IIS logs.

---

## 📌 Key Features

- 🔍 Scans **IIS W3C logs** recursively from a given root directory.
- 🧠 Detects:
  - ToolPane abuse (`ToolPane.aspx` exploitation)
  - Suspicious file accesses (e.g. `spinstall.aspx`, `ghostfile.aspx`, etc.)
  - Requests from known **malicious IPs** (via external blocklist)
- ⚙️ Fully parallelized using `ForEach-Object -Parallel` for speed.
- 🧾 Outputs CSV results for DFIR reporting or SIEM ingestion.

---

## 💻 Requirements

- PowerShell 7.0 or newer
- Admin/Read access to IIS log files
- Internet access to retrieve remote IP blocklist (optional)

---

## 🚀 How to Use

1. **Edit the top of the script:**
   ```powershell
    $logRoot       = "C:\inetpub\logs\LogFiles"  # Your log folder
    $ThrottleLimit = 12                          # Number of parallel threads
   ```
2. **Run the script:**
   ```powershell
   .\toolshellfinderPS7.ps1
   ```
3. **Results will be saved to:**

   ```powershell
   IIS_IoC_Matches.csv
   ```

   ---

## 📌 Detection Logic

✅ IoC Set 1 — CVE-2025-53771 (ToolPane abuse)
   - **POST or GET to:**
     ```powershell
     /_layouts/15/ToolPane.aspx
      /_layouts/16/ToolPane.aspx
     ```
   - **With query:**
     ```powershell
     DisplayMode=Edit&a=/ToolPane.aspx
     ```
   - **And referer:**
      ```powershell
     /_layouts/SignOut.aspx or "-"
      ```
✅ IoC Set 2 — CVE-2025-53770 (Suspicious file names)
   - **Access to files matching:**
        ```powershell
        spinstall.aspx, spinstall*.aspx, ghostfile.aspx, debug_dev.js,
        info.js, machinekey.aspx, ghost.aspx, etc.
        ```
   - **Located under:**
        ```powershell
        /_layouts/15/
        /_layouts/16/
        ```
   - **With referer:**
        ```powershell
        /SignOut.aspx or -
        ```
✅ IoC Set 3 — Malicious IP addresses
   - **The script dynamically downloads a threat intel list from:**
        ```powershell
        https://raw.githubusercontent.com/zach115th/BlockLists/main/emerging-threats/2025/toolshell/toolshell_ips.txt
        ```

---

## 📎 References

- [CVE-2025-53770](https://nvd.nist.gov/vuln/detail/CVE-2025-53770)
- [CVE-2025-53771](https://nvd.nist.gov/vuln/detail/CVE-2025-53771)
- [Eye Security – ToolShell Analysis](https://research.eye.security/sharepoint-under-siege/)
- [Microsoft Guidance](https://msrc.microsoft.com/blog/2025/07/customer-guidance-for-sharepoint-vulnerability-cve-2025-53770/)

---

## ✅ Summary

**ToolShellFinder** is a fast, flexible, and battle-tested PowerShell script for detecting real-world exploitation of SharePoint zero-days via log review. Use it in your DFIR toolkit to catch what your EDR may have missed.

---
