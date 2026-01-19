<p align="center">
  <img
    src="https://github.com/user-attachments/assets/230d5b85-43ad-4845-82d1-2a1ca54f9eea"
    width="1200"
    alt="Threat Hunt Cover Image"
  />
</p>

---

## 🎭 Scenario Context

An employee named **John Doe**, working in a sensitive department, was recently placed on a **Performance Improvement Plan (PIP)**. Following an emotional reaction to the decision, management raised concerns that John may attempt to **steal proprietary company information and resign**.

The security team was tasked with proactively investigating John’s activity on his assigned corporate device, **`windows-target-1`**, using **Microsoft Defender for Endpoint (MDE)** to determine whether any suspicious behavior, data collection, staging, or exfiltration attempts were taking place.

### Investigation Goals

- Review endpoint telemetry for signs of data collection or staging  
- Identify suspicious PowerShell or compression activity  
- Determine whether proprietary data was prepared for exfiltration  
- Validate whether any network activity supported data theft concerns  

This scenario frames the investigation as an **insider-threat motivated hunt**, focused on early detection of data theft behaviors.

---

# 🛡️ Threat Hunt Report – Suspicious Archive Creation & Possible Data Staging

---

## 📌 Executive Summary

This threat hunt was initiated after identifying unusual archive creation activity on `vm-lab-mde`. Analysis revealed repeated ZIP file creation and movement into a backup directory. Correlation with process telemetry showed a PowerShell script silently installing 7-Zip and compressing employee data. While no evidence of data exfiltration was observed, the activity aligned with data collection and potential staging behaviors, warranting escalation to management and continued monitoring.

---

## 🎯 Hunt Objectives

- Identify suspicious file archiving activity  
- Correlate archive creation to process execution  
- Determine whether data staging or exfiltration occurred  
- Map observed behaviors to MITRE ATT&CK techniques  

---

## 🧭 Scope & Environment

- **Environment:** Azure-hosted Windows virtual machines  
- **Primary Host:** vm-lab-mde  
- **Data Sources:** Microsoft Defender for Endpoint  
  - DeviceFileEvents  
  - DeviceProcessEvents  
  - DeviceNetworkEvents  
- **Timeframe:** 2026-01-06  

---

## 📚 Table of Contents

- [🧠 Hunt Overview](#-hunt-overview)  
- [🧪 Preparation](#-preparation)  
- [📥 Data Collection](#-data-collection)  
- [🧠 Data Analysis](#-data-analysis)  
- [🔎 Investigation](#-investigation)  
- [🧬 MITRE ATT&CK Summary](#-mitre-attck-summary)  
- [🚩 Flag Analysis](#-flag-analysis)  
- [🛡️ Response Actions](#-response-actions)  
- [🚨 Detection Gaps & Recommendations](#-detection-gaps--recommendations)  
- [🧾 Final Assessment](#-final-assessment)  
- [📎 Analyst Notes](#-analyst-notes)  

---

## 🧠 Hunt Overview

The hunt began after noticing regular archive creation activity involving employee data. The investigation focused on identifying whether these archives were part of legitimate backup operations or indicative of unauthorized data collection and staging. Correlation of file and process telemetry revealed PowerShell-driven compression using 7-Zip. Network telemetry was reviewed to validate whether any data exfiltration occurred.

---

## 🧪 Preparation

### Goal
Determine whether repeated ZIP archive creation represented unauthorized data collection or preparation for exfiltration.

### Hypothesis
If employee data is being archived repeatedly via script-driven execution, the activity may represent collection and staging techniques used prior to exfiltration.

---

## 📥 Data Collection

### Data Sources
- `DeviceFileEvents` – identify archive creation and file movement  
- `DeviceProcessEvents` – correlate process execution  
- `DeviceNetworkEvents` – validate possible data exfiltration  

---

## 🧠 Data Analysis

### Focus Areas
- Frequency and location of ZIP file creation  
- Process responsible for archive generation  
- Evidence of outbound data transfer  

---

## 🔎 Investigation

### Step 1 – Identify ZIP File Activity

I searched within MDE DeviceFileEvents for any activities involving ZIP files and observed regular creation and movement of archives into a “backup” folder.

~~~kql
DeviceFileEvents
| where DeviceName == "vm-lab-mde"
| where FileName endswith ".zip"
| order by Timestamp desc
~~~

<img width="1125" height="298" alt="532623863-2eec9c1e-886a-4200-86d9-48f0316e974b" src="https://github.com/user-attachments/assets/9d1af2d7-7989-4869-a805-b6ecf1b852d9" />

---

### Step 2 – Correlate Archive Creation to Process Execution

I took note of instances where ZIP files were created, extracted the timestamps, and pivoted into DeviceProcessEvents to identify activity occurring two minutes before and after archive creation. Around the same time, a PowerShell script was observed silently installing 7-Zip and compressing employee data.

~~~kql
let VMName = "vm-lab-mde";
let specificTime = datetime(2026-01-06T21:18:51.4101916Z);
DeviceProcessEvents
| where Timestamp between ((specificTime - 2m) .. (specificTime + 2m))
| where DeviceName == VMName
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName, ProcessCommandLine
~~~

<img width="1125" height="697" alt="532626603-49cc5294-75db-4c0d-9ed1-6bfbd8f0d28c" src="https://github.com/user-attachments/assets/afa6cfb9-f51a-4fbd-a452-9ee0f013cbc4" />

---

### Step 3 – Search for Evidence of Exfiltration

I searched the same time window for any evidence of outbound network activity that could indicate data exfiltration.

~~~kql
let VMName = "vm-lab-mde";
let specificTime = datetime(2026-01-06T21:18:51.4101916Z);
DeviceNetworkEvents
| where Timestamp between ((specificTime - 2m) .. (specificTime + 2m))
| where DeviceName == VMName
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType
~~~

**Finding:** No evidence of data exfiltration was observed.

---

## 🧬 MITRE ATT&CK Summary

| Tactic | Technique | MITRE ID | Evidence |
|-------|------------|----------|----------|
| Execution | PowerShell | T1059.001 | PowerShell installed 7-Zip and executed archive commands |
| Collection | Archive Collected Data via Utility | T1560.001 | Employee data compressed into ZIP files |
| Staging (possible) | Data Staged | T1074 | Repeated ZIP creation suggests preparation for transfer |
| Exfiltration (ruled out) | None observed | — | No supporting DeviceNetworkEvents evidence |

---

## 🚩 Flag Analysis

<details>
<summary>🚩 <strong>Flag 1: Repeated ZIP archive creation</strong></summary>

Employee data was regularly archived and moved into a backup directory.

</details>

<details>
<summary>🚩 <strong>Flag 2: Unauthorized PowerShell-driven compression</strong></summary>

A PowerShell script silently installed 7-Zip and performed compression.

</details>

<details>
<summary>🚩 <strong>Flag 3: Possible data staging</strong></summary>

Repeated archive creation suggests preparation for transfer, though no exfiltration was observed.

</details>

<details>
<summary>🚩 <strong>Flag 4: Exfiltration ruled out</strong></summary>

Network telemetry did not support outbound data transfer.

</details>

---

## 🛡️ Response Actions

- Relayed findings to employee management  
- Documented archive creation pattern and PowerShell activity  
- Continued monitoring pending management instruction  

---

## 🚨 Detection Gaps & Recommendations

### Observed Gaps
- No alerting on scripted archive creation  
- Limited behavioral detections for internal data staging  

### Recommendations
- Alert on unauthorized compression utilities  
- Monitor repeated archive creation involving sensitive data  
- Correlate scripting activity with file operations  
- Implement stricter controls over backup and scripting processes  

---

## 🧾 Final Assessment

`vm-lab-mde` exhibited repeated archive creation of employee data driven by a PowerShell script that silently installed 7-Zip. While no evidence of data exfiltration was identified, the behavior aligned with data collection and possible staging techniques. The incident was escalated to management, and the system remains under observation. This hunt demonstrates detection of early-stage collection activity prior to confirmed data loss.

---

## 📎 Analyst Notes

- Evidence reproducible via Microsoft Defender Advanced Hunting  
- MITRE ATT&CK aligned investigation  
- Demonstrates collection detection, process correlation, and validation of non-exfiltration  

---
