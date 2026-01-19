## 🎭 Scenario Context

A new ransomware strain named **PwnCrypt** was recently reported in the news. The ransomware leverages a **PowerShell-based payload** to encrypt files using **AES-256**, targeting directories such as `C:\Users\Public\Desktop` and appending a `.pwncrypt` extension to affected files (e.g., `hello.txt` → `hello.pwncrypt.txt`).

The CISO raised concerns that this new ransomware variant could be spreading within the corporate network. The security team was tasked with investigating systems using **Microsoft Defender for Endpoint (MDE)** to identify potential infections and determine whether ransomware activity was occurring.

---

# 🛡️ Threat Hunt Report – PwnCrypt Ransomware Detection & Containment

---

## 📌 Executive Summary

This investigation was initiated following threat intelligence regarding a new ransomware strain named PwnCrypt. Analysis of telemetry from `vm-lab-mde` revealed the creation of `pwncrypt.ps1`, widespread file renaming consistent with encryption activity, and execution of PowerShell with execution policy bypass. Multiple files were converted into `.pwncrypt` variants. Process telemetry showed the ransomware was executed under the SYSTEM account. The system was isolated, malware scans confirmed ransomware presence, and a ticket was submitted for full re-imaging.

---

## 🎯 Hunt Objectives

- Detect presence of PwnCrypt ransomware indicators  
- Identify ransomware execution method and timeline  
- Validate file encryption behavior  
- Determine execution context and origin  
- Contain and remediate the infected host  

---

## 🧭 Scope & Environment

- **Environment:** Azure-hosted Windows virtual machines  
- **Primary Host:** vm-lab-mde  
- **Data Sources:** Microsoft Defender for Endpoint  
  - DeviceFileEvents  
  - DeviceProcessEvents  
- **Timeframe:** 2026-01-05  

---

## 🧠 Hunt Overview

The hunt focused on identifying file encryption activity associated with the newly reported PwnCrypt ransomware strain. Indicators included suspicious PowerShell scripts, mass file renaming, execution policy bypass, and SYSTEM-level execution. The investigation validated ransomware presence and escalated the incident for remediation.

---

## 🔎 Investigation

### Step 1 – Identify PwnCrypt File Activity

I did a search within MDE DeviceFileEvents for any activity indicating a pwncrypt file and found many files that included pwncrypt in the file name.

~~~kql
let VMName = "vm-lab-mde";
DeviceFileEvents
| where DeviceName == VMName
| where FileName contains "pwn"
| order by Timestamp desc
~~~

<img width="1125" height="362" alt="532628471-702caec1-b870-4e4b-a0d4-76c8c4f66550" src="https://github.com/user-attachments/assets/06b4ea61-e00d-4324-804d-82b44803fe23" />

---

### Step 2 – Identify Mass File Encryption

I searched around the same timeframe for any files being created with the pwncrypt name and found many files being converted from ordinary files into their pwncrypt variants.

~~~kql
let VMName = "vm-lab-mde";
let specificTime = datetime(2026-01-05T20:13:12.8400855Z);
DeviceFileEvents
| where DeviceName == VMName
| where FileName contains "pwn"
| where Timestamp between ((specificTime - 3m) .. (specificTime + 3m))
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName
~~~

<img width="1125" height="427" alt="532628440-03976b9d-ec2b-4e6a-9001-d115a47054e5" src="https://github.com/user-attachments/assets/6fa3bfea-fc44-4bc0-8fba-f81284b8d3a3" />

---

### Step 3 – Review Ransomware Script

I logged into the suspected computer and observed the PowerShell script that was used to execute the ransomware.

<img width="1125" height="452" alt="532628391-ba099ec7-639a-473d-aa4a-1024bc067bd0" src="https://github.com/user-attachments/assets/187f3657-0aac-4f36-abd0-9ec6354cd8b1" />

---

### Step 4 – Identify Ransomware Origin and Execution Context

After discovering this ransomware, I checked to see who created it or its origin and found that it was associated with the account name SYSTEM.

~~~kql
let VMName = "vm-lab-mde";
let specificTime = datetime(2026-01-05T20:13:12.8400855Z);
DeviceProcessEvents
| where DeviceName == VMName
| where InitiatingProcessCommandLine contains "pwn"
| where Timestamp between ((specificTime - 3m) .. (specificTime + 3m))
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, InitiatingProcessCommandLine, AccountName
~~~

<img width="1125" height="211" alt="532628350-9ff72e5d-511d-49e9-85c3-b1bc3dd3e995" src="https://github.com/user-attachments/assets/3adafc6c-8e3b-400f-8303-86d61b695ad4" />

---

### Step 5 – Containment and Remediation

Following these discoveries, I isolated the VM from the rest of the network and ran malware scans. The scan detected the presence of ransomware. A ticket was created to have the computer fully re-imaged from backup.

---

## 🧬 MITRE ATT&CK Summary

| Tactic | Technique | MITRE ID | Evidence |
|-------|------------|----------|----------|
| Execution | PowerShell | T1059.001 | PowerShell used to execute `pwncrypt.ps1` |
| Defense Evasion | Impair Defenses | T1562.001 | Execution policy bypass used |
| Impact | Data Encrypted for Impact | T1486 | Files converted into pwncrypt variants |
| Privilege Context | Valid Accounts: SYSTEM | T1078.003 | Ransomware ran under SYSTEM |

---

## 🚩 Flag Analysis

🚩 **Flag 1 – PwnCrypt indicators detected**  
Multiple files contained pwncrypt extensions.

🚩 **Flag 2 – Mass file encryption**  
Ordinary files were rapidly converted to encrypted variants.

🚩 **Flag 3 – Malicious PowerShell execution**  
Execution policy bypass observed.

🚩 **Flag 4 – SYSTEM-level ransomware execution**  
Script was launched under SYSTEM account.

---

## 🛡️ Response Actions

- Isolated infected VM  
- Executed malware scans (ransomware confirmed)  
- Escalated incident  
- Ticket created for full re-image  

---

## 🚨 Detection Gaps & Recommendations

### Observed Gaps
- Limited detection of abnormal PowerShell execution  
- No early alerting on mass file rename/encryption  
- Insufficient SYSTEM account activity monitoring  

### Recommendations
- Baseline normal system and scripting behavior  
- Block or constrain PowerShell abuse  
- Monitor SYSTEM-level process creation  
- Alert on mass file rename patterns  
- Limit unnecessary network exposure  

---

## 🧾 Final Assessment

`vm-lab-mde` was confirmed infected with the PwnCrypt ransomware strain. Evidence showed malicious PowerShell execution, SYSTEM-level privilege use, and mass file encryption. Rapid isolation and remediation actions limited further impact. This hunt demonstrates full ransomware detection, execution tracing, and containment workflow.

---

## 📎 Analyst Notes

- Evidence reproducible via Microsoft Defender Advanced Hunting  
- Demonstrates ransomware investigation lifecycle  
- MITRE ATT&CK aligned  

---
