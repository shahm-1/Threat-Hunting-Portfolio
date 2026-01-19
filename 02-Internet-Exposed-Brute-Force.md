## 🎭 Scenario Context

During routine maintenance, the security team was tasked with investigating any virtual machines in the **shared services cluster** (handling DNS, Domain Services, DHCP, etc.) that may have been **mistakenly exposed to the public internet**.

The objective of this scenario was to:

- Identify any misconfigured or unintentionally internet-facing VMs  
- Determine whether those systems were receiving external authentication attempts  
- Validate whether any brute-force activity resulted in successful unauthorized access  

This hunt frames the investigation as a **preventive exposure assessment and brute-force validation exercise**, focused on early detection of initial access attempts before compromise.

---

# 🛡️ Threat Hunt Report – Internet-Exposed VM Brute Force Investigation

---

## 📌 Executive Summary

A Windows VM (`windows-target-1`) in the shared services environment was found to be unintentionally exposed to the public internet for several days. Authentication telemetry showed multiple external IP addresses repeatedly attempting to authenticate via remote/network logon types, consistent with brute-force behavior. Investigation confirmed **no evidence of brute-force success** and **no signs of unauthorized access**, with successful logons limited to a legitimate lab account from expected sources. Remediation actions were implemented to reduce exposure and strengthen identity controls.

---

## 🎯 Hunt Objectives

- Identify malicious activity across endpoints and authentication telemetry  
- Correlate attacker behavior to MITRE ATT&CK techniques  
- Validate whether brute-force activity resulted in successful compromise  
- Document evidence, detection gaps, and response improvements  

---

## 🧭 Scope & Environment

- **Environment:** Azure-hosted Windows VM (Shared Services Cluster)  
- **Target Host:** `windows-target-1`  
- **Data Sources:** Microsoft Defender for Endpoint (Advanced Hunting)  
  - `DeviceInfo`  
  - `DeviceLogonEvents`  
- **Timeframe:** 2026-01-01 → 2026-01-05  

---

## 📚 Table of Contents

- [🧠 Hunt Overview](#-hunt-overview)
- [🧪 Preparation](#-preparation)
- [📥 Data Collection](#-data-collection)
- [🧠 Data Analysis](#-data-analysis)
- [🔎 Investigation](#-investigation)
  - [Step 1 – Confirm Internet Exposure](#step-1--confirm-internet-exposure)
  - [Step 2 – Identify Brute-Force Attempts](#step-2--identify-brute-force-attempts)
  - [Step 3 – Validate Brute-Force Success](#step-3--validate-brute-force-success)
  - [Step 4 – Review Successful Logons](#step-4--review-successful-logons)
- [🧬 MITRE ATT&CK Summary](#-mitre-attck-summary)
- [🚩 Flag Analysis](#-flag-analysis)
- [🛡️ Response Actions](#-response-actions)
- [🚨 Detection Gaps & Recommendations](#-detection-gaps--recommendations)
- [🧾 Final Assessment](#-final-assessment)

---

## 🧠 Hunt Overview

This hunt was initiated to identify shared services virtual machines (DNS, Domain Services, DHCP, etc.) that may have been mistakenly exposed to the public internet and to assess whether that exposure resulted in brute-force authentication attempts and/or successful unauthorized access.

The hunt confirmed that `windows-target-1` was internet-facing and was actively targeted by multiple external IP addresses attempting remote/network authentication. However, correlation analysis found no evidence of successful logons from the attacking IPs, and successful logons were limited to a legitimate account from expected sources.

---

## 🧪 Preparation

### Goal
Identify any shared services VMs mistakenly exposed to the internet and assess whether external brute-force attempts succeeded.

### Hypothesis
Because the device was unknowingly exposed to the public internet and some older systems may lack lockout controls, it is possible external actors attempted brute-force authentication and could have succeeded.

---

## 📥 Data Collection

### Goal
Collect the relevant logs to validate exposure and authentication patterns.

### Data Sources Used
- `DeviceInfo` (confirm internet exposure)
- `DeviceLogonEvents` (failed/successful logons, logon types, remote IPs)

---

## 🧠 Data Analysis

### Goal
Identify anomalies consistent with brute force:
- Excessive failed logons from external IPs
- Many failures followed by a success
- Successful logons from suspicious IPs or unexpected accounts

---

## 🔎 Investigation

### Step 1 – Confirm Internet Exposure

**Finding:** `windows-target-1` was internet-facing for several days.

~~~kql
DeviceInfo
| where DeviceName == "windows-target-1"
| where IsInternetFacing == 1
| order by Timestamp desc
~~~

**Observed Example Timestamp:** `2026-01-05T22:55:11.9532147Z`

---

### Step 2 – Identify Brute-Force Attempts

**Finding:** Several external IPs were attempting to log in, producing high volumes of failures consistent with brute force.

~~~kql
DeviceLogonEvents
| where DeviceName == "windows-target-1"
| where LogonType has_any("Network", "Interactive", "RemoteInteractive", "Unlock")
| where ActionType == "LogonFailed"
| where isnotempty(RemoteIP)
| summarize Attempts = count() by ActionType, RemoteIP, DeviceName
| order by Attempts
~~~

<img width="1125" height="480" alt="532615874-fc7c7a04-97bd-4b01-9847-057268b72fc4" src="https://github.com/user-attachments/assets/d364287d-6eeb-493a-9926-47831a979832" />

---

### Step 3 – Validate Brute-Force Success

**Finding:** The top attacking IPs (highest failed attempts) showed **no successful logons**.

~~~kql
let RemoteIPsInQuestion = dynamic(["185.11.61.192","185.11.61.198","45.136.68.76","77.90.185.64","77.90.185.62"]);
DeviceLogonEvents
| where LogonType has_any("Network", "Interactive", "RemoteInteractive", "Unlock")
| where ActionType == "LogonSuccess"
| where RemoteIP has_any(RemoteIPsInQuestion)
~~~

**Result:** Query returned **no results**.

---

### Step 4 – Review Successful Logons

**Finding:** The only successful remote/network logons in the last 90 days were for the legitimate account `labuser1` (2 total).

~~~kql
DeviceLogonEvents
| where DeviceName == "windows-target-1"
| where LogonType == "Network"
| where ActionType == "LogonSuccess"
| where AccountName == "labuser1"
| where TimeGenerated > ago(90d)
| summarize count()
~~~

**Finding:** There was 1 failed logon event for `labuser1` in the last 90 days, indicating brute-force activity did not focus on this account and a one-off guess is unlikely.

~~~kql
DeviceLogonEvents
| where DeviceName == "windows-target-1"
| where LogonType == "Network"
| where ActionType == "LogonFailed"
| where AccountName == "labuser1"
| where TimeGenerated > ago(90d)
| summarize count()
~~~

**Finding:** Successful logon IPs for the lab account were checked and were normal/expected.

~~~kql
DeviceLogonEvents
| where DeviceName == "windows-target-1"
| where LogonType == "Network"
| where ActionType == "LogonSuccess"
| where AccountName == "labuser"
| where TimeGenerated > ago(1000d)
| summarize Logincount = count() by DeviceName, ActionType, AccountName, RemoteIP
~~~

<img width="1125" height="306" alt="532615972-cbb3135f-01f0-4c05-9e97-1e72a9597784" src="https://github.com/user-attachments/assets/345f30be-6e1d-47d2-ab5e-b33e0cf500d7" />

---

## 🧬 MITRE ATT&CK Summary

| Tactic / Category | Technique | MITRE ID | Evidence in This Hunt |
|---|---|---|---|
| Initial Access | External Remote Services | T1133 | System was internet-facing and receiving remote authentication attempts |
| Credential Access | Brute Force | T1110 | High volume of failed logons from multiple external IPs |
| Lateral Movement / Initial Access (attempted) | Remote Services | T1021 | Logon types observed: Network, RemoteInteractive, Interactive, Unlock |
| Persistence / Privilege Escalation (ruled out) | Valid Accounts (NOT observed) | T1078 | Only successful logons were from legitimate account(s) and expected IPs |

---

## 🚩 Flag Analysis

<details>
<summary>🚩 <strong>Flag 1: Internet Exposure Confirmed</strong></summary>

**Objective:** Confirm whether the VM was mistakenly exposed to the public internet.  
**Finding:** `windows-target-1` was internet-facing.  
**Evidence:** `DeviceInfo` showed `IsInternetFacing == 1` with recent timestamps.  
**Why it matters:** Public exposure increases risk of brute force, exploitation, and credential abuse.  

</details>

<details>
<summary>🚩 <strong>Flag 2: Brute-Force Attempts Detected</strong></summary>

**Objective:** Identify malicious login attempts from external sources.  
**Finding:** High volume of failed logons from multiple external IPs.  
**Evidence:** `DeviceLogonEvents` failures across remote/network logon types with non-empty `RemoteIP`.  
**Why it matters:** Consistent with automated brute-force/credential spraying behavior.  

</details>

<details>
<summary>🚩 <strong>Flag 3: Brute-Force Success Ruled Out</strong></summary>

**Objective:** Determine if attackers successfully authenticated.  
**Finding:** No successful logons from the top attacking IPs.  
**Evidence:** `LogonSuccess` query scoped to top IPs returned no results.  
**Why it matters:** Confirms the activity did not progress to authenticated access (based on available telemetry).  

</details>

<details>
<summary>🚩 <strong>Flag 4: Valid Account Abuse Ruled Out</strong></summary>

**Objective:** Verify whether legitimate credentials were compromised.  
**Finding:** Successful logons limited to legitimate account(s) from expected sources.  
**Evidence:** Successful logons were tied to lab account(s); remote IPs were reviewed and deemed normal.  
**Why it matters:** No evidence of credential compromise, persistence, or escalation.  

</details>

---

## 🛡️ Response Actions

- Hardened the NSG attached to `windows-target-1` to allow only RDP traffic from specific approved endpoints (removed broad public exposure)
- Implemented an account lockout policy
- Implemented MFA

---

## 🚨 Detection Gaps & Recommendations

### Observed Gaps
- Misconfigured internet exposure for a VM in shared services
- Lack of account lockout controls increased brute-force feasibility
- MFA not enforced for remote access (increased risk if credentials are guessed/stolen)

### Recommendations
- Implement continuous monitoring/alerts for any VM that becomes internet-facing
- Alert on brute-force indicators (threshold-based failures per IP and per account)
- Require MFA for all remote access / administrative accounts
- Apply conditional access and JIT/JEA principles for admin access where possible
- Consider geo/IP reputation enrichment for RemoteIP to prioritize investigation

---

## 🧾 Final Assessment

`windows-target-1` was unintentionally exposed to the public internet and was actively targeted with brute-force login attempts from multiple external IP addresses. Analysis found **no evidence of successful brute-force compromise** and no indication of unauthorized access via valid accounts based on available logon telemetry. The primary issue was attack surface exposure and missing identity hardening controls, which were addressed through NSG restriction, account lockout policy, and MFA implementation.

---
