# 🚨 Incident Response: Brute-Force Attack Detection & Investigation (NIST 800-61)

*End-to-end investigation of brute-force login attempts against Azure virtual machines using Microsoft Sentinel, Microsoft Defender for Endpoint, and KQL, aligned to the NIST 800-61 incident response lifecycle.*


<img width="1536" height="1024" alt="image" src="https://github.com/user-attachments/assets/02310890-377f-4b1e-afa5-9864319ac1c3" />

---

## 📌 Scenario Context

As a security analyst for a large organization relying heavily on Microsoft Azure services, I observed multiple failed login attempts, particularly targeting privileged accounts during off-hours. This raises concerns about a brute-force attack or a credential-stuffing campaign.

This lab documents the investigation and response following the **NIST 800-61 Incident Response Framework**.

---

## 🛠️ Platforms & Tools

- Microsoft Defender for Endpoint  
- Microsoft Azure Virtual Machines  
- Microsoft Sentinel / Log Analytics  
- Kusto Query Language (KQL)  

---

# 🔁 NIST SP 800-61 Incident Response Lifecycle

---

## 1️⃣ Preparation

1. **Policies and Procedures:**
   - Establish protocols for handling brute-force attempts, account lockouts, and account recovery.
   - Include predefined actions for notifications, account lockdowns, and reporting suspicious activity.

2. **Access Control and Logging:**
   - Enable logging of all login attempts across Azure AD.
   - Integrate with **Microsoft Defender for Identity** and **Azure Sentinel** for automated detection and alerts.

3. **Training:**
   - Train the security team to handle credential-based attacks, including brute force and credential stuffing.

4. **Communication Plan:**
   - Create an escalation plan for IT support and privileged account holders during incidents.


---

## 2️⃣ Detection & Analysis

### 🔍 Initial Detection

Repeated failed logon events were observed in MDE originating from multiple public IP addresses.

~~~kql
DeviceLogonEvents
|where ActionType == "LogonFailed"
|where TimeGenerated > ago(5h)
|summarize NumberOfFailures = count() by RemoteIP, ActionType, DeviceName
|where NumberOfFailures > 35
|order by NumberOfFailures desc
~~~

<img width="883" height="484" alt="image" src="https://github.com/user-attachments/assets/3970c16c-8fd2-499c-b749-ba16b3ce6ee7" />

### 📊 Affected Systems & Indicators

| Source IP        | Target Machine                                                   | ActionType  | Failed Attempts |
|------------------|------------------------------------------------------------------|-------------|-----------------|
| 37.187.24.235    | chi-chi-vm                                                       | LogonFailed | 67              |
| 141.98.11.190    | daes-vm-final-l                                                  | LogonFailed | 40              |
| 112.199.44.195   | daes-vm-final-l                                                  | LogonFailed | 39              |
| 218.145.181.48   | linuxvm--cd.p2zfvso05mlezjev3ck4vqd3kd.cx.internal.cloudapp.net  | LogonFailed | 45              |


<img width="428" height="641" alt="Alert Triggered-Incident Created-AssignOwner-StatusActive" src="https://github.com/user-attachments/assets/ba1a6d14-7ad3-4418-84be-6aa54985e5e7" />

This triggered an Incident alert that I created in Sentinel through a Scheduled Rule accompanied by the associated MITRE ATT&CK TTP'S.

---

<img width="1520" height="868" alt="Investigation" src="https://github.com/user-attachments/assets/7b58358a-8e98-4f9f-8d47-6e19068b6b2b" />

The activity pattern was consistent with automated brute-force attempts.

---

### 🧠 Investigation & Validation

The following KQL query was used to determine whether any attempts were successful:

~~~kql
DeviceLogonEvents
| where RemoteIP in ("218.145.181.48", "141.98.11.190", "185.156.73.74", "112.199.44.195")
| where ActionType != "LogonFailed"
~~~

## ✅ Results

No successful authentication events were identified from the suspicious IP addresses.

<img width="1211" height="549" alt="No Succesful Logins" src="https://github.com/user-attachments/assets/e0665d4e-dc90-4fe5-b3fe-fd9c20d21f0f" />

This confirmed the incident as a **failed brute-force attack with no evidence of compromise**.

---

## 📌 Analysis Conclusion

- Multiple public IPs targeting exposed systems  
- High-volume failed authentication attempts  
- No confirmed unauthorized access  
- Clear perimeter exposure risk  

---

## 3️⃣ Containment

Immediate containment actions were taken to prevent continued attack attempts and reduce system exposure.

### 🔐 Containment Actions

- Isolated all affected devices using **Microsoft Defender for Endpoint**  
- Ran full **antimalware scans** on each system  
- Hardened **Network Security Groups (NSGs)**:
  - Removed public RDP access  
  - Restricted inbound access to a trusted IP  
  - Recommended **Azure Bastion** for secure administration

<img width="560" height="663" alt="Isolate the Devices" src="https://github.com/user-attachments/assets/86000abb-5d73-48b1-ac7d-7c4c47d39c56" />

---

<img width="659" height="867" alt="Only Allow RDP connection with specific source IP" src="https://github.com/user-attachments/assets/2169fad2-f41c-4735-8429-5e5272fada6c" />



These actions immediately stopped external brute-force attempts.


---

## 4️⃣ Eradication

Although no compromise was identified, eradication actions focused on eliminating the attack vector.

### 🧹 Eradication Actions

- Verified antimalware scans returned clean results  
- Removed all unnecessary inbound NSG rules  
- Reviewed systems for persistence mechanisms  
- Confirmed no additional indicators of compromise  

---

## 5️⃣ Recovery

Systems were safely returned to normal operation.

### 🔄 Recovery Actions

- Released devices from isolation after validation  
- Continued monitoring authentication telemetry  
- Validated normal login behavior  
- Ensured hardened NSG rules remained enforced  

---

## 6️⃣ Post-Incident Activity

### 📘 Lessons Learned

- Publicly exposed VMs are frequent brute-force targets  
- Network-level controls are critical preventative defenses  
- Early validation prevents unnecessary escalation  

---

### 🏗️ Improvements & Recommendations

- Implement corporate policy prohibiting public RDP exposure  
- Enforce Azure Bastion or IP allow-listing  
- Enable MFA for all administrative access  
- Deploy Sentinel analytics rules for brute-force detection  

---

### 🗂️ Documentation

- Indicators of attack recorded  
- Queries preserved  
- Response actions documented  
- Preventative recommendations submitted  

---

## 🚫 Incident Outcome

- ✔️ Brute-force activity detected  
- ✔️ No successful compromise  
- ✔️ Devices isolated and validated clean  
- ✔️ Network exposure remediated  
- ✔️ Preventative controls proposed  

---

## 🎯 Skills Demonstrated

- Incident triage and analysis  
- KQL threat investigation  
- Microsoft Defender for Endpoint response  
- Cloud network containment  
- NIST 800-61 incident handling  
- Security documentation and reporting 
