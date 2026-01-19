<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/shahm-1/Threat-Hunting-TOR-Usage/blob/main/README.md)

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

##  Scenario

Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

Searched for any file that had the string "tor" in it and discovered what looks like the user "shadow-it" downloaded a TOR installer, did something that resulted in many TOR-related files being copied to the desktop, and the creation of a file called `tor-shopping-list.txt` on the desktop at `2026-01-09T00:25:51.3271069Z`. These events began at `2026-01-09T00:09:32.0673536Z`.

**Query used to locate events:**

```kql
DeviceFileEvents  
| where DeviceName == "threat-hunt-tor"  
| where InitiatingProcessAccountName == "shadow-it"  
| where FileName contains "tor"  
| where Timestamp >= datetime(2026-01-09T00:09:32.0673536Z)  
| order by Timestamp desc  
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName
```

<img width="1551" height="822" alt="533671073-162f4faa-9caf-47d4-a777-c6c83c0c1d42" src="https://github.com/user-attachments/assets/3d46b032-40c4-4733-9575-d5c1faa7481a" />

---

### 2. Searched the `DeviceProcessEvents` Table

Searched for any `ProcessCommandLine` that contained the string "tor-browser-windows-x86_64-portable-15.0.3.exe". Based on the logs returned, at `2026-01-09T00:17:28.8171343Z`, an employee on the "threat-hunt-tor" device ran the file `tor-browser-windows-x86_64-portable-15.0.3.exe` from their Downloads folder, using a command that triggered a silent installation.

**Query used to locate event:**

```kql

DeviceProcessEvents  
| where DeviceName == "threat-hunt-tor"  
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-15.0.3.exe"  
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
```

<img width="1553" height="835" alt="533671110-1ab85697-c24e-46e2-b436-b9214c42f068" src="https://github.com/user-attachments/assets/f7dbfb38-0a86-43ae-8497-fb3646df48b3" />

---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched for any indication that user "shadow-it" actually opened the TOR browser. There was evidence that they did open it at `2026-01-09T00:18:02.8430311Z`. There were several other instances of `firefox.exe` (TOR) as well as `tor.exe` spawned afterwards.

**Query used to locate events:**

```kql
DeviceProcessEvents  
| where DeviceName == "threat-hunt-tor"  
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe")  
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine  
| order by Timestamp desc
```

<img width="1753" height="761" alt="533671150-2b369791-69ac-4db0-9c1e-c6d46b9535db" src="https://github.com/user-attachments/assets/25e56a8e-7def-45e1-969f-ec1552f75ce6" />

---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched for any indication the TOR browser was used to establish a connection using any of the known TOR ports. At `2026-01-09T00:19:08.4732338Z`, an employee on the "threat-hunt-tor" device successfully established a connection to the remote IP address `102.130.113.30` on port `9001`. The connection was initiated by the process `tor.exe`, located in the folder `c:\users\shadow-it\desktop\tor browser\browser\torbrowser\tor\tor.exe`. There were a couple of other connections to sites over port `443`.

**Query used to locate events:**

```kql
DeviceNetworkEvents  
| where DeviceName == "threat-hunt-tor"  
| where InitiatingProcessAccountName != "shadow-it"  
| where InitiatingProcessFileName in ("tor.exe", "firefox.exe")  
| where RemotePort in ("9001", "9030", "9040", "9050", "9051", "9150", "80", "443")  
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessFolderPath  
| order by Timestamp desc
```

<img width="1808" height="803" alt="533671181-8acbf13e-6890-4364-8b1f-ab3eae1bff69" src="https://github.com/user-attachments/assets/29937210-28cf-4a03-936f-8bc1b89145e9" />

---

## Chronological Event Timeline 

### 1. File Download - TOR Installer

- **Timestamp:** `2026-01-09T00:09:32.0673536Z`
- **Event:** The user "shadow-it" downloaded a file named `tor-browser-windows-x86_64-portable-15.0.3.exe` to the Downloads folder.
- **Action:** File download detected.
- **File Path:** `C:\Users\shadow-it\Downloads\tor-browser-windows-x86_64-portable-15.0.3.exe`

### 2. Process Execution - TOR Browser Installation

- **Timestamp:** `2026-01-09T00:17:28.8171343Z`
- **Event:** The user "shadow-it" executed the file `tor-browser-windows-x86_64-portable-15.0.3.exe` in silent mode, initiating a background installation of the TOR Browser.
- **Action:** Process creation detected.
- **Command:** `tor-browser-windows-x86_64-portable-15.0.3.exe /S`
- **File Path:** `C:\Users\shadow-it\Downloads\tor-browser-windows-x86_64-portable-15.0.3.exe`

### 3. Process Execution - TOR Browser Launch

- **Timestamp:** `2026-01-09T00:18:02.8430311Z`
- **Event:** User "shadow-it" opened the TOR browser. Subsequent processes associated with TOR browser, such as `firefox.exe` and `tor.exe`, were also created, indicating that the browser launched successfully.
- **Action:** Process creation of TOR browser-related executables detected.
- **File Path:** `C:\Users\shadow-it\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`

### 4. Network Connection - TOR Network

- **Timestamp:** `2026-01-09T00:19:08.4732338Z`
- **Event:** A network connection to IP `102.130.113.30` on port `9001` by user "shadow-it" was established using `tor.exe`, confirming TOR browser network activity.
- **Action:** Connection success.
- **Process:** `tor.exe`
- **File Path:** `c:\users\shadow-it\desktop\tor browser\browser\torbrowser\tor\tor.exe`

### 5. Additional Network Connections - TOR Browser Activity

- **Timestamps:**
  - `2026-01-09T00:19:06.8672881Z` - Connected to `96.9.98.210` on port `443`.
  - `2026-01-09T00:19:05.3566911Z` - Local connection to `127.0.0.1` on port `9150`.
- **Event:** Additional TOR network connections were established, indicating ongoing activity by user "shadow-it" through the TOR browser.
- **Action:** Multiple successful connections detected.

### 6. File Creation - TOR Shopping List

- **Timestamp:** `2026-01-09T00:25:51.3271069Z`
- **Event:** The user "shadow-it" created a file named `tor-shopping-list.txt` on the desktop, potentially indicating a list or notes related to their TOR browser activities.
- **Action:** File creation detected.
- **File Path:** `C:\Users\shadow-it\Desktop\tor-shopping-list.txt`

---

## Summary

The user "shadow-it" on the "threat-hunt-tor" device initiated and completed the installation of the TOR browser. They proceeded to launch the browser, establish connections within the TOR network, and created various files related to TOR on their desktop, including a file named `tor-shopping-list.txt`. This sequence of activities indicates that the user actively installed, configured, and used the TOR browser, likely for anonymous browsing purposes, with possible documentation in the form of the "shopping list" file.

---

## Response Taken

TOR usage was confirmed on the endpoint `threat-hunt-tor` by the user `shadow-it`. The device was isolated, and the user's direct manager was notified.

---
