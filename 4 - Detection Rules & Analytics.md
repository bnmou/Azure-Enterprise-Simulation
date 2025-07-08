# 🔍 Phase 4 - Detection Rules & Analytics&#x20;

This phase focuses on building detection analytics to identify attacker behaviors simulated in Phase 2. Custom analytic rules were created in Microsoft Sentinel to detect specific techniques across the Cyber Kill Chain. Each rule was validated by generating logs in the client VM, verifying alerts and incidents, and documenting the results.

---

## 🔧 Detection Rules Overview

| Rule Name                                | Description                                                       | TTP ID    | Technique                     | Tactic                |
| ---------------------------------------- | ----------------------------------------------------------------- | --------- | ----------------------------- | --------------------- |
| **Malicious .docm Execution Detection**  | Detects macro-enabled Word documents opened using WINWORD.EXE     | T1566.001 | Spearphishing Attachment      | Initial Access        |
| **Reverse Shell Detection**              | Detects PowerShell reverse shell behavior via obfuscated commands | T1059.001 | PowerShell                    | Command and Control   |
| **LSASS Access**                         | Alerts when LSASS credentials are accessed or dumped              | T1003.001 | LSASS Memory                  | Credential Access     |
| **Suspicious Scheduled Tasks**           | Detects non-Microsoft startup tasks tied to user accounts         | T1053.005 | Scheduled Task                | Persistence           |
| **User Creation + Privilege Escalation** | Flags net user additions followed by admin group assignment       | T1136.001 | Create Account: Local Account | Privilege Escalation  |
| **Data Exfiltration via NGROK**          | Monitors for outbound connections to ngrok tunnels                | T1041     | Exfiltration Over C2 Channel  | Exfiltration          |
| **Advanced Multistage Attack Detection** | Correlation rule from Microsoft Sentinel (Fusion)                 | Multiple  | Multiple Techniques           | Multiple (Correlated) |

📸 *Overview of Detection Rules*
![analytics rules overview](https://github.com/user-attachments/assets/be16ae6c-7900-4bd2-bd45-0b3a86b309ca)

---

## 📜 Detection Queries and Incidents

Each rule below includes the KQL query, a short narrative of how the rule was built, the scan interval used in Sentinel, and associated screenshots:

### 1. **Malicious .docm Execution Detection**

```kql
DeviceProcessEvents
| where InitiatingProcessFileName contains "WINWORD.EXE"
| where FileName == "powershell.exe"
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessFolderPath, InitiatingProcessAccountName, ProcessIntegrityLevel, IsInitiatingProcessRemoteSession
```

- I created a query rule inside Sentinel’s analytics to look for suspicious PowerShell processes spawned from macro-embedded Word documents. This simulated a phishing attack using `.docm` files with embedded scripts.
- **Scan interval:** Every 5 minutes, looking back 1 hour.

📸 *DOCM rule configuration*
![docm rule config](https://github.com/user-attachments/assets/432f75ea-206b-40db-aa57-987184a37c24)

📸 *Confirmation that our rule is configured to alert on powershell activity from docm macros*  
![confirmation that our rule is configured to alert on powershell activity from docm macros](https://github.com/user-attachments/assets/9d8f00a4-d06c-4025-8f1e-8e95147deb08)

📸 *DOCM powershell alerts*
![docm powershell alerts](https://github.com/user-attachments/assets/8ec722be-a610-442f-a4a2-969694986ca4)

---

### 2. **Reverse Shell Detection**

```kql
DeviceProcessEvents
| where FileName == "powershell.exe"
| where ProcessCommandLine has_all ("-nop", "NoProfile", "Hidden", "EncodedCommand")
| where ProcessCommandLine has_any ("Invoke-Expression", "IEX")
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName, ProcessIntegrityLevel
```

- I built this rule to detect obfuscated reverse shell PowerShell commands, often launched with encoded and hidden execution flags from macro payloads or remote execution.
- **Scan interval:** Every 5 minutes, looking back 1 hour.

📸 *Reverse shell rule configuration and confirmation of query*  
![reverse shell rule config and confirmation of query](https://github.com/user-attachments/assets/8c512013-570b-45e4-bd34-c47cfe758734)

📸 *Reverse shell incident created from analytics rule*
![reverse shell incident created from analytics rule](https://github.com/user-attachments/assets/1f957dfc-d5d8-453f-b82d-cb887cec6806)

---

### 3. **LSASS Access**

```kql
DeviceProcessEvents
| where FileName =~ ("procdump.exe", "mimikatz.exe")
  or ProcessCommandLine has_any ("lsass.exe", "comsvcs.dll", "-ma", "dum", "sekurlsa")
| where ProcessCommandLine has "lsass"
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName, ProcessIntegrityLevel
```

- This rule detects common tools and behaviors used to access or dump LSASS memory, a technique attackers use to steal credentials after gaining access (LOLBins).
- **Scan interval:** Every 5 minutes, looking back 1 hour.

📸 *LSASS dump rule configuration and confirmation of query*  
![LSASS dump rule config and confirmation of query](https://github.com/user-attachments/assets/e33ae379-48bb-46b2-b7fb-1056436d7d44)

📸 *LSASS dump incident created*
![Lsass access incident created](https://github.com/user-attachments/assets/2c0f0420-1334-4653-a9ed-01815ca0317a)

---

### 4. **Suspicious Scheduled Tasks (User Associated)**

```kql
DeviceProcessEvents
| where FileName =~ "schtasks.exe"
| where ProcessCommandLine has "/create"
| where InitiatingProcessAccountName !startswith "NT AUTHORITY"
    and InitiatingProcessAccountName !startswith "SYSTEM"
    and InitiatingProcessAccountName !startswith "localService"
    and InitiatingProcessAccountName !startswith "NetworkService"
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName
```

- I designed this rule to find suspicious scheduled tasks being created from user accounts, which could indicate attacker persistence via startup scripts or unauthorized jobs.
- **Scan interval:** Every 5 minutes, looking back 1 hour.

📸 *Scheduled tasks rule configuration and confirmed query run*  
![Scheduled tasks from user accounts that could be suspicious along with a confirmed query run](https://github.com/user-attachments/assets/50eb2660-12de-4944-82b9-1740c94d8938)

📸 *Incident triggered for user created scheduled tasks*
![incident created for user created scheduled task](https://github.com/user-attachments/assets/e96da39c-034b-426c-bed5-174164b2784b)

---

### 5. **User Creation + Immediate Privilege Escalation**

```kql
DeviceProcessEvents
| where ProcessCommandLine has_any ("net user", "net1 user", "/add", "net localgroup administrators")
| project TimeGenerated, AccountName, FileName, ProcessCommandLine, DeviceName
```

- I configured this rule to detect when a new local user is created and then quickly added to the Administrators group—an indicator of privilege escalation.
- **Scan interval:** Every 5 minutes, looking back 1 hour.

📸 *User creation plus immediate privilege escalation rule created with query confirmation*  
📸 *incident created for user creation and immediate priv escalation*

---

### 6. **Data Exfiltration via NGROK**

```kql
DeviceNetworkEvents
| where RemoteUrl contains "ngrok"
| project TimeGenerated, DeviceName, RemoteUrl, InitiatingProcessFileName, InitiatingProcessCommandLine
```

- This detection monitors outbound network connections to ngrok.io, a tunneling tool used by attackers to bypass firewalls and exfiltrate data.
- **Scan interval:** Every 5 minutes, looking back 14 days.

📸 *data exfil via ngrok rule and query confirmation*  
📸 *incident created for NGROK C2 data exfil*

---

## 📊 MITRE ATT&CK Coverage

All detection rules were mapped to ATT&CK TTPs and visualized in Microsoft Sentinel’s **MITRE ATT&CK Preview** blade.

📸 *These are the MITRE TTPs we have covered with our analytic rules*

**Mapped Coverage Includes:**

- Initial Access → T1566.001: Phishing (Attachment)
- Execution → T1059.001: Command and Scripting Interpreter (PowerShell)
- Persistence → T1053.005: Scheduled Task/Job, T1136.001: Create Account
- Privilege Escalation → T1136.001: Create Account
- Credential Access → T1003.001: OS Credential Dumping
- Discovery → T1069.001: Permission Groups Discovery
- C2 → T1071.001: Application Layer Protocol
- Exfiltration → T1041: Exfiltration Over C2 Channel

---

## ✅ Status

Phase 4 is complete. All detections successfully generated alerts and incidents, and each query was tested against real attacker telemetry simulated in Phase 2.

Next step: Begin Phase 5 (Incident Response Playbooks).

