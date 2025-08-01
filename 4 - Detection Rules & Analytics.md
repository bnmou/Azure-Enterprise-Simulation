# 🔍 Phase 4 - Detection Rules & Analytics&#x20;

This phase focuses on building detection analytics to identify attacker behaviors simulated in Phase 2. Custom analytic rules were created in Microsoft Sentinel to detect specific techniques across the Cyber Kill Chain. Each rule was validated by generating logs in the client VM, verifying alerts and incidents, documenting the results and mapping entities for Phase 5.

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

*Initial thresholds may yield noise and will be optimized in Phase 8*

---

### 1. **Malicious .docm Execution Detection**

```kql
DeviceProcessEvents
| where InitiatingProcessFileName contains "WINWORD.EXE"
| where FileName == "powershell.exe"
| project TimeGenerated,
  DeviceName,
  AccountName,
  FileName,
  ProcessCommandLine,
  InitiatingProcessFileName,
  InitiatingProcessCommandLine,
  InitiatingProcessFolderPath,
  InitiatingProcessAccountName,
  ProcessIntegrityLevel,
  IsInitiatingProcessRemoteSession,
  SHA256,
  DeviceId
```

- I created a query rule inside Sentinel’s analytics to look for suspicious PowerShell processes spawned from macro-embedded Word documents. The query looks for processes integral to our investigation into this type of event such as command lines, folder paths, SHA256 hashes, filenames, and the DeviceID which will be helpful when mapping entities to logic-apps in Phase 5. This simulated a phishing attack using `.docm` files with embedded scripts.
- **Scan interval:** Every 5 minutes, looking back 1 hour. This short interval ensures quick detection of macro-triggered post-exploitation activity while allowing enough data lookback for context.

📸 *DOCM rule config (Using CustomLogs table for organizational purposes)*
<img width="1912" height="962" alt="image" src="https://github.com/user-attachments/assets/34f6ddf1-35a7-4a71-8378-2b44fa9c6a7f" />

📸 *Entity Mapping*    
<img width="683" height="632" alt="image" src="https://github.com/user-attachments/assets/793482df-2279-4a41-9001-0da7edccd0e6" />

📸 *Confirmation that our rule is configured to alert on powershell activity from docm macros*  
![confirmation that our rule is configured to alert on powershell activity from docm macros](https://github.com/user-attachments/assets/9d8f00a4-d06c-4025-8f1e-8e95147deb08)

---

### 2. **Reverse Shell Detection**

```kql
DeviceProcessEvents
| where FileName =~ "powershell.exe"
| where ProcessCommandLine has_any ("-nop", "NoProfile", "Hidden", "EncodedCommand")
| where ProcessCommandLine has "invoke-expression"
| project TimeGenerated,
  DeviceName,
  AccountName,
  FileName,
  ProcessCommandLine,
  InitiatingProcessFileName,
  InitiatingProcessCommandLine,
  InitiatingProcessAccountName,
  ProcessIntegrityLevel,
  DeviceId
```

- I built this rule to detect obfuscated reverse shell PowerShell commands, often launched with encoded and hidden execution flags from macro payloads or remote execution.
- **Scan interval:** Every 5 minutes, looking back 1 hour. This balance helps detect quick C2 channel behavior while limiting noise from benign PowerShell use.

📸 *Reverse shell rule config (Using CustomLogs table for organizational purposes)*  
<img width="1912" height="962" alt="image" src="https://github.com/user-attachments/assets/44dfc332-1d24-4600-9e34-bac12d30977c" />

📸 *Entity Mapping*  
<img width="698" height="649" alt="image" src="https://github.com/user-attachments/assets/8c03b77c-f343-4a14-afc0-3125a15ed8dc" />

📸 *Reverse shell incident created from analytics rule*
![reverse shell incident created from analytics rule](https://github.com/user-attachments/assets/1f957dfc-d5d8-453f-b82d-cb887cec6806)

---

### 3. **LSASS Access**

```kql
DeviceProcessEvents
| where FileName =~ ("procdump.exe" "mimikatz.exe")
  or ProcessCommandLine has_any ("lsass.exe", "comsvcs.dll", "-ma", "dum", "sekurlsa")
| where ProcessCommandLine has "lsass"
| project TimeGenerated,
  DeviceName,
  AccountName,
  FileName,
  ProcessCommandLine,
  InitiatingProcessFileName,
  InitiatingProcessCommandLine,
  InitiatingProcessAccountName,
  ProcessIntegrityLevel,
  DeviceId
```

- This rule detects common tools and behaviors used to access or dump LSASS memory, a technique attackers use to steal credentials after gaining access (LOLBins).
- **Scan interval:** Every 5 minutes, looking back 1 hour. A short scan interval helps catch credential theft attempts in near real-time for quick containment procedures.

📸 *LSASS dump rule config (Using CustomLogs table for organizational purposes)*  
<img width="1912" height="962" alt="image" src="https://github.com/user-attachments/assets/3f445469-2513-4bab-8ec6-0a6848579df9" />

📸 *Entity Mapping*  
<img width="685" height="631" alt="image" src="https://github.com/user-attachments/assets/5c443f8d-f272-45c4-a907-fb3c0eb0a449" />

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
| project TimeGenerated,
  DeviceName,
  AccountName,
  FileName,
  ProcessCommandLine,
  InitiatingProcessFileName,
  InitiatingProcessCommandLine,
  InitiatingProcessAccountName,
  DeviceId
```

- I designed this rule to find suspicious scheduled tasks being created from user accounts, which could indicate attacker persistence via startup scripts or unauthorized jobs.
- **Scan interval:** Every 2 hours, looking back 4 hours. This catches unauthorized persistence attempts while reducing processing overhead.

📸 *Scheduled tasks rule config (Using CustomLogs table for organizational purposes)*  
<img width="1912" height="962" alt="image" src="https://github.com/user-attachments/assets/b68e773f-bee2-4616-80ab-611b1e800950" />

📸 *Entity Mapping*  
<img width="712" height="636" alt="image" src="https://github.com/user-attachments/assets/9ee0bacb-d1ca-422b-b82b-7814c1dd85fd" />

📸 *Incident triggered for user created scheduled tasks*
![incident created for user created scheduled task](https://github.com/user-attachments/assets/e96da39c-034b-426c-bed5-174164b2784b)

---

### 5. **User Creation + Immediate Privilege Escalation**

```kql
DeviceProcessEvents
| where ProcessCommandLine has_any ("net user", "net1 user", "/add", "net localgroup administrators")
| extend CreatedUser = extract(@"(?:net1?|net\.exe)\s+user\s+(\S+)", 1, ProcessCommandLine)
| project TimeGenerated, 
  AccountName,
  DeviceName,
  CreatedUser,
  FileName, 
  ProcessCommandLine,
  DeviceId
| order by TimeGenerated desc
```

- I configured this rule to detect when a new local user is created and then quickly added to the Administrators group—an indicator of privilege escalation. This query also extracts newly created usernames for easier entity mapping & identification.
- **Scan interval:** Every 5 minutes, looking back 1 hour. This allows the rule to catch quick post-exploitation privilege escalations.

📸 *User creation plus immediate privilege escalation config (Using CustomLogs table for organizational purposes)*  
<img width="1912" height="962" alt="image" src="https://github.com/user-attachments/assets/2e4e649e-9e5e-424a-8289-ace4ed82746c" />

📸 *Entity Mapping*  
<img width="699" height="544" alt="image" src="https://github.com/user-attachments/assets/2a5f9c68-4eb7-40be-b550-0137707c7180" />

📸 *Incident created for user creation and immediate privilege escalation*
![incident created for user creation and immediate priv escalation](https://github.com/user-attachments/assets/d8bfcdef-3f22-42ee-9308-13013a2ea12e)

---

### 6. **Data Exfiltration via NGROK**

```kql
DeviceNetworkEvents
| where RemoteUrl has_any ("ngrok", ".ngrok-free.app")
| where InitiatingProcessFileName in~ ("powershell.exe", "curl.exe", "wget.exe")
| project TimeGenerated,
  DeviceName,
  RemoteUrl,
  InitiatingProcessFileName,
  InitiatingProcessCommandLine,
  DeviceId
```

- This detection monitors outbound network connections to ngrok.io, a tunneling tool abused by attackers to bypass firewalls and exfiltrate data.
- **Scan interval:** Every 1 hour, looking back 14 days. Longer lookback ensures deep catch of any beaconing behavior from tunneling tools.

📸 *Data exfil via ngrok config (Using CustomLogs table for organizational purposes)*  
<img width="1912" height="962" alt="image" src="https://github.com/user-attachments/assets/ae89e8b0-8305-49c9-8c72-e10c9dda585f" />

📸 *Entity Mapping*  
<img width="635" height="637" alt="image" src="https://github.com/user-attachments/assets/951a8d1c-457e-4ca5-8f86-f8d60a471cb7" />

📸 *Incident created for NGROK C2 data exfil*
![incident created for NGROK C2 data exfil](https://github.com/user-attachments/assets/a676b428-9530-4735-a6f5-4371b2e0f524)

---

## 📊 MITRE ATT&CK Coverage

All detection rules were mapped to ATT&CK TTPs and visualized in Microsoft Sentinel’s **MITRE ATT&CK Preview** blade.

📸 *These are the MITRE TTPs we have covered with our analytic rules*
![These are the MITRE TTPs we have covered with our analytic rules](https://github.com/user-attachments/assets/9871605e-a11f-473e-b2a9-927afb4d6944)

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

---

**Next Phase:** [Phase 5 – SOAR Automation](https://github.com/bnmou/Azure-Enterprise-Simulation/blob/main/5%20-%20SOAR%20Automation.md)
