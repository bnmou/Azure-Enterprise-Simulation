# 🛰 Phase 6: Threat Hunting

## 📌 Table of Contents
1. [Live Threat Intelligence Feed (OTX Integration)](#1-live-threat-intelligence-feed-otx-integration)
2. [SQR3 Hypothesis Framework](#2-sqr3-hypothesis-framework)
3. [KQL Hunting Queries & Results](#3-kql-hunting-queries--results)
4. [Chronological Timeline of Attacker Actions](#4-chronological-timeline-of-attacker-actions)
5. [Correlation Analysis](#5-correlation-analysis)
6. [IOC Table](#6-ioc-table)
7. [Global Threat Map (Honeypot Integration)](#7-global-threat-map-honeypot-integration)
8. [Final Containment & Remediation Actions](#8-final-containment--remediation-actions)

---

## 🛰 1. Live Threat Intelligence Feed (OTX Integration)

**Objective**  
Automate ingestion of **subscribed AlienVault OTX pulse indicators** into Microsoft Sentinel to enhance threat hunting with up-to-date IOCs.

**Implementation**
- Logic App calls OTX `/pulses/subscribed`.
- Filters **IPv4**, **domain**, **URL**, and **hash** indicators.
- Tags each IOC with `"OTX"` and the **pulse name**.
- Deduplicates before ingestion into `ThreatIntelligenceIndicator`.

<details>
<summary><strong>📷 Screenshot References</strong></summary>

- `otx_logic_app_workflow.png`  
- `otx_api_connection_settings.png`  
- `otx_ingestion_results.png`
</details>

<details>
<summary><strong>🧠 Notes & Design Choices</strong></summary>

- Favor REST API for full control over filtering, tagging, and deduplication.  
- Post to `ThreatIntelligenceIndicator` with standardized `Tags: ["OTX", "<PulseName>"]`.  
- Add a **source reliability** tag (e.g., `Confidence=Medium`) for downstream analytics.
</details>

---

## 🔍 2. SQR3 Hypothesis Framework

**Hypothesis**  
If the `JOKER` account is active, it may engage in **privilege abuse**, **defense evasion**, **persistence**, **credential access**, or **data exfiltration**.

**Scope (last 7 days)**  
Hunt in: `DeviceLogonEvents`, `DeviceProcessEvents`, `DeviceFileEvents`, `DeviceRegistryEvents`.

**Key Questions**
1. Unexpected logons or lateral movement?  
2. Suspicious binaries/scripts executed (LoLBins, credential tools)?  
3. System/registry configuration changes?  
4. Sensitive file access or new administrative accounts?

**Refine**  
If hits appear (e.g., LSASS dump tools, `net user`), **pivot** into device timeline and correlate with firewall/process activity.

**Results**  
Summarize Joker’s actions **chronologically**, map to **MITRE ATT&CK**, and propose **detections**.

<details>
<summary><strong>🧭 SQR3 (State–Question–Refine–Review–Report) Checklist</strong></summary>

- **State:** Environment posture, account role, assets in scope.  
- **Question:** The 4 questions above + look-back window justifications.  
- **Refine:** Narrow on suspicious IPs, toolchains, or time windows.  
- **Review:** Cross-account patterning, shared infrastructure, repeated TTPs.  
- **Report:** Timeline + ATT&CK mapping + recommendations (detections, SOAR).
</details>

---

## 🖥 3. KQL Hunting Queries & Results

> **Time Range:** All queries executed with `TimeGenerated >= ago(7d)`.

### 🔎 Overview
We began with logon reconnaissance, pivoted into process execution (persistence & defense evasion), then validated file/registry tampering.

---

<details>
<summary><strong>🔍 Query 1 – DeviceLogonEvents (Initial Access & Privilege Misuse)</strong></summary>

```kql
DeviceLogonEvents
| where AccountName contains "Joker"
| project TimeGenerated, DeviceName, ActionType, LogonType, RemoteIP, AccountDomain, AccountName, AccountSid, ReportId
| order by TimeGenerated desc
```

**Findings**
- Multiple logons from **unusual remote IP**: `99.157.17.206` (masked in screenshots for privacy).

**MITRE TTPs**
- `T1078` – Valid Accounts  
- `T1078.003` – Valid Accounts: Local Accounts  
- `T1136` – Create Account  
- `T1136.001` – Create Account: Local Account  
- `T0859` – Access Tokens *(token-oriented misuse during sessions)*

**Screenshots**
- `first threat hunting query looking for login instances of Joker with entity mapping.png`  
- `results of first query.png`  
- `results of first query continued with IP not shown for privacy reasons.png`  
- `first query type of data we are interested in like the remote IP account name login type and time and the device.png`
</details>

---

<details>
<summary><strong>🔍 Query 2 – DeviceProcessEvents (Persistence, Defense Evasion, LOLBins)</strong></summary>

```kql
DeviceProcessEvents
| where AccountName contains "Joker" or InitiatingProcessAccountName contains "joker"
| project TimeGenerated, DeviceName, FileName, FolderPath, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, AccountName, InitiatingProcessAccountName
| order by TimeGenerated desc
```

**Findings**
- Malicious scheduled tasks: **JokerHeartbeat**, **JokerTask**  
- Backdoor service creation: `sc.exe` (**BackdoorSvc**)  
- Firewall rule manipulation: `netsh.exe`  
- LOLBins abused: `regsvr32.exe`, `mshta.exe`  
- Registry persistence activity: `reg.exe`

**Key IOCs (Commands)**
```
schtasks.exe /create /sc minute /mo 1 /tn JokerHeartbeat /tr "calc.exe"
schtasks.exe /create /sc once /tn JokerTask /tr "notepad.exe" /st 00:00
sc.exe create BackdoorSvc binPath= "cmd.exe /c calc.exe"
netsh.exe advfirewall firewall add rule name="JokerRule" dir=in action=allow program="C:\Windows\System32\notepad.exe" enable=yes
mshta.exe vbscript:Execute "CreateObject(""Wscript.Shell"").Run ""calc.exe"""
regsvr32.exe /s /u /i:calc scrobj.dll
```

**MITRE TTPs**
- `T1053` – Scheduled Task/Job  
- `T1543` – Create or Modify System Process (Service)  
- `T1562` – Impair Defenses (firewall rules)  
- `T1218` – Signed Binary Proxy Execution (mshta, regsvr32)  
- `T1112` – Modify Registry  
- `T0863` – Abuse Elevation Control Mechanism *(if UAC bypass attempted)*

**Screenshots**
- `second threat hunting query looking for process file events created by Joker.png`  
- `second query persistance with scheduled task.png`  
- `second query another scheduled task to run malicous Joker Task.png`  
- `second query backdoor service creation for persistance.png`  
- `second query LOLBin being used to masquerade a service.png`  
- `second query suspicious folder path as legitimate windows process svchost is being run from temp folder .png`
</details>

---

<details>
<summary><strong>🔍 Query 3 – DeviceFileEvents (File Staging / Exfil)</strong></summary>

> Result: **No malicious file tampering or unusual activity detected.**

```kql
DeviceFileEvents
| where AccountName contains "Joker"
| project TimeGenerated, DeviceName, ActionType, FileName, FolderPath, SHA256, InitiatingProcessFileName, InitiatingProcessCommandLine, AccountName
| order by TimeGenerated desc
```

**MITRE TTPs (monitored)**
- `T1420` – File and Directory Discovery  
- `T1074` – Data Staged  
- `T1041` – Exfiltration Over C2  
- `T0893` – Archive Collected Data

**Screenshot**
- `third query after a thorough analysis we found no malicious tampering with any files belonging to wayne enterprises and no unusual activity outside of normal system processes.png`
</details>

---

<details>
<summary><strong>🔍 Query 4 – DeviceRegistryEvents (Registry Persistence)</strong></summary>

> Result: **No suspicious registry changes detected.**

```kql
DeviceRegistryEvents
| where AccountName contains "Joker"
   or InitiatingProcessAccountName contains "Joker"
| project TimeGenerated, DeviceName, ActionType, RegistryKey, RegistryValueName, PreviousRegistryValueData, RegistryValueData, InitiatingProcessFileName, InitiatingProcessCommandLine, AccountName
| order by TimeGenerated desc
```

**MITRE TTPs (monitored)**
- `T1547` – Boot or Logon Autostart Execution  
- `T1112` – Modify Registry

**Screenshots**
- `fourth query looking for changes made to the registry by Joker.png`  
- `fourth query results.png`  
- `fourth query shows no signs of registry changes.png`
</details>

---

## 📆 4. Chronological Timeline of Attacker Actions

1. **External IP logon** → `T1078` (Valid Accounts)  
2. **Create Scheduled Task** `JokerHeartbeat` → `T1053`  
3. **Delete Outlook Add-in DLL** via `cmd.exe` → `T1070` (Indicator Removal on Host)  
4. **Create BackdoorSvc** → `T1543` (Create/Modify System Process)  
5. **Add firewall allow rule** for `notepad.exe` → `T1562` (Impair Defenses)  
6. **Execute calc.exe** via `mshta.exe` & `regsvr32.exe` → `T1218` (Signed Binary Proxy Execution)  
7. **Create Scheduled Task** `JokerTask` → `T1053`  
8. **Run `whoami.exe /fqdn`** → `T1087` (Account Discovery)

<details>
<summary><strong>🗺️ Evidence Links (Screenshots)</strong></summary>

Cross-reference the screenshots in Sections 3.1–3.4 for each timeline step.  
Where IPs appear, they are masked in the public repo screenshots for privacy.
</details>

---

## 🔗 5. Correlation Analysis

- **Logons → Processes:** Linked Joker’s remote logons to subsequent **scheduled task creation** and **service creation**.  
- **Process → Firewall:** Correlated `sc.exe`/`schtasks.exe` activity with `netsh.exe` changes (defense evasion).  
- **Gaps:** No corroborated **file staging** or **registry** persistence in this period.  
- **Assessment:** Activity indicates **persistence attempts** and **defense evasion** rather than data theft.

<details>
<summary><strong>🧩 Analyst Notes</strong></summary>

- The combination of scheduled tasks and service creation is a classic persistence chain.  
- The use of `mshta` and `regsvr32` suggests living-off-the-land execution to evade detection.  
- Lack of file/registry artifacts could indicate **trial-and-error** staging or **cleanup**.
</details>

---

## 📑 6. IOC Table

| IOC | Type | Description | Source Query | MITRE TTP |
|---|---|---|---|---|
| JokerHeartbeat | Scheduled Task | Persistence mechanism | ProcessEvents | T1053 |
| JokerTask | Scheduled Task | Executes notepad.exe | ProcessEvents | T1053 |
| HKCU\Software\Joker | Registry Key | Custom persistence key | ProcessEvents | T1547 |
| BackdoorSvc | Service | Backdoor service executing calc.exe | ProcessEvents | T1543 |
| `netsh.exe advfirewall ...` | Command | Allows inbound Notepad | ProcessEvents | T1562 |
| mshta.exe vbscript execution | LOLBin Abuse | Executes calc.exe | ProcessEvents | T1218 |
| regsvr32.exe /i:calc scrobj.dll | LOLBin Abuse | Executes calc.exe | ProcessEvents | T1218 |
| whoami.exe /fqdn | Recon | Enumerates domain FQDN | ProcessEvents | T1087 |
| 99.000.00.206 | IP Address | External logon source | LogonEvents | T1078 |

```
IOC,Type,Description,Source Query,MITRE TTP
JokerHeartbeat,Scheduled Task,Persistence mechanism,ProcessEvents,T1053
JokerTask,Scheduled Task,Executes notepad.exe,ProcessEvents,T1053
HKCU\Software\Joker,Registry Key,Custom persistence key,ProcessEvents,T1547
BackdoorSvc,Service,Backdoor service executing calc.exe,ProcessEvents,T1543
netsh.exe advfirewall ...,Command,Allows inbound Notepad,ProcessEvents,T1562
mshta.exe vbscript execution,LOLBin Abuse,Executes calc.exe,ProcessEvents,T1218
regsvr32.exe /i:calc scrobj.dll,LOLBin Abuse,Executes calc.exe,ProcessEvents,T1218
whoami.exe /fqdn,Recon,Enumerates domain FQDN,ProcessEvents,T1087
99.157.17.206,IP Address,External logon source,LogonEvents,T1078
```
</details>

---

## 🌍 7. Global Threat Map (Honeypot Integration)

**Objective**  
Visualize **live malicious activity** targeting our honeypot to correlate external attacker IPs with exploitation patterns and enrich hunts with **geo context**.

**Implementation Steps**
1. **Honeypot Deployment & Capture** – Collect unsolicited inbound connection attempts.  
2. **Export Attacker IPs** – CSV of observed IPs.  
3. **Sentinel Watchlist** – Create `HoneypotIPs` and upload **55k+ IPs**.  
4. **Workbook Query** – Geolocate and plot IPs for a **real-time attack map**.

**Sample KQL (Workbook)**
```kql
let HoneypotIPs = (_GetWatchlist('HoneypotIPs') | project SearchKey);
Heartbeat
| where RemoteIP in (HoneypotIPs)
| extend GeoInfo = geo_info_from_ip_address(RemoteIP)
| summarize AttemptCount = count() by tostring(GeoInfo.Country), tostring(GeoInfo.City), bin(TimeGenerated, 1h)
| project TimeGenerated, Country=GeoInfo.Country, City=GeoInfo.City, AttemptCount
```

<details>
<summary><strong>📷 Screenshot References</strong></summary>

- `We will now create a watchlist for IPs we have recorded from one of our honeypots to create an attack map.png`  
- `overview of the IPs we imported from our honeypot.png`  
- `Final overview of watchlist creation.png`  
- `HoneypotIPs added and uploaded to watchlist with 55k results.png`  
- `Query for our live attack map workbook referencing our honeypot attacker data csv.png`  
- `we now have a fully functional and live attack map referencing our honeypot data.png`
</details>

<details>
<summary><strong>🛠️ Notes</strong></summary>

- Ensure watchlist column used in `project SearchKey` matches your CSV header.  
- If your telemetry table differs from `Heartbeat`, adjust the `where` clause to the table that contains `RemoteIP`.
</details>

---

## 🛡 8. Final Containment & Remediation Actions

- **Disable** `JOKER` account in **Active Directory**.  
- **Revoke** all active sessions and tokens.  
- **Force** 20-character complex password reset.  
- **Isolate** affected endpoints for **forensics**.  
- **Create** Sentinel detection rule for any `"joker"` account activity.

<details>
<summary><strong>💡 Detection Suggestion (KQL stub)</strong></summary>

```kql
union isfuzzy=true
    DeviceLogonEvents,
    DeviceProcessEvents,
    DeviceRegistryEvents,
    DeviceFileEvents
| where AccountName =~ "joker" or InitiatingProcessAccountName =~ "joker"
| summarize Count = count(), FirstSeen=min(TimeGenerated), LastSeen=max(TimeGenerated) by AccountName, DeviceName
| where Count > 0
```
Use as an **analytics rule** (scheduled) with appropriate entity mapping and suppression logic.
</details>

---

### ✅ Outcome
- Confirmed **persistence & defense evasion** attempts by `JOKER`.  
- No confirmed **file staging** or **registry** persistence within the window.  
- Hardened account controls and established **detections** for rapid response.

