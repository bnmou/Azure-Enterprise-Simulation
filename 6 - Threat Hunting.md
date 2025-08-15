# 🛰 Phase 6: Threat Hunting

## ✅ Objectives

1. Build and automate a **Live Threat Intelligence Feed** from AlienVault OTX into Microsoft Sentinel.

2. Apply the **SQR3 Hypothesis Framework** (State, Question, Refine, Review, Report) to hunt the `JOKER` account.

3. Run multiple **KQL hunting queries** for logons, processes, file activity, and registry changes.

4. Create a **chronological timeline** of attacker actions.

5. Perform **correlation analysis** between events.

6. Compile a comprehensive **IOC table** with all commands, IPs, registry keys, and scheduled tasks.

7. Deploy a **Global Threat Map** using honeypot data.

8. Execute **final containment and remediation actions**.

---

## 🛰 1. Live Threat Intelligence Feed (OTX Integration)

**Objective**  
Automate ingestion of **subscribed AlienVault OTX pulse indicators** into Microsoft Sentinel to enhance threat hunting with up-to-date IOCs.

**Implementation**
- Logic App calls OTX `/pulses/subscribed`.
- Filters **IPv4**, **domain**, **URL**, **hostname**, and **hash** indicators.
- Tags each IOC with `"OTX"` and the **pulse name**.
- Deduplicates before ingestion into `ThreatIntelligenceIndicator`.

<details>
<summary><strong>📷 Screenshot References</strong></summary>

- Example of subscribed pulses we will be using
  <img width="1920" height="925" alt="Using OTX Alienvault for our live threat feed pulse with a view of our subscribed pulses using a select few to avoid too many IOCs" src="https://github.com/user-attachments/assets/853b0d05-bc73-4f22-8e81-355e7fd8e228" />

- Overview of our OTX Logic App
  <img width="1912" height="962" alt="calling our OTX API to ingest our subscribed pulses and their IOCs into sentinel with full customization of what gets ingested" src="https://github.com/user-attachments/assets/5e0e7082-1ca7-4f4f-8c53-da08568a79f3" />

- Live feed from our pulses will be updated daily
  
  <img width="559" height="305" alt="recurrence is set to once per day for the pulse scan" src="https://github.com/user-attachments/assets/95aa0815-4a05-4144-abe6-15a47c946d67" />

- Calling our authentication token to reference necessary permissions from Microsoft Graph Audience
  <img width="561" height="662" alt="getting auth token and calling to Microsoft Graph audience so we can write our IOCs to Threat Intelligence" src="https://github.com/user-attachments/assets/f680c833-f088-4076-b2a9-dc41da95e808" />

- HTTP Request to our OTX API token
  
  <img width="569" height="474" alt="HTTP Get request to our OTX token" src="https://github.com/user-attachments/assets/52f5720a-7f24-4f66-82b7-e1c639e4dc42" />

- Parsing our IOCs
  
  <img width="565" height="805" alt="Parse JSON step for our IOCs" src="https://github.com/user-attachments/assets/eb75deea-2526-4f0b-a856-707aab474576" />

- Selecting distinct key steps
  
  <img width="559" height="343" alt="Select to keys step " src="https://github.com/user-attachments/assets/3fb7340a-520e-4f7d-9c2b-828812d2b9eb" />
  <img width="563" height="274" alt="Distinct keys step" src="https://github.com/user-attachments/assets/5064c901-26b7-4cf2-b0d4-5c6a6f2645a3" />

- For each loop that repeats for hostname, IPv4, domain, URL, and hash IOCs
  <img width="565" height="807" alt="for each loop code view which repeats for hostname IP Hash etc" src="https://github.com/user-attachments/assets/f6a949a9-6f46-45b4-9d20-e9c87928b3bd" />

- Switch step that repeats for hostname, IPv4, domain, URL, and hash IOCs
  <img width="563" height="803" alt="Switch step using same format that repeats for the Domain IP hash etc" src="https://github.com/user-attachments/assets/17285da3-c5cc-4846-a7a4-40ae00577a03" />

- Overview of switch step across all IOCs
  <img width="1664" height="570" alt="switch step that then grabs indicators of different types from our pulse" src="https://github.com/user-attachments/assets/ba96a4df-1654-4d0b-a01c-023d16c2a94f" />

- Within the switch step are various HTTP requests to post each of the hostname, IPv4, domain, URL, and hash IOCs
  <img width="563" height="809" alt="example of one of the HTTP Post Graph steps for the IP IOCs with the same exact format replicated for the URL domain host and hash" src="https://github.com/user-attachments/assets/c0713aa0-ba15-4f9c-8c19-1745974b0937" />

- Playbook operating successfully
  
  <img width="297" height="555" alt="OTX Playbook successfully ran" src="https://github.com/user-attachments/assets/81032b39-5878-4ef7-b3b3-a583f9ce14ad" />

- Our OTX feed now bringing in external IOCs from our subscribed pulses
  <img width="1912" height="962" alt="our OTX feed now bringing IOCs from our pulses we can sort this mess of indicators later and will work on dedupe'ing this in the fine tuning phase of the project" src="https://github.com/user-attachments/assets/eec7cdb4-9224-498d-884e-bfa9b7f0f543" />

</details>

<details>
<summary><strong>🧠 Notes & Design Choices</strong></summary>

- Favor REST API for full control over filtering, tagging, and deduplication.  
- Post to `ThreatIntelligenceIndicator` with standardized `Tags: ["OTX", "<PulseName>"]`.  
- Add a **source reliability** tag (e.g., `Confidence=Medium`) for downstream analytics.
- Using a Logic App to pull in external IOCs allows for full automation and control over which pulses we want to bring in.
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
<summary><strong>📷 Screenshot References</strong></summary>

- We are able to filter our IOCs using the `Internal-Incident` tag for ease of access
  <img width="1912" height="962" alt="we are able to filter for the IOCs from our relevant internal incidents that we want to hunt for using tags that we had previously created when making these IOCs from our previous SOAR playbooks phase" src="https://github.com/user-attachments/assets/b5166dc8-73c6-418a-b651-c81d1b430d80" />

- We zero in on the `Joker` IOC from a previous incident and begin our hunt
  
  <img width="418" height="763" alt="we will hunt for the Joker IOC from a previous incident with an SQR3 hypothesis" src="https://github.com/user-attachments/assets/cfbb229d-ac1b-4e83-9807-ee18c84e55cd" />

- Using Microsoft Sentinel's Threat Hunting feature to document our investigation for the malicious `Joker` account
  <img width="1912" height="962" alt="creating our hunt for JOKER within sentinels built in hunting feature" src="https://github.com/user-attachments/assets/1e510cd1-4cf7-4307-9972-15be4938f89f" />

</details>

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
- Multiple logons from **unusual remote IP**: `99.***.**.206` (masked in screenshots for privacy).

**Key IOCs (Private IP)**
```
99.***.**.206
```

**MITRE TTPs**
- `T1078` – Valid Accounts  
- `T1078.003` – Valid Accounts: Local Accounts  
- `T1136` – Create Account  
- `T1136.001` – Create Account: Local Account  
- `T0859` – Access Tokens *(token-oriented misuse during sessions)*

**Screenshots**
- First threat hunting query looking for logon activity from `Joker`
  <img width="1906" height="980" alt="First threat hunting query looking for login instances of Joker with entity mapping" src="https://github.com/user-attachments/assets/ccc29733-2fe9-4713-b5b1-a37fe7d62d1b" />

- 26 results from our first query
  <img width="1907" height="948" alt="results of first query" src="https://github.com/user-attachments/assets/ced6a5d4-fd5c-4409-8ce8-f95750723c91" />

- Logs generated from our first query show suspicious logon activity from an unusual IP address
  <img width="1826" height="736" alt="results of first query continued with IP not shown for privacy reasons" src="https://github.com/user-attachments/assets/cbf3ee44-0e70-41e1-a7ef-2bf8e5b3778a" />

- Suspicious IP will be marked as an IOC related to `Joker` logon activity
  <img width="1746" height="390" alt="first query type of data we are interested in like the remote IP account name login type and time and the device" src="https://github.com/user-attachments/assets/1d3d7db8-1db4-4eff-8ed6-ead922d816e5" />

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

**Key IOCs (Commands, task names, registry)**
```
Task name: JokerHeartbeat
Task name: JokerTask
Registry: HKCU\Software\Joker
Command line: "cmd.exe" /q /c del /q "C:\Program Files\Microsoft Office\root\vfs\ProgramFilesCommonX64\Microsoft Shared\OFFICE16\Addins\UmOutlookAddin.dll"
Command line: sc.exe create BackdoorSvc binPath= "cmd.exe /c calc.exe"
Command line: schtasks.exe /create /sc minute /mo 1 /tn JokerHeartbeat /tr "calc.exe"
Command line: schtasks.exe /create /sc once /tn JokerTask /tr "notepad.exe" /st 00:00
Command line: netsh.exe advfirewall firewall add rule name="JokerRule" dir=in action=allow program="C:\Windows\System32\notepad.exe" enable=yes
Command line: netsh.exe advfirewall firewall delete rule name="JokerRule"
Command line: regsvr32.exe /s /u /i:calc scrobj.dll
Command line: mshta.exe vbscript:Execute "CreateObject(""Wscript.Shell"").Run ""calc.exe"""
Command line: reg.exe add HKCU\Software\Joker /v Key1 /t REG_SZ /d Value1
Command line: cmd.exe /c echo Joker was here > C:\Temp\joker.txt
Command line: whoami.exe /fqdn
```

**MITRE TTPs**
- `T1053` – Scheduled Task/Job  
- `T1543` – Create or Modify System Process (Service)  
- `T1562` – Impair Defenses (firewall rules)  
- `T1218` – Signed Binary Proxy Execution (mshta, regsvr32)  
- `T1112` – Modify Registry  
- `T0863` – Abuse Elevation Control Mechanism *(if UAC bypass attempted)*

**Screenshots**
- Second threat hunting query looking for process file events created by Joker
  <img width="1870" height="770" alt="second threat hunting query looking for process file events created by Joker" src="https://github.com/user-attachments/assets/f2256420-7a76-4fec-a8b4-096223ec3b02" />

- Our second query returned 155 results
  <img width="1904" height="944" alt="results of second query" src="https://github.com/user-attachments/assets/e7773cb0-e1e3-4b78-b756-a80f727049d7" />

- Log showing file deletion activity from `runonce.exe`
  <img width="1752" height="490" alt="second query first potentially suspicious thing we find is CMD launched from runonceexe deleting microsoft files " src="https://github.com/user-attachments/assets/02d40d1d-a7b7-45e9-8479-b1f87b692c7c" />

- Log showing potential backdoor creation and attacker calling card
   <img width="1757" height="486" alt="second query more suspicious activity with a potential backdoor and attacker signature" src="https://github.com/user-attachments/assets/f3ecf67e-790f-42d8-bfc2-7f730eaf962f" />

- Detection evasion activity
  <img width="1752" height="492" alt="second query immediately followed up with detection evasion trying to clean up their trail" src="https://github.com/user-attachments/assets/422cc89c-1ee5-41f0-b5cc-2d4c632126ab" />

- `JokerHeartbeat` scheduled task created for persistence
  <img width="1757" height="492" alt="second query persistance with scheduled task" src="https://github.com/user-attachments/assets/3d3b1d80-e9a7-4b80-894e-1d4134d3997c" />

- Legitimate windows service running from `Local/Temp` folder indicative of classic masquerading & process injection techniques
  <img width="1757" height="491" alt="second query suspicious folder path as legitimate windows process svchost is being run from temp folder " src="https://github.com/user-attachments/assets/8cb169f0-829c-4b3f-8d3d-ea484a8cd4aa" />

- Log showing more suspicious LOLBin activity
  <img width="1753" height="492" alt="second query LOLBin being used to masquerade a service" src="https://github.com/user-attachments/assets/9ee41421-2b60-4ac6-aead-7df6ac2a53d5" />

- Our attacker utilizing more LOLBin techniques to disguise potentially malicious activity
  <img width="1757" height="492" alt="second query another LOLBin being used" src="https://github.com/user-attachments/assets/08e0b38a-3b6c-4b83-9726-f8ff5fddfd90" />

- Registry modification by `Joker` account
  <img width="1752" height="482" alt="second query registry being modified by Joker" src="https://github.com/user-attachments/assets/5a714f83-a0b8-4648-88d8-5812e595e348" />

- Scheduled task set to run potentially malicious `JokerTask`
  <img width="1761" height="497" alt="second query another scheduled task to run malicous Joker Task" src="https://github.com/user-attachments/assets/567fe59c-99c3-44f0-9db8-1e7e617153f8" />

- `Joker` account manipulating firewall rules
  <img width="1751" height="493" alt="second query Joker manipulating firewall rules" src="https://github.com/user-attachments/assets/79869595-2cbf-42cb-ae15-28290d2f2793" />

- More LOLBin abuse by `Joker` to execute malicious DLL payloads without dropping an obvious EXE payload
  <img width="1748" height="486" alt="second query powershell interacting with rundll32 in unusual manner" src="https://github.com/user-attachments/assets/987a5afa-0a7c-4827-8dfe-fdac0da6a6b0" />

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

