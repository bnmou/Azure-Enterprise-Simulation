# ⚙️ Phase 5: SOAR Automation

**Azure SOC Operations Home Lab | Analyst-Triggered Playbooks**

In **Phase 5** of my Azure SOC simulation, I developed four deeply integrated Microsoft Sentinel playbooks for real-world SOAR automation. These **analyst-triggered playbooks** automate detection and containment of:

* Malicious macro payload execution
* Reverse shell activity
* Suspicious user privilege escalation
* LSASS credential dumping attempts

Each Logic App was carefully constructed with exact permissions, robust API authentication, user filtering, and multi-platform alerting.

---

## 🔹 Playbook: MacroExecution

<details>
<summary><strong>🔍 Malicious Macro Auto-Response</strong></summary>

### 🔐 Purpose

Triggers when a `.docm` file containing a malicious macro is executed, initiating a containment workflow to tag the device, block further app execution, and notify analysts and users.

### ⚙️ Logic App Breakdown

**Trigger**: Analyst-triggered Microsoft Sentinel incident (Preview)

**Required Permissions**:

* Logic App API connection to Microsoft Sentinel and Microsoft Defender for Endpoint (MDE)
* Logic App Managed Identity must have:

  * `Microsoft Sentinel Responder` role on Sentinel workspace
  * `Machine.Isolate`, `Alert.Read`, `Machine.Read.All`, and `Machine.RunAntiVirusScan` API permissions on Defender

**Step-by-Step Breakdown**:

📸*Playbook Overview*
<img width="1912" height="962" alt="Macro Playbook overview" src="https://github.com/user-attachments/assets/b4dfc085-787a-4c0e-a0a8-720b9676bdd7" />

---

1. **Trigger**

   📸*Triggered manually from the Sentinel incident.*

   <img width="565" height="430" alt="image" src="https://github.com/user-attachments/assets/d0266379-6154-49a7-8f58-3933d5e4c2c9" />

2. **Compose Entities**

   📸*Extracts involved usernames, file hashes, and device names.*
   
   <img width="562" height="249" alt="image" src="https://github.com/user-attachments/assets/46c5be6e-c2d8-47a7-8681-abd995f85444" />

3. **Get Auth Token (MDE)**

   📸*Performs secure OAuth token retrieval for API use.*
   
    <img width="568" height="557" alt="image" src="https://github.com/user-attachments/assets/afe7acbe-acce-4e14-a09b-cc419b004e02" />

4. **Restrict App Execution**

   📸*Applies "Attack Surface Reduction" tagging via Defender API.*
   
   <img width="568" height="496" alt="image" src="https://github.com/user-attachments/assets/63cac163-97bf-4e0d-b744-5f354ce2bb2b" />

5. **Run AV Scan**

   📸*Forces a Defender Antivirus scan remotely on affected endpoint.*
   
   <img width="571" height="501" alt="image" src="https://github.com/user-attachments/assets/9894a305-1184-4b89-9803-08133d103db1" />

6. **Send Email (V2)**

   📸*Notifies the affected user that a suspicious macro was executed.*
   
   <img width="566" height="562" alt="image" src="https://github.com/user-attachments/assets/d7cc5778-325f-4fea-8adb-fbb75a5646a3" />

7. **Discord Alert**

   📸*Sends alert to SOC team via webhook with incident title and user/machine context.*
   
   <img width="562" height="763" alt="image" src="https://github.com/user-attachments/assets/520889e0-cc47-462c-bd9f-412a22c5761d" />

8. **Get File Statistics**

    📸*Extracts the SHA256 hash from the malicous macro file.*
    
   <img width="564" height="521" alt="image" src="https://github.com/user-attachments/assets/0414df55-3bc7-4766-b81e-893b0fb8be71" />

9. **Upload SHA256 to Threat Intelligence**

    📸*Automatically extracts file hash from the "Get File Statistics" step and uploads it to Sentinel's custom threat intelligence table.*
    
   <img width="563" height="778" alt="image" src="https://github.com/user-attachments/assets/6cb5f94d-1d7a-48ad-9a48-066e2e63cd43" />

### 📊 Screenshots

* *Playbook operating successfully*
  <img width="1912" height="962" alt="Macro playbook operating successfully" src="https://github.com/user-attachments/assets/74cf4803-5cd8-4ae7-8dd8-d224f3a36e7d" />
  <img width="1912" height="962" alt="macro close up of playbook with explanation of each step and their purpose" src="https://github.com/user-attachments/assets/01686526-93ff-4980-a036-86cda332265b" />

* *Device tagged and AV scan launched*
  <img width="1912" height="962" alt="macro machine tagged and AV scan conducted" src="https://github.com/user-attachments/assets/d8dba25f-f6fd-4543-beb6-c48db99e5b92" />

* *SHA256 hash added to Threat Intel*
  <img width="1912" height="962" alt="Macro SHA 256 blocked and added to threat intel" src="https://github.com/user-attachments/assets/4ae29896-0e6d-4510-b42d-1446fe2f9d76" />

* *Discord alert with dynamic incident summary*
  <img width="1256" height="407" alt="macro playbook discord alert" src="https://github.com/user-attachments/assets/d0c07b0d-078f-4ef7-805e-3ea58d5bcbeb" />

* *Email notification to compromised user*
  <img width="1629" height="320" alt="email notification" src="https://github.com/user-attachments/assets/0d16496c-0e7b-44be-aec8-e302aaaf9756" />

### 🧠 Key Takeaways (Macro Execution Scenario)

* Defender tagging is a stealthy yet effective way to stop unknown malware execution without full isolation.
* Hash uploads allow for threat sharing across the workspace and reusable TI-based rules.
* Analyst-triggered design prevents false positives from regular macros (e.g., HR templates).

</details>

---

## 🔹 Playbook: ReverseShell Containment

<details>
<summary><strong>🔴 Reverse Shell Detection & Remediation</strong></summary>

### 🔐 Purpose

Detects and responds to reverse shell attempts launched using Windows, PowerShell, `cmd.exe`, or encoded base64 payloads.

### ⚙️ Logic App Breakdown

**Trigger**: Analyst-initiated Microsoft Sentinel incident

**Required Permissions**:

* Logic App API connection to Sentinel and Defender
* Live response script deployment permissions on Defender

**Step-by-Step Breakdown**:

📸*Playbook Overview*
<img width="1912" height="962" alt="RevShell Playbook overview" src="https://github.com/user-attachments/assets/71b3dbf4-a4e4-4742-910e-7ed5a6f651c5" />

1. **Get Incident**

   📸*Pulls full context, including entities like command line and username.*
   
   <img width="562" height="404" alt="image" src="https://github.com/user-attachments/assets/26bb59c0-9c16-4cb7-a71e-2d29ac2aa95d" />

2. **Compose Entities**

   📸*Parses for specific entities to be used later on in the playbook like obfuscated Shell Commands.*
   
   <img width="568" height="362" alt="image" src="https://github.com/user-attachments/assets/bd2b5b4a-0b34-4a49-b652-e0545021e121" />

3. **Discord Alert**

   📸*Sends enriched alert to SOC team.*
   
   <img width="566" height="781" alt="image" src="https://github.com/user-attachments/assets/ee6d681f-7671-4a7c-9a94-5355502f2f9a" />

4. **Email Notification**

   📸*Notifies the user who launched the process.*
   
   <img width="568" height="553" alt="image" src="https://github.com/user-attachments/assets/c47ddb81-8ff4-4317-9eda-3b90a6a5a346" />

5. **Get Auth Token**
 
   📸*Required for script deployment.*
   
   <img width="562" height="536" alt="image" src="https://github.com/user-attachments/assets/5bb4c0e6-b191-4589-941a-a7b620130853" />
 
6. **Run Live Response Script** (`KillPowerShell.ps1`)

   📸*Kills all instances of PowerShell running on the machine including any established Reverse Shells currently running.*
   
   <img width="566" height="719" alt="image" src="https://github.com/user-attachments/assets/0a3bc80d-5f59-4070-b17e-1b7f0246906e" />
  
7. **Isolate and Tag Machine**
   
   📸*Full network isolation + tag added.*
   
   <img width="567" height="498" alt="image" src="https://github.com/user-attachments/assets/ebfe924a-86a1-402b-be44-72915622e609" />
   <img width="569" height="476" alt="image" src="https://github.com/user-attachments/assets/cf358999-70a4-4b17-9e5d-bdc6c2bc22a7" />
 
8. **Upload Command Line IOC**

   📸*Adds base64 encoded reverse shell payload as custom IOC to Threat Intelligence.*
   
    <img width="562" height="763" alt="image" src="https://github.com/user-attachments/assets/b1dacc3d-3ad0-44f2-b53d-b231e7a7abd1" />

### 📊 Screenshots

* *Playbook operating successfully*
  <img width="1912" height="962" alt="revshell playbook operating successfully" src="https://github.com/user-attachments/assets/5e380a7a-d8cb-4a41-90d0-3229fb0ff8eb" />
  <img width="1912" height="962" alt="revshell close up of playbook with explanation of each step and their purpose" src="https://github.com/user-attachments/assets/d2f2611c-73a4-4d7b-b6f2-cee3fb27efde" />

* *Discord alert with dynamic incident summary*
  <img width="1249" height="415" alt="revshell playbook discord alert" src="https://github.com/user-attachments/assets/b810d817-6acd-4963-ad57-3776f9da19f2" />

* *User notification email*
  <img width="1621" height="317" alt="email notification 2" src="https://github.com/user-attachments/assets/1f7fe8cf-9a83-4c5a-a110-7ac81cb7d8e1" />

* *Machine isolation + tagging confirmed*
  <img width="1605" height="209" alt="revshell machine isolated and tagged" src="https://github.com/user-attachments/assets/2f4b8ba2-5e12-445f-b098-036698a12a71" />

* *Live response script executed successfully*
  <img width="1588" height="286" alt="Revshell live response command executed successfully" src="https://github.com/user-attachments/assets/2398bed0-2c37-4925-83b3-a47cc9e1220d" />

* *Command line added to Threat Intel*
  <img width="1912" height="962" alt="revshell playbook uploaded reverse shell command line as IOC to threat intel" src="https://github.com/user-attachments/assets/438362e7-9d86-4e01-8e16-9bbb31a26b37" />

### 🧠 Key Takeaways (Reverse Shell Scenario)

* PowerShell/encoded payloads must be handled surgically to avoid nuking valid usage.
* A playbook to swiftly cut off ReverseShell instances adds defense-in-depth alongside isolation.
* Live response scripts give granular control beyond built-in Defender actions.

</details>

---

## 🔹 Playbook: Suspicious Privilege Escalation

<details>
<summary><strong>👤 New User with Immediate Admin Privileges</strong></summary>

### 🔐 Purpose

Flags and auto-restricts new accounts that are granted administrator rights within minutes of being created.

### ⚙️ Logic App Breakdown

**Trigger**: Manual incident trigger

**Required Permissions**:

* Graph API permissions for group modification (via Defender API Live Response)
* Sentinel contributor access to write comments + threat intel

**Step-by-Step Breakdown**:

📸*Playbook Overview*
<img width="1912" height="962" alt="suspriv playbook overview" src="https://github.com/user-attachments/assets/bb4e7cf5-c67f-4e1b-9cdb-7563d0718201" />

1. **Get Incident**

   📸*Gathers entities involved: users and their timestamps.*
   
   <img width="564" height="402" alt="image" src="https://github.com/user-attachments/assets/a3d55756-40fb-4de5-b714-34943a22ace8" />

2. **Compose Entities**

   📸*Parses usernames and roles.*
   
   <img width="558" height="375" alt="image" src="https://github.com/user-attachments/assets/fcbb9210-afe3-4d81-8c6b-2b9fe497aaaa" />

3. **Filter Array + Known Users**

   📸*Filters out entities for UserAccounts.*
   
   <img width="564" height="346" alt="image" src="https://github.com/user-attachments/assets/edab300a-699d-4a33-91f4-425ebfc92c2c" />

   📸*Creates an array labeled `Filtered Usernames` to be utilized in a later loop.*
   
   <img width="562" height="385" alt="image" src="https://github.com/user-attachments/assets/e5a2119c-d109-4356-b406-cc5f4a1b1913" />

   📸*For Each loop filters out legitimate admin accounts (e.g., `barbara.hr`, `wayneadmin`) and appends suspicious UserAccounts to `Filtered Usernames`*
   
   <img width="565" height="802" alt="image" src="https://github.com/user-attachments/assets/a2d06fb2-fafd-4f31-a327-357cd4cc5aee" />

4. **Discord Alert**

   📸*Sends alert on risky admin assignment.*
   
    <img width="563" height="802" alt="image" src="https://github.com/user-attachments/assets/913bb1ee-e31c-4fbe-8b4e-6907da86b0ce" />

5. **Email Notification (SOC)**
   
   📸*Notifies analysts for review and audit as well as affected user.*
   
   <img width="566" height="549" alt="image" src="https://github.com/user-attachments/assets/b53153f6-9b41-4bc1-a27d-ad4fa987de03" />
   <img width="569" height="557" alt="image" src="https://github.com/user-attachments/assets/0b33e503-2bfd-4d25-ab73-da1ae6a3c1c4" />
   
6. **Get Auth Token**
   
   📸*Grants token for Defender script execution.*
   
   <img width="565" height="555" alt="image" src="https://github.com/user-attachments/assets/063945d2-d7ec-4879-bc07-3d9f2040ef23" />
   
7. **For Each Filtered User**
   
   📸*Runs live response script to remove from local admin group and disable account*
   
   <img width="565" height="655" alt="image" src="https://github.com/user-attachments/assets/b6695289-95cd-4304-8189-149fb508a623" />
   
8. **Add Comment to Incident**
   
   📸*Documents SOAR action timeline.*
     
   <img width="568" height="512" alt="image" src="https://github.com/user-attachments/assets/d34a3275-b621-4aa2-b725-36e187aa3ec3" />
   
9. **Upload Usernames to Threat Intel**
     
   📸*Flags user as possible persistence vector.*
    
   <img width="566" height="801" alt="image" src="https://github.com/user-attachments/assets/80bac710-5cd8-4ac6-b348-9310a364395e" />

### 📊 Screenshots

* *Playbook operating successfully*
  <img width="1912" height="962" alt="suspriv playbook operating successfully" src="https://github.com/user-attachments/assets/5e608bcb-8a16-4825-93b6-a2660bf8e962" />
  <img width="1912" height="962" alt="suspriv closeup of playbook with explanation of each step and what they do" src="https://github.com/user-attachments/assets/c9367e53-0e4e-4b24-938a-6c76f237c295" />
   
* *Discord alert to SOC team*
   <img width="1255" height="400" alt="suspriv playbook discord alert" src="https://github.com/user-attachments/assets/55007ae3-7439-4c3a-9b61-9a294021ff90" />

* *Dual email notifications (SOC + User)*
   <img width="1620" height="223" alt="suspriv ontop of our regular user alert email we also have analyst alert emails for soar actions taken on sus users" src="https://github.com/user-attachments/assets/4bb08f7e-ccfe-40bf-bc15-38bfa09078ba" />

* *User removed from local admin group*
   <img width="1542" height="220" alt="suspriv users successfully removed from admin group" src="https://github.com/user-attachments/assets/561f8486-d5e9-439e-82b7-619a6f871f8c" />

* *Hunting query confirms access revoked*
   <img width="1912" height="962" alt="suspriv query confirms users removed" src="https://github.com/user-attachments/assets/62ed6006-262c-413c-a6a8-cb10319389f3" />

* *Comment added to incident*
  
   <img width="769" height="734" alt="suspriv comments added to incident for analysts" src="https://github.com/user-attachments/assets/7081d99c-47fd-4a04-beaf-897be00e8efc" />

* *Usernames uploaded to threat intel*
   <img width="1912" height="962" alt="suspriv sus accounts added to threat intel" src="https://github.com/user-attachments/assets/42a4444b-3d35-4469-a581-49905bb7bb28" />

### 🧠 Key Takeaways (Privilege Escalation Scenario)

* Privilege escalation often follows account creation during lateral movement.
* Pre-filtering known users prevents internal disruption.
* Registry edits + account disablement adds long-term protection.

</details>

---

## 🔹 Playbook: LSASS Access

<details>
<summary><strong>❇️ Credential Dumping (LSASS Defense)</strong></summary>

### 🔐 Purpose

Responds to LOLBins or credential tools accessing `lsass.exe`, commonly used in Mimikatz-style attacks.

### ⚙️ Logic App Breakdown

**Trigger**: Sentinel incident with keywords (`comsvcs.dll`, `lsass.dmp`, `rundll32.exe lsass`)

**Required Permissions**:

* Defender API access to isolate machines
* Script deployment and live response permissions

**Step-by-Step Breakdown**:

1. **Get Incident**

   * Captures device, user, and command line.

2. **Filter User Entities**

   * Filters affected users only.

3. **Send Discord Alert**

   * Notifies analysts of possible dump attempt.

4. **Send Email Notification**

   * Notifies user and logs to mailbox.

5. **Get Auth Token**

   * OAuth token for Defender script deployment.

6. **Isolate + Tag Endpoint**

   * Enforces full machine isolation + tagging for tracking.

7. **Run Live Response Script** (`RestrictLSASSUser.ps1`)

   * Disables user, forces password reset, removes from Admin group.

8. **Add Comment to Incident Timeline**

### 📊 Screenshots

* *Playbook run successful*
  ![Run](./screenshots/phase5/Lsass%20playbook%20operating%20successfully.png)

* *Discord alert to SpideyBot*
  ![Discord](./screenshots/phase5/lsass%20playbook%20discord%20alert.png)

* *Email alert to affected user*
  ![Email](./screenshots/phase5/Lsass%20email%20notif.png)

* *Machine isolated and tagged*
  ![Isolated](./screenshots/phase5/lsass%20machine%20isolated%20and%20tagged.png)

* *Account status verified post-remediation*
  ![Verification](./screenshots/phase5/lsass%20live%20action%20script%20confirmed%20by%20checking%20account%20status%20on%20domain%20controller%20.png)

### 🧠 Key Takeaways (LSASS Dumping Scenario)

* Isolation plus live script hardens the system within seconds.
* Regex-based trigger logic reduces false alerts.
* Built-in escalation path keeps remediation efficient while providing full audit trace.

</details>

---

## 📈 Summary of SOAR Impact

| Threat Scenario           | Detection Source    | Remediation Actions                              |
| ------------------------- | ------------------- | ------------------------------------------------ |
| Malicious Macros          | FileHash + Command  | Tag, AV scan, Notify, TI upload, Block Hash      |
| Reverse Shell Activity    | CommandLine Pattern | Isolate, Disable, Alert, Upload IOC              |
| Immediate Priv Escalation | Group Add Events    | Remove rights, Disable, Notify, Threat Tagging   |
| LSASS Dump Attempt        | LOLBin + LSASS Ref  | Isolate, Disable, Reset, Comment + Discord alert |

> All actions are **audited, analyst-controlled, and verifiable via KQL or incident comments.**

---

## 🚀 Phase 6 Preview: Detection Engineering & Reporting

Next, I will correlate all triggered incidents into a custom **Microsoft Sentinel workbook**, linking:

* Playbook responses
* Threat intel matches
* Endpoint telemetry

Stay tuned!
