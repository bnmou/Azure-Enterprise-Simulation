# ⚙️ Phase 5: SOAR Automation

**Azure SOC Operations Home Lab | Analyst-Triggered Playbooks**

In **Phase 5** of my Azure SOC simulation, I developed four deeply integrated Microsoft Sentinel playbooks for real-world SOAR automation. These **analyst-triggered playbooks** automate detection and containment of:

* Malicious macro payload execution
* Reverse shell activity
* Suspicious user privilege escalation
* LSASS credential dumping attempts

Each Logic App was carefully constructed with exact permissions, robust API authentication, user filtering, and multi-platform alerting.

---

## 🔹 Playbook: MacroExecution AutoResponse Playbook

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

*Playbook Overview*
<img width="1912" height="962" alt="Macro Playbook overview" src="https://github.com/user-attachments/assets/b4dfc085-787a-4c0e-a0a8-720b9676bdd7" />

---

1. **Trigger**

   * Triggered manually from the Sentinel incident.
   <img width="565" height="430" alt="image" src="https://github.com/user-attachments/assets/d0266379-6154-49a7-8f58-3933d5e4c2c9" />

2. **Compose Entities**

   * Extracts involved usernames, file hashes, and device names.
   <img width="562" height="249" alt="image" src="https://github.com/user-attachments/assets/46c5be6e-c2d8-47a7-8681-abd995f85444" />

3. **Get Auth Token (MDE)**

   * Performs secure OAuth token retrieval for API use.
    <img width="568" height="557" alt="image" src="https://github.com/user-attachments/assets/afe7acbe-acce-4e14-a09b-cc419b004e02" />

4. **Restrict App Execution**

   * Applies "Attack Surface Reduction" tagging via Defender API.
   <img width="568" height="496" alt="image" src="https://github.com/user-attachments/assets/63cac163-97bf-4e0d-b744-5f354ce2bb2b" />

5. **Run AV Scan**

   * Forces a Defender Antivirus scan remotely on affected endpoint.
  <img width="571" height="501" alt="image" src="https://github.com/user-attachments/assets/9894a305-1184-4b89-9803-08133d103db1" />

6. **Send Email (V2)**

   * Notifies the affected user that a suspicious macro was executed.
   <img width="566" height="562" alt="image" src="https://github.com/user-attachments/assets/d7cc5778-325f-4fea-8adb-fbb75a5646a3" />

7. **Discord Alert**

   * Sends alert to SOC team via webhook with incident title and user/machine context.
   <img width="562" height="763" alt="image" src="https://github.com/user-attachments/assets/520889e0-cc47-462c-bd9f-412a22c5761d" />

8. **Get File Statistics**

   * Extracts the SHA256 hash from the malicous macro file.
   <img width="564" height="521" alt="image" src="https://github.com/user-attachments/assets/0414df55-3bc7-4766-b81e-893b0fb8be71" />

9. **Upload SHA256 to Threat Intelligence**

   * Automatically extracts file hash from the "Get File Statistics" step and uploads it to Sentinel's custom threat intelligence table.
   <img width="563" height="778" alt="image" src="https://github.com/user-attachments/assets/6cb5f94d-1d7a-48ad-9a48-066e2e63cd43" />

### 📊 Screenshots

* *Playbook operating successfully*
  ![Macro Success](./screenshots/phase5/macro%20playbook%20operating%20successfully.png)

* *Device tagged and AV scan launched*
  ![Tagged + AV](./screenshots/phase5/macro%20machine%20tagged%20and%20AV%20scan%20conducted.png)

* *SHA256 hash added to Threat Intel*
  ![Threat Intel Hash](./screenshots/phase5/Macro%20SHA%20256%20blocked%20and%20added%20to%20threat%20intel.png)

* *Discord alert with dynamic incident summary*
  ![Discord Alert](./screenshots/phase5/macro%20playbook%20discord%20alert.png)

* *Email notification to compromised user*
  ![Email](./screenshots/phase5/email%20notification.png)

### 🧠 Key Takeaways (Macro Execution Scenario)

* Defender tagging is a stealthy yet effective way to stop unknown malware execution without full isolation.
* Hash uploads allow for threat sharing across the workspace and reusable TI-based rules.
* Analyst-triggered design prevents false positives from regular macros (e.g., HR templates).

</details>

---

## 🔹 Playbook: RevShell\_AutoResponse\_Playbook

<details>
<summary><strong>🔴 Reverse Shell Detection & Remediation</strong></summary>

### 🔐 Purpose

Detects and responds to reverse shell attempts launched using Windows LOLBins like PowerShell, `cmd.exe`, or encoded base64 payloads.

### ⚙️ Logic App Breakdown

**Trigger**: Analyst-initiated Microsoft Sentinel incident

**Required Permissions**:

* Logic App API connection to Sentinel and Defender
* Live response script deployment permissions on Defender

**Step-by-Step Breakdown**:

1. **Get Incident**

   * Pulls full context, including entities like command line and username.

2. **Filter Shell Command Lines**

   * Parses for known reverse shell patterns (e.g., `powershell -nop -enc`, `bash -i`)

3. **Discord Alert**

   * Sends enriched alert to SOC team.

4. **Email Notification**

   * Notifies the user who launched the process.

5. **Get Auth Token**

   * Required for script deployment.

6. **Run Live Response Script** (`DisableShellUser.ps1`)

   * Disables account, sets password reset flag, and removes from local admin group.

7. **Isolate and Tag Machine**

   * Full network isolation + tag added.

8. **Upload Command Line IOC**

   * Adds base64 reverse shell payload as custom IOC to Threat Intelligence.

### 📊 Screenshots

* *Playbook operating successfully*
  ![RevShell Success](./screenshots/phase5/revshell%20playbook%20operating%20successfully.png)

* *Discord alert (SpideyBot)*
  ![Discord](./screenshots/phase5/revshell%20playbook%20discord%20alert.png)

* *User notification email*
  ![Email](./screenshots/phase5/email%20notification%202.png)

* *Machine isolation + tagging confirmed*
  ![Isolated](./screenshots/phase5/revshell%20machine%20isolated%20and%20tagged.png)

* *Live response script executed successfully*
  ![Live Response](./screenshots/phase5/Revshell%20live%20response%20command%20executed%20successfully.png)

* *Command line added to Threat Intel*
  ![TI IOC](./screenshots/phase5/revshell%20playbook%20uploaded%20reverse%20shell%20command%20line%20as%20IOC%20to%20threat%20intel.png)

### 🧠 Key Takeaways (Reverse Shell Scenario)

* PowerShell/encoded payloads must be handled surgically to avoid nuking valid usage.
* Account disablement + password reset adds defense-in-depth alongside isolation.
* Live response scripts give granular control beyond built-in Defender actions.

</details>

---

## 🔹 Playbook: SuspiciousPrivilegeEscalation\_Playbook

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

1. **Get Incident**

   * Gathers entities involved: users and their timestamps.

2. **Compose Entities**

   * Parses usernames and roles.

3. **Filter Array + Known Users**

   * Filters out legitimate admin accounts (e.g., `barbara.hr`, `wayneadmin`)

4. **Discord Alert**

   * Sends alert on risky admin assignment.

5. **Email Notification (SOC)**

   * Notifies analysts for review and audit.

6. **Get Auth Token**

   * Grants token for Defender script execution.

7. **For Each Filtered User**

   * Runs live response script to:

     * Remove from local Admin group
     * Add registry restrictions
     * Disable account

8. **Add Comment to Incident**

   * Documents SOAR action timeline.

9. **Upload Username to Threat Intel**

   * Flags user as possible persistence vector.

### 📊 Screenshots

* *Playbook operating successfully*
  ![Success](./screenshots/phase5/suspriv%20playbook%20operating%20successfully.png)

* *Discord alert to SOC team*
  ![Discord](./screenshots/phase5/suspriv%20playbook%20discord%20alert.png)

* *Dual email notifications (SOC + User)*
  ![Emails](./screenshots/phase5/suspriv%20ontop%20of%20our%20regular%20user%20alert%20email%20we%20also%20have%20analyst%20alert%20emails%20for%20soar%20actions%20taken%20on%20sus%20users.png)

* *User removed from local admin group*
  ![Removed](./screenshots/phase5/suspriv%20users%20successfully%20removed%20from%20admin%20group.png)

* *Hunting query confirms access revoked*
  ![Query](./screenshots/phase5/suspriv%20query%20confirms%20users%20removed.png)

* *Comment added to incident*
  ![Comment](./screenshots/phase5/suspriv%20comments%20added%20to%20incident%20for%20analysts.png)

* *Usernames uploaded to threat intel*
  ![TI](./screenshots/phase5/suspriv%20sus%20accounts%20added%20to%20threat%20intel.png)

### 🧠 Key Takeaways (Privilege Escalation Scenario)

* Privilege escalation often follows account creation during lateral movement.
* Pre-filtering known users prevents internal disruption.
* Registry edits + account disablement adds long-term protection.

</details>

---

## 🔹 Playbook: LSASS\_Access\_AutoResponse\_Playbook

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
