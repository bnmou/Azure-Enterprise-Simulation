# 🚨 Phase 7 — Incident Response

**Incident Title:** Multi-stage incident involving Initial Access & Exfiltration on multiple endpoints  
**Incident ID:** 74  
**Owner:** Bruce Wayne  
**Workspace:** wayne-law  
**Status:** Closed ✅

---

## 📌 Overview

In this phase, we responded to a **multi-stage attack chain** detected by our custom rules in Microsoft Sentinel.  
The adversary:

- Delivered a **malicious macro payload** via a `.docm` file.  
- Spawned a **reverse shell** using PowerShell.  
- Established **persistence** through scheduled tasks.  
- Dumped **LSASS credentials**.  
- Created **new privileged accounts**.  
- Exfiltrated data using **NGROK C2 channels**.

We grouped all alerts into **one incident** and responded in line with the **NIST Cybersecurity Framework** (Identify → Contain → Eradicate → Recover → Lessons Learned).

---

<details>
<summary>🔎 1) Detection & Analysis</summary>

### 📂 Incident created in Sentinel  
<img width="1912" height="962" alt="Overview of the Multi stage incident our detection rules put together" src="https://github.com/user-attachments/assets/54194b05-84e7-4b89-94b8-853e8fda14c7" />

---

### 📊 Incident overview (grouped alerts + entities)  
<img width="1912" height="962" alt="Our incident with multiple grouped alerts and our entities" src="https://github.com/user-attachments/assets/42ab5c21-4c9e-4656-bf88-dfacf46ddf74" />

---

### 📄 Evidence of malicious macro, reverse shell & C2 exfil  
<img width="432" height="505" alt="our alerts from our detection rules including a malicious macro reverse shell and data exfil" src="https://github.com/user-attachments/assets/22d5298f-4623-4a19-9ce7-279c3795858f" />

---

### 🔐 Evidence of LSASS access & persistence via scheduled tasks
<img width="427" height="499" alt="as well as our lsass access rules and scheduled task rules" src="https://github.com/user-attachments/assets/ad43939d-0f3d-4699-aac7-d8cb94502661" />

---

### 👥 Evidence of attacker account creation + privilege escalation  
<img width="431" height="504" alt="finally our user creation and priv escalation" src="https://github.com/user-attachments/assets/86dddc8e-ccb6-43b9-893f-ed15b5b75fd2" />

---

### 🌐 Incident IOCs identified
<img width="1082" height="776" alt="persistence tasks foreign IP addresses obfuscated command lines and a suspicious macro document along with compromised accounts and hosts" src="https://github.com/user-attachments/assets/8dad122a-fba5-4131-ad41-eb05ae691834" />
<img width="1081" height="776" alt="lsass access and the adversary creating new accounts with admin priv" src="https://github.com/user-attachments/assets/b0b2de9b-9fb5-4e50-9d41-cd5f0e9faaa0" />

---

### 📅 Timeline of Grouped Alerts  

The following timeline reconstructs the attack sequence, mapped to the **Cyber Kill Chain**:  

1️⃣ **Initial Access**  
- Delivery of a **malicious `.docm` file** (Wayne_Enterprises_Resume.docm).  
- User `barbara.hr` opened the document, triggering **macro execution**.  

2️⃣ **Execution**  
- Macro spawned **PowerShell commands**, downloading a reverse shell payload from NGROK C2.  
- Reverse shell connection established → outbound traffic observed.  

3️⃣ **Persistence**  
- Adversary created a **scheduled task** (`schtasks.exe`) to repeatedly launch the reverse shell at logon.  

4️⃣ **Credential Access**  
- **LSASS process dumped** using `rundll32` + `comsvcs.dll`.  
- Dump file stored in temporary directories for later retrieval.  

5️⃣ **Privilege Escalation**  
- Multiple local accounts (`attacker1`, `attacker2`, `attacker3`) created via `net user`.  
- Accounts immediately added to the **Administrators group**.  

6️⃣ **Command & Control (C2)**  
- Outbound traffic to multiple **NGROK endpoints** observed (C2 tunnels).  
- External IP addresses linked to the reverse shell sessions.  

7️⃣ **Exfiltration**  
- Data staged and sent out via NGROK tunnel.  
- Alerts flagged **data exfiltration over alternative protocol**.  

---

✅ By mapping to the Cyber Kill Chain, we can clearly see how the attacker moved from **Initial Access → Execution → Persistence → Credential Access → Privilege Escalation → C2 → Exfiltration**. 

---

### 📉 Log retention gap (important lesson)  
<img width="1011" height="402" alt="Unfortunately our log retention period purged all logs so we must improvise with the information we have so far and add this to our lessons learned at the end" src="https://github.com/user-attachments/assets/de241b11-0e78-431a-846a-6c79be19b560" />

Unfortunately, our log retention period purged all logs, so we must improvise with the information we have so far and coordinate a better retention policy or compensating control during our lessons learned segment.

</details>

---

<details>
<summary>🛡️ 2) Containment Actions</summary>

We leveraged **Microsoft Sentinel playbooks** for automated containment:

- ▶️ **Playbook-MacroExecution** → blocked malicious macro execution.  
  ![MacroExecution playbook run](our alerts from our detection rules including a malicious macro reverse shell and data exfil.png)  

- ▶️ **ReverseShellContainment** → killed PowerShell reverse shells + removed scheduled task.  
  ![ReverseShellContainment playbook run](Seeing this scheduled reverse shell task we launch the reverse shell containment playbook to kill all instances of a potential reverseshell.png)  

- ▶️ **SusPrivEscalation** → restricted admin rights of new attacker accounts + Barbara’s account.  
  ![Privilege Escalation containment](finally we run our sus priv escalation playbook to restrict admin privs of all accounts in the incident including the compromised barbara account in which we will restore admin rights later on.png)  

- ▶️ **LSASS_Access_AutoRes** (manual trigger) → isolated device + logged remediation to incident timeline.  

---

### 🔒 Device isolation in MDE  
![Device isolation completed](we can then release the machine from isolation in MDE.png)  

</details>

---

<details>
<summary>🧹 3) Eradication — Indicators Blocked</summary>

### 🧾 File Hash (SHA256)  
Blocked & remediated.  
![Hash added to Defender](this is the known hash for the malicious macro exe so we will add it to defender.png)  

---

### 🌍 Malicious Domains  
`*.ngrok-free.app` → Block execution (C2 category).  
![Domain added to blocklist](adding ngrok to block list for the tenant.png)  

---

### 📡 Malicious IPs  
- 3.x.x.175  
- 3.x.x.225  
- 3.x.x.203  
- 3.x.x.220  

![IPs blocklisted](we will now add these IPs to the block list.png)  
![IPs confirmation](IP added to block list same process for the other 3 IPs.png)  

---

### 👥 Accounts  
- Disabled attacker accounts (`attacker1`, `attacker2`, `attacker3`).  
- Temporarily restricted Barbara’s admin rights until investigation completed.  

</details>

---

<details>
<summary>🔄 4) Recovery — Restoring Host</summary>

Our victim machine (`wayne-client`) was an **Azure VM**.  
Because it’s cloud-hosted, we can restore to a **known-good state** using **Azure Backup / Restore Point** or by creating a **new VM from a snapshot**.

![Azure VM ready for restore](our victim machine is an azure resource so we can restore to a known good checkpoint from here.png)  

---

### ✅ Option A — Azure Backup (preferred)
1. Recovery Services Vault → Backup items → Select VM.  
2. Restore VM → Choose restore point (pre-attack).  
3. Create **new VM** (recommended to preserve forensic evidence).  
4. Re-onboard new VM into Defender + run scans.  

### 🌀 Option B — Snapshot fallback
- Snapshot OS disk → Create managed disk → Deploy new VM from snapshot.  

### 💥 Option C — Redeploy/Reimage
- Reimage VM (last resort — nukes forensic evidence).  

---

### 📤 Post-restore validation
- Defender shows device healthy.  
- No malicious scheduled tasks / services remain.  
- Blocklists (hash, IPs, domains) enforced.  
- Compromised accounts secured & MFA enforced.  
- Endpoint monitored under heightened scrutiny (14 days).  

---

### 🔓 Releasing host from isolation after validation  
![Release from isolation](we can then release the machine from isolation in MDE.png)  

</details>

---

<details>
<summary>📖 5) Lessons Learned</summary>

- 🕑 **Retention gap** → old logs purged; extend retention or enable export to Storage/Event Hub.  
- 🛡️ **Macro defense** → block macros from Internet.  
- 🌍 **NGROK C2** → block tunneling services tenant-wide.  
- 🔐 **LSASS protection** → enable Credential Guard + restrict local admin usage.  
- 🤖 **Automation** → validated that playbooks (MacroExecution, ReverseShellContainment, SusPrivEscalation) worked as intended.  
- 💾 **Backups** → confirm Azure Backup or snapshot strategy for quick recovery.  

</details>

---

## ✅ Final Status
Incident closed after containment, eradication, and recovery:  
![Incident closed screenshot](incident has been closed after initial remediation steps our next step is to remote onto the victim machine and restore the device to a healthy state.png)  

**Closure note:**  
> Threat actor infiltrated with malicious macro payload → reverse shell → persistence via tasks + accounts → LSASS dump → NGROK exfil. All remediations applied, host isolated and restored, IOCs blocked, admin accounts disabled.

---

## 🧩 Appendix
### 🔗 Playbooks used
- Playbook-MacroExecution  
- ReverseShellContainment  
- SusPrivEscalation  
- LSASS_Access_AutoRes  

### ⚔️ MITRE ATT&CK Mapping
- **Initial Access** → User Execution (T1204)  
- **Execution** → PowerShell (T1059)  
- **Persistence** → Scheduled Task (T1053)  
- **Credential Access** → LSASS Dump (T1003.001)  
- **Privilege Escalation** → Account Manipulation (T1136)  
- **Exfiltration** → Exfiltration over Alt Protocol (T1048)  

---

