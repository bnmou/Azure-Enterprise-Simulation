# 📦 Phase 1: Initial Setup (Enterprise Network & Infrastructure)

This document outlines the **chronological setup** of the Azure-hosted enterprise network and attacker infrastructure. It includes detailed steps with screenshots for setting up the Wayne Enterprises resource group, Active Directory, virtual machines, networking, security controls, and Microsoft security tool integration.

---

## 1️⃣ Create Resource Group: Wayne Enterprises
The first step was to create a dedicated resource group for the enterprise environment.

- **Name:** `Wayne-Enterprises-RG`

📸 **Screenshot:** Azure Portal showing `Wayne-Enterprises-RG` in the Resource Groups list  
![image](https://github.com/user-attachments/assets/7a92adbb-2a30-4289-879d-0f70750f438a)



---

## 2️⃣ Deploy Domain Controller (Wayne-DC01)
Deployed the primary domain controller for the `wayne.corp` domain.

- **VM Name:** `Wayne-DC01`
- **OS:** Windows Server 2019
- **Role:** Domain Controller
- Placed in `Wayne-VNET` under `AD-Subnet`

📸 **Screenshot:** VM creation blade for Wayne-DC01  
![image](https://github.com/user-attachments/assets/02e884be-370e-4d18-b08d-4577f35bbc15)


---

## 3️⃣ Configure Active Directory on Wayne-DC01
Once deployed, Active Directory Domain Services was configured.

- Promoted to domain controller for `wayne.corp`
- Users created:
  - `Barbara.HR`
  - `Lucious.R&D`
  - `Bruce.FINANCE`
  - `WayneAdmin`
- OUs configured: `Users`, `Workstations`, `Admins`
- Applied password policy and auditing GPOs

📸 **Screenshots:**
- Server Manager showing AD DS role installed  
![image](https://github.com/user-attachments/assets/263dc3da-9273-40c5-81e1-19643e73bceb)

- `dsa.msc` with created users & OUs

![image](https://github.com/user-attachments/assets/ec2bbfd7-df46-439c-aeb5-0cabb8b6ee63)
![image](https://github.com/user-attachments/assets/2e4ae7b1-a045-4037-b750-bd3162f5b29f)
![image](https://github.com/user-attachments/assets/d61aa893-f8d2-4ef6-84a3-4a72a263b566)


---

## 4️⃣ Create Additional Virtual Machines
After configuring AD, virtual machines for domain joining were deployed.

- **VMs Created:** `Wayne-Client-01`, `Wayne-Client-02`, etc.
- **OS:** Windows 10/11
- All under `Wayne-Enterprises-RG`

📸 **Screenshot:** VM list showing all workstations  
![image](https://github.com/user-attachments/assets/41cee873-c176-4fad-900e-35acdac13c69)


---

## 5️⃣ Create and Configure Wayne-VNET

- **Name:** `Wayne-VNET`
- **Address Space:** `10.0.0.0/24`
- **Subnets:**
  - `AD-Subnet`: `10.0.0.0/25`
  - `Workstations-Subnet`: `10.0.0.128/25`
- **DNS Setting:** Private IP of Wayne-DC01 to allow domain join

📸 **Screenshot:** VNet configuration showing custom DNS  
![image](https://github.com/user-attachments/assets/8629073b-33d6-46f7-b4cb-d2285dfa6842)
![image](https://github.com/user-attachments/assets/2f99ea2c-0ec4-441b-8041-598f636361e4)


---

## 6️⃣ Domain Join Workstations
Each client VM was manually joined to the `wayne.corp` domain.

📸 **Screenshots:**
- System Properties → Domain Join screen  
![image](https://github.com/user-attachments/assets/ee55782c-cbe4-46db-9c93-0c0c97bae755)
- Confirmation after domain join & restart  
![image](https://github.com/user-attachments/assets/a6615d30-7bc6-4223-879f-60c57c39a14b)


---

## 7️⃣ Create and Apply NSG: WayneNSG

- **Name:** `WayneNSG`
- **Inbound Rule:** RDP (3389) allowed from your IP only (initially open to all)

📸 **Screenshot:** NSG configuration with rule highlighted  
_`screenshots/phase1/wayne-nsg-rules.png`_

---

## 8️⃣ Configure Microsoft Security Stack

### 🔹 Log Analytics Workspace (LAW)
- **Name:** `Wayne-LAW`
- Connected to all enterprise VMs

📸 Screenshot: LAW overview page  
_`screenshots/phase1/law-overview.png`_

### 🔹 Microsoft Sentinel
- Connected to `Wayne-LAW`
- Data connectors configured: Security Events, Defender, Sysmon

📸 Screenshot: Sentinel connectors page  
_`screenshots/phase1/sentinel-connectors.png`_

### 🔹 Defender for Endpoint (XDR)
- VMs onboarded with script
- Confirmed visibility in M365 Defender portal

📸 Screenshot: Defender endpoint list  
_`screenshots/phase1/xdr-devices.png`_

---

## 9️⃣ Setup Attacker Environment (Joker)

### 🔹 Create Joker Resource Group & VNet
- **Resource Group:** `Joker-RG`
- **VNet:** `Joker-VNET` – `10.1.0.0/24`
- No DNS configured; isolated

### 🔹 Create Joker-NSG
- **Inbound Rule:** SSH (22) allowed only from your IP

📸 Screenshot: Joker-NSG rule  
_`screenshots/phase1/joker-nsg.png`_

### 🔹 Deploy Kali Linux (Joker-Kali)
- Kali deployed into `Joker-VNET`
- Tools pre-installed (Metasploit, Nmap, etc.)

📸 Screenshot: Terminal view of tools  
_`screenshots/phase1/kali-terminal.png`_

---

## ✅ Final Validation
- Verified domain join success
- Logs arriving in Sentinel
- XDR reporting healthy status

📸 Screenshot: Sentinel logs validating activity  
_`screenshots/phase1/sentinel-log-validation.png`_

---

## ✅ Summary
This phase set the foundation for enterprise and adversary simulation:
- ✅ Azure infra setup (RGs, VNets, NSGs)
- ✅ AD Domain and user accounts
- ✅ Domain-joined clients
- ✅ SIEM + XDR integrated
- ✅ Kali attacker isolated for later simulation

**Next Phase:** [Phase 2 – Attack Simulation & Threat Emulation](https://github.com/bnmou/Azure-Enterprise-Simulation/blob/main/2%20-%20Attack%20Simulation%20%26%20Threat%20Emulation.md)
