# 📦 Phase 1: Initial Setup (Enterprise Network & Infrastructure)

This document outlines the **chronological setup** of the Azure-hosted enterprise network and attacker infrastructure. It includes detailed steps with screenshots for setting up the Wayne Enterprises resource group, Active Directory, virtual machines, networking, security controls, and Microsoft security tool integration.

---

## 1️⃣ Create Resource Group: Wayne Enterprises
The first step was to create a dedicated resource group for the enterprise environment.

- **Name:** `Wayne-Enterprises-RG`

📸 **Screenshot:** Azure Portal showing `Wayne-Enterprises-RG` in the Resource Groups list  
_`screenshots/phase1/wayne-resource-group.png`_

---

## 2️⃣ Deploy Domain Controller (Wayne-DC01)
Deployed the primary domain controller for the `wayne.corp` domain.

- **VM Name:** `Wayne-DC01`
- **OS:** Windows Server 2019
- **Role:** Domain Controller
- Placed in `Wayne-VNET` under `AD-Subnet`

📸 **Screenshot:** VM creation blade for Wayne-DC01  
_`screenshots/phase1/wayne-dc01-deployment.png`_

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
  _`screenshots/phase1/ad-ds-config.png`_
- `dsa.msc` with created users & OUs  
  _`screenshots/phase1/ad-users-ous.png`_

---

## 4️⃣ Create Additional Virtual Machines
After configuring AD, virtual machines for domain joining were deployed.

- **VMs Created:** `Wayne-Client-01`, `Wayne-Client-02`, etc.
- **OS:** Windows 10/11
- All under `Wayne-Enterprises-RG`

📸 **Screenshot:** VM list showing all workstations  
_`screenshots/phase1/vm-list.png`_

---

## 5️⃣ Create and Configure Wayne-VNET

- **Name:** `Wayne-VNET`
- **Address Space:** `10.0.0.0/24`
- **Subnets:**
  - `AD-Subnet`: `10.0.0.0/25`
  - `Workstations-Subnet`: `10.0.0.128/25`
- **DNS Setting:** Private IP of Wayne-DC01 to allow domain join

📸 **Screenshot:** VNet configuration showing custom DNS  
_`screenshots/phase1/wayne-vnet-dns.png`_

---

## 6️⃣ Domain Join Workstations
Each client VM was manually joined to the `wayne.corp` domain.

📸 **Screenshots:**
- System Properties → Domain Join screen  
  _`screenshots/phase1/domain-join.png`_
- Confirmation after domain join & restart  
  _`screenshots/phase1/domain-join-confirmation.png`_

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
