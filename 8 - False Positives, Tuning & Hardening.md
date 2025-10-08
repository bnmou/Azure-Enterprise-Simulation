# 🛡️ Phase 8 — False Positives, Tuning & Hardening  

---

## 🎯 Objective  

Phase 8 focuses on closing the exact gaps revealed during **Phase 2 – Attack Simulation and Threat Emulation**, where the attacker successfully exfiltrated sensitive data from NGROK, harvested credentials from LSASS, and leveraged legitimate user accounts to persist undetected.  

In this phase, we harden Wayne Enterprises’ environment by deploying **risk-based Conditional Access**, **FIDO2 authentication**, **DLP protections**, **extended log retention**, **password hygiene controls**, and **frequent system backups** — ensuring that the same attack paths used in Phase 2 can no longer succeed.  

---

## 🧩 Step 1 – Data Loss Prevention (DLP) for CUI and Key Material  

During Attack Simulation and Threat Emulation, the adversary exfiltrated CUI (Controlled Unclassified Information) and proprietary design files through NGROK without triggering alerts. To address this, a Microsoft Purview DLP policy was created to automatically detect, alert, and block any attempt to move sensitive information outside trusted boundaries.  

### 🔧 Implementation  
**Portal:** Microsoft Purview → Data Loss Prevention → Policies → Create Policy  

We begin by selecting a new DLP policy.  
<img width="395" height="706" alt="First step to creating our DLP policy" src="https://github.com/user-attachments/assets/3111a722-8c2e-411d-b2a3-8540bd5f32c3" />

We configure the type of data to protect.  
<img width="1912" height="962" alt="DLP step 1" src="https://github.com/user-attachments/assets/7770e2e4-794e-45ea-a97d-bf8c15992378" />

We then define the scope and data locations to include Exchange, SharePoint, OneDrive, Teams, and endpoint devices.  
<img width="1912" height="962" alt="locations for our DLP" src="https://github.com/user-attachments/assets/941614cf-88f9-4dbe-bb34-85156f9ab9ec" />

Finally, we define detection logic for CUI or schematic content containing symmetric keys or sensitive keywords, ensuring automatic alerts and blocking of outbound movement.  
<img width="1912" height="962" alt="CUI or schematic conent from wayne enterprises contain symmetric keys that will be caught by this custom DLP policy if it is extracted externally" src="https://github.com/user-attachments/assets/8f4399c1-b57d-43ae-8cd1-703ecc401b3c" />

Once complete, our policy goes live and actively protects sensitive data across the tenant.  
<img width="1912" height="962" alt="Our DLP policy is now live and active" src="https://github.com/user-attachments/assets/52999b13-e816-4cf0-82b0-57c6b20b0788" />

**🧠 Why:**  
This directly mitigates the Phase 2 data exfiltration technique — any attempt to upload CUI or design files to NGROK or other external channels now triggers automatic protection and alerting.  

---

## 🧱 Step 2 – Extended Log Retention for Long-Term Forensics  

In Phase 2, critical forensic evidence was lost due to limited log retention. Our logs were purged before a full investigation could be completed. To prevent this, we extend Sentinel’s retention window to preserve telemetry for up to **730 days**.  

Increasing our log retention period.
<img width="1912" height="962" alt="steps to take in order to increase our log retention period" src="https://github.com/user-attachments/assets/cc3be01e-f121-48b0-93b6-3ab61cf3e574" />

Log retention period is now set to 730 days.

<img width="386" height="384" alt="log retention status set to 730 days now" src="https://github.com/user-attachments/assets/2f344ef5-e779-4188-beea-ee83ca305741" />

**🧠 Why:**  
This ensures that future incidents — whether credential theft, persistence, or exfiltration — can be fully reconstructed without gaps in visibility.  

---

## 🔐 Step 3 – FIDO2 Authentication for Admins  

Phase 2 showed that stolen credentials (via LSASS dumping) could be reused to authenticate as legitimate users. To eliminate password-based attacks, we enforce **FIDO2 passkey authentication** for all admin and privileged accounts.  

We begin by accessing the Entra ID Admin Center.  
<img width="1912" height="962" alt="now in EntraID Admin center to begin enabling FIDO2 authentication for admins" src="https://github.com/user-attachments/assets/41d0c903-2700-4f35-9cc3-68c0a35ab832" />

We then enable and configure FIDO2 settings, allowing only hardware-based authenticators like YubiKeys for secure, phishing-resistant MFA.  
<img width="1912" height="962" alt="our FIDO2 settings" src="https://github.com/user-attachments/assets/645ce5b9-66d0-423b-9522-7aeab599ea40" />

**🧠 Why:**  
This control completely removes the attack surface exploited in Phase 2 — even if LSASS credentials are extracted, they are useless without the physical security key.  

---

## 🧠 Step 4 – Risk-Based Conditional Access Policies  

Next, we design a **risk-based Conditional Access (CA)** policy that adapts dynamically to sign-in context, device compliance, and insider risk levels. This ensures only secure, trusted sessions are allowed — a direct countermeasure against the lateral movement seen in Phase 2.  

### Creating the policy  
<img width="1912" height="962" alt="we are now creating our risk based conditional access policies" src="https://github.com/user-attachments/assets/8596fdfb-b4c4-493a-99f5-04c5fcfb9289" />

We scope the policy to include **all users**.  
<img width="662" height="529" alt="include all users" src="https://github.com/user-attachments/assets/88d2eb0f-837c-4437-8274-f521a4dc683e" />

We apply the policy to **all cloud resources** to ensure consistent enforcement across Microsoft 365 and Azure.  
<img width="632" height="489" alt="for all resources" src="https://github.com/user-attachments/assets/662241ba-6e5e-4c35-a9c5-f8c4c22cf71d" />

Trusted locations are excluded to avoid internal lockouts.  
<img width="650" height="527" alt="network exclusions" src="https://github.com/user-attachments/assets/4cabbfe4-de9f-4023-ad77-5e0eb53e4ba8" />

We then configure our five risk conditions for user, sign-in, and insider risk.  
<img width="1620" height="624" alt="condition 1" src="https://github.com/user-attachments/assets/8a9938af-83f2-4988-aed9-d7faed2d0404" />
<img width="1623" height="623" alt="condition 2" src="https://github.com/user-attachments/assets/602e6ed8-f55d-4f47-9aa5-ada7f04c21a2" />
<img width="1622" height="626" alt="condition 3" src="https://github.com/user-attachments/assets/6277f6ae-14de-490c-ad1b-78824fa2787f" />
<img width="1617" height="623" alt="condition 4" src="https://github.com/user-attachments/assets/adf3ad03-16ee-4163-b7f3-5b2e71e7ea5a" />
<img width="860" height="629" alt="condition 5" src="https://github.com/user-attachments/assets/6a7b004e-f5a1-45a8-9504-de98cda6dc0f" />

Access control requirements are set to **require MFA**, **device compliance**, and **Entra hybrid join** before granting access.  
<img width="1912" height="962" alt="the controls that will grant access requiring MFA device compliance and entra joined devices" src="https://github.com/user-attachments/assets/d21f4f35-47b7-4747-a0e8-a10d68b8d490" />

**🧠 Why:**  
In Phase 2, the attacker successfully authenticated from an untrusted system. With risk-based CA in place, any suspicious sign-in now triggers adaptive MFA or is blocked outright, depending on device posture and risk level.  

---

## 🔄 Step 5 – Password Hygiene & Rotation  

A 90-day password rotation policy is introduced to reduce the lifetime of any compromised credentials.  

We navigate to the Microsoft 365 Admin Center → Settings → Org Settings → Security & Privacy → Password expiration policy.  
<img width="1912" height="962" alt="steps to configure password reset policy" src="https://github.com/user-attachments/assets/439ee0ee-a32c-465b-b07c-85984e6e195e" />

We then define the rotation period to 90 days.  
<img width="589" height="330" alt="password expiration is now 90 days" src="https://github.com/user-attachments/assets/139c9d44-2aca-474b-955e-4b06122ca8a6" />

**🧠 Why:**  
In Phase 2, credential reuse and persistence were possible because passwords never expired. Now, any stolen credentials quickly become invalid, forcing reauthentication through secure MFA.  

---

## 💾 Step 6 – Frequent Backups and Disaster Recovery  

To ensure that Wayne Enterprises can recover from destructive actions or ransomware-style events, we configure Azure Backup policies for all critical VMs.  

Backups on a four hour frequency.
<img width="1912" height="962" alt="finally we configure a quick backup frequency policy to ensure our VMs always have a ready save state in the event of an incident" src="https://github.com/user-attachments/assets/b4f50a13-5531-409f-a5db-7ab745f02c79" />

**🧠 Why:**  
Phase 2 highlighted the risk of data destruction following privilege escalation. Frequent, automated backups ensure a known-good system state is always available for rapid restoration.  

---

## ⚙️ Step 7 – False Positives & Analytics Tuning  

After implementing stronger security controls, we focused on tuning Microsoft Sentinel and Defender analytics rules to reduce false positives without missing true malicious activity.  

This included:  
- Creating suppression logic for known benign PowerShell activity,  
- Adding watchlists for internal administrative tools,  
- Adjusting frequency and threshold parameters on repetitive detections,  
- Validating that only high-fidelity incidents reach Tier-1 SOC queue.  

**🧠 Why:**  
A mature SOC requires high-signal alerting. After Phase 2, where real malicious activity initially blended with noise, these tuning steps ensure analysts receive fewer false positives while maintaining high detection fidelity.  

---

## ✅ Summary  

| Control Implemented | Platform | Phase 2 Weakness Addressed | Result |
|----------------------|-----------|-----------------------------|--------|
| Microsoft Purview DLP | Microsoft 365 / Endpoint | Data exfiltration via NGROK | Blocks sensitive data uploads and alerts SOC |
| FIDO2 Authentication | Entra ID | LSASS credential theft | Passwordless authentication eliminates reuse |
| Conditional Access | Entra ID | Unmanaged device access | Risk-based policy enforces MFA and device compliance |
| 90-Day Password Rotation | Microsoft 365 | Credential persistence | Limits exposure of stolen credentials |
| Log Retention (730 Days) | Sentinel / Log Analytics | Short investigation window | Enables full forensic timeline |
| Azure VM Backup | Azure | Potential data destruction | Ensures rapid recovery from incident |

---

## 🧠 Final Thoughts  

Phase 8 transforms Wayne Enterprises’ cloud security posture from **reactive** to **resilient**.  
Each remediation directly ties back to the lessons learned during **Attack Simulation and Threat Emulation** — ensuring the same attack vectors can no longer succeed.  

---

**Next Phase:** [Phase 9 – Dashboarding & Reporting](https://github.com/bnmou/Azure-Enterprise-Simulation/blob/main/9%20-%20Dashboarding%20%26%20Reporting.md)
With these controls in place, the Wayne Enterprises SOC can now perform high-fidelity detection, confident triage, and sustained incident response — closing the loop on the full defensive lifecycle.

---

