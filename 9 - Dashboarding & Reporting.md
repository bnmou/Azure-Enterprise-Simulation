# 📊 Phase 9 — Dashboarding & Reporting

## 🎯 Objective

This phase focuses on transforming all previous detection, response, and automation data into **visual insights** using **Microsoft Sentinel Workbooks**.  
The goal was not to over-engineer the dashboard, but to present a clear, minimal, and professional snapshot of the **Wayne Enterprises SOC’s operational performance**.

The visuals created here combine **alert severity**, **playbook activity**, and **automated response verification** — giving both analysts and management a **one-glance understanding** of the environment’s security posture.

---

## 🧩 Workbook Design

**Data Sources Used:**

| Table | Purpose |
|-------|----------|
| `SecurityIncident` | Displays alert volume and severity |
| `AzureDiagnostics` | Displays Logic App (SOAR playbook) runs and their success/failure |

This combination showcases both **detection** and **automated response** metrics side-by-side, creating a **lightweight yet meaningful SOC dashboard**.

---

## 🧠 Step 1 — Security Incident Overview

The first visualization uses the **SecurityIncident** table to show how many incidents occurred across different severity levels (High, Medium, Low).

This quick breakdown gives the SOC team immediate **situational awareness** of active threats, helping analysts prioritize **high-severity incidents** before others.

**Query Used:**
```kql
SecurityIncident
| summarize Count = count() by Severity
```
📸 **Screenshot — Severity Distribution Pie Chart**  
<img width="1860" height="603" alt="our first data point is simple and just for alerts by severity" src="https://github.com/user-attachments/assets/24179e81-63fc-4f11-9897-be6025272169" />

The **pie chart visualization** provides a simple, color-coded representation of the environment’s alert severity distribution.

---

## ⚙️ Step 2 — Playbook Activity & Success Rate

The next visualization focuses on **automation telemetry** — specifically which playbooks were triggered and how often they succeeded or failed.

This uses the **AzureDiagnostics** table to monitor every Logic App run recorded under the **WorkflowRuntime** category.  
The result gives instant visibility into **SOAR effectiveness** and confirms that all playbooks configured in **Phase 5** and **Phase 8** are operating as expected.

**Query Used:**
```kql
AzureDiagnostics
| where Category == "WorkflowRuntime"
| where OperationName == "Microsoft.Logic/workflows/workflowRunCompleted"
| summarize Runs = count() by Playbook = resource_workflowName_s, Status = status_s
| order by Playbook asc
```
📸 **Screenshot — Playbook Success vs Failure Bar Chart**  
<img width="1912" height="962" alt="workbook query to monitor playbook usage" src="https://github.com/user-attachments/assets/c6733561-cfdc-43eb-bb8d-47c61f49ed5a" />

Each bar represents a **playbook** (e.g., `Playbook-MacroExecution`, `ReverseShellContainment`, `SuspPrivEscalation`), while colors indicate **success or failure counts**.  
This visualization validates that the **automated responses** configured throughout the project executed properly and without error.

---

## 📊 Step 3 — Combined Workbook View

The visuals were combined into a single workbook named **“Diagnostics.”**  
This unified dashboard gives a **minimal, elegant overview** of alerts and automation health within the simulated SOC.

📸 **Screenshot — Combined Workbook View**  
<img width="1912" height="962" alt="very simple diagnostics page for alert reporting and playbook usage" src="https://github.com/user-attachments/assets/567deaa6-31ce-4bdf-8c3f-934bed602894" />

The **Diagnostics workbook** was designed to be **visually clean** — ideal for **daily analyst check-ins** or **executive summaries**.  
It avoids unnecessary widgets and focuses solely on **clarity and operational relevance**.

---

## 🧾 Step 4 — Workbook Export & Reporting

Once the visuals were configured, the workbook was exported as a PDF report titled:

**`WayneEnterprises_Sentinel_Dashboard_Report.pdf`**

This report simulates what a **monthly or quarterly SOC summary** would look like — consolidating **incident metrics** and **playbook performance** into one presentable format.

---

## 💡 Insights & Value

| **Insight** | **Description** |
|--------------|-----------------|
| **Alert Visibility** | The severity chart provides a quick view of the current threat landscape. |
| **Automation Validation** | The playbook visualization confirms that SOAR workflows executed successfully. |
| **Operational Efficiency** | Combining incident and automation data allows rapid status checks. |
| **Simplicity Over Complexity** | A single, focused dashboard communicates full operational readiness. |

---

## ✅ Outcome

Phase 9 successfully demonstrates the **reporting and visualization layer** of the Azure SOC Operations Home Lab.

While earlier phases focused on **detections**, **responses**, and **playbooks**, this phase translates those technical outcomes into an **easy-to-digest operational summary** — the final step before concluding the project.
