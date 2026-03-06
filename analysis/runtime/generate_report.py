#!/usr/bin/env python3
import os
import json
from datetime import date
from pathlib import Path

TODAY = date.today().isoformat()
ARTIFACT_ROOT = "artifacts"

STATE_FILE = f"{ARTIFACT_ROOT}/system/state.json"
INCIDENT_DIR = f"{ARTIFACT_ROOT}/incidents"
THREAT_DIR = f"{ARTIFACT_ROOT}/threats"

os.makedirs(INCIDENT_DIR, exist_ok=True)
os.makedirs(THREAT_DIR, exist_ok=True)

def read_metric(file_path, key):
    if not os.path.exists(file_path):
        return 0
    with open(file_path) as f:
        for line in f:
            if key in line:
                return int(line.split(":")[1].strip())
    return 0


# === Collect today's metrics ===
auth_file = f"{ARTIFACT_ROOT}/auth/auth_{TODAY}.log"
network_file = f"{ARTIFACT_ROOT}/network/network_{TODAY}.log"
system_file = f"{ARTIFACT_ROOT}/system/system_{TODAY}.log"

failed_ssh = read_metric(auth_file, "Failed SSH Attempts")
listening_ports = read_metric(network_file, "Listening Ports")
running_services = read_metric(system_file, "Running Services")
suid_count = read_metric(system_file, "SUID Binaries")


# === Base Risk Calculation ===
base_risk = (failed_ssh * 3) + (listening_ports * 2) + (suid_count * 1.5)


# === Load Previous State ===
previous_data = {}

if os.path.exists(STATE_FILE):
    with open(STATE_FILE) as f:
        previous_data = json.load(f)

previous_stage = previous_data.get("stage")
previous_metrics = previous_data.get("metrics", {})
previous_risk = previous_data.get("risk_score", 0)


# === Momentum Risk Blending ===
risk_score = (previous_risk * 0.6) + (base_risk * 0.4)
risk_score = round(risk_score, 1)


# === Stage Engine ===
def determine_stage(score):

    if score < 40:
        stage = "GREEN"

    elif score < 100:
        stage = "YELLOW"

    elif score < 200:
        stage = "ORANGE"

    else:
        stage = "RED"

    if stage == "GREEN":
        status_msg = "Containment stable. No propagation detected."

    elif stage == "YELLOW":
        status_msg = "Anomalous activity increasing. Monitoring escalation."

    elif stage == "ORANGE":
        status_msg = "Sustained compromise indicators present. Containment at risk."

    else:
        status_msg = "Critical outbreak condition. Immediate intervention required."

    return stage, status_msg


current_stage, status_msg = determine_stage(risk_score)


# === Metric Delta Tracking ===
def delta(current, previous):
    return current - previous if previous else 0


delta_ssh = delta(failed_ssh, previous_metrics.get("failed_ssh", 0))
delta_ports = delta(listening_ports, previous_metrics.get("listening_ports", 0))
delta_services = delta(running_services, previous_metrics.get("running_services", 0))
delta_suid = delta(suid_count, previous_metrics.get("suid_count", 0))


# === Escalation Detection ===
escalation = previous_stage and previous_stage != current_stage


# === Threat Intelligence Engine ===
threats = []

if failed_ssh > 25:
    threats.append("⚠️ Possible SSH brute force activity")

if listening_ports > 20:
    threats.append("⚠️ Abnormally high number of open ports")

if suid_count > 40:
    threats.append("⚠️ Privilege escalation surface unusually large")

if running_services > 70:
    threats.append("⚠️ Excessive running services detected")

# === Propagation Simulation Engine ===

infection_score = (
    (listening_ports * 2) +
    (running_services * 0.5) +
    (suid_count * 1.2) +
    (failed_ssh * 1.5)
)

if infection_score < 50:
    infection_probability = "LOW"
elif infection_score < 120:
    infection_probability = "MODERATE"
else:
    infection_probability = "HIGH"

lateral_paths = int((listening_ports + running_services) / 20)

if lateral_paths < 2:
    exposure_surface = "MINIMAL"
elif lateral_paths < 5:
    exposure_surface = "MODERATE"
else:
    exposure_surface = "WIDE"

propagation_output = f"""
Host Infection Probability: {infection_probability}
Potential Lateral Movement Paths: {lateral_paths}
Exposure Surface: {exposure_surface}
"""

# === Containment Recommendation Engine ===
recommendations = []

if failed_ssh > 10:
    recommendations.append("Restrict SSH authentication attempts (fail2ban recommended)")

if listening_ports > 10:
    recommendations.append("Audit exposed ports and close unnecessary services")

if suid_count > 30:
    recommendations.append("Review SUID binaries for privilege escalation risks")

if running_services > 50:
    recommendations.append("Investigate excessive running services")

if infection_probability == "HIGH":
    recommendations.append("Consider host isolation or segmentation")

if not recommendations:
    recommendations.append("No containment actions required.")

containment_output = ""
for r in recommendations:
    containment_output += f"- {r}\n"

# === Adversary Behavior Classification ===
behaviors = []

if failed_ssh > 20:
    behaviors.append("Credential Access Activity (SSH brute force pattern)")

if suid_count > 30:
    behaviors.append("Privilege Escalation Activity (abnormal SUID surface)")

if running_services > 60:
    behaviors.append("Persistence Activity (service density anomaly)")

if listening_ports > 15:
    behaviors.append("Command and Control Exposure (network surface expansion)")

if infection_probability == "HIGH":
    behaviors.append("Lateral Movement Risk (high propagation probability)")

if not behaviors:
    behaviors.append("No adversary behavior patterns detected.")

behavior_output = ""
for b in behaviors:
    behavior_output += f"- {b}\n"

# === Save Threat Record ===
if threats:

    threat_record = {
        "date": TODAY,
        "stage": current_stage,
        "risk": risk_score,
        "threats": threats
    }

    threat_file = f"{THREAT_DIR}/threat_{TODAY}.json"

    with open(threat_file, "w") as f:
        json.dump(threat_record, f, indent=2)


# === Maintain Rolling Risk History ===
risk_history = previous_data.get("risk_history", [])
# === Campaign Detection Engine ===
CAMPAIGN_DIR = f"{ARTIFACT_ROOT}/campaigns"
os.makedirs(CAMPAIGN_DIR, exist_ok=True)

campaign_alert = ""

# Detect multi-day escalation patterns
if len(risk_history) >= 3:

    last3 = risk_history[-3:]

    r1 = last3[0]["risk"]
    r2 = last3[1]["risk"]
    r3 = last3[2]["risk"]

    if r1 < r2 < r3 and r3 >= 80:

        campaign_id = f"CVX-CAM-{TODAY}"
        campaign_file = f"{CAMPAIGN_DIR}/{campaign_id}.json"

        campaign_data = {
            "campaign_id": campaign_id,
            "type": "Escalating Intrusion Pattern",
            "start_date": last3[0]["date"],
            "end_date": TODAY,
            "risk_progression": [r1, r2, r3],
            "final_stage": current_stage
        }

        with open(campaign_file, "w") as f:
            json.dump(campaign_data, f, indent=2)

        campaign_alert = f"🚨 Attack campaign detected ({campaign_id})"
# Prevent duplicate same-day entries
if not risk_history or risk_history[-1]["date"] != TODAY:

    risk_history.append({
        "date": TODAY,
        "risk": risk_score,
        "stage": current_stage
    })

risk_history = risk_history[-14:]


# === Save Current State ===
with open(STATE_FILE, "w") as f:

    json.dump({
        "date": TODAY,
        "stage": current_stage,
        "risk_score": risk_score,
        "risk_history": risk_history,
        "metrics": {
            "failed_ssh": failed_ssh,
            "listening_ports": listening_ports,
            "running_services": running_services,
            "suid_count": suid_count
        }
    }, f, indent=2)


# === Create Incident if Stage Changed ===
incident_note = ""

if escalation:

    incident_id = f"INC-{TODAY}"
    incident_path = f"{INCIDENT_DIR}/{incident_id}.json"

    with open(incident_path, "w") as f:

        json.dump({
            "incident_id": incident_id,
            "date": TODAY,
            "previous_stage": previous_stage,
            "new_stage": current_stage,
            "risk_score": risk_score
        }, f, indent=2)

    incident_note = f"\n🚨 STAGE ESCALATION DETECTED: {previous_stage} → {current_stage}\n"


# === Incident Listing ===
incident_files = sorted(Path(INCIDENT_DIR).glob("INC-*.json"))

incident_list = ""

for file in incident_files:

    with open(file) as f:
        data = json.load(f)

        incident_list += f"- {data['incident_id']} ({data['previous_stage']} → {data['new_stage']})\n"

if not incident_list:
    incident_list = "No active incidents.\n"


# === Build Trend Output ===
trend_output = ""

for entry in risk_history:

    trend_output += f"- {entry['date']} → {entry['risk']} ({entry['stage']})\n"

# === IOC Generation Engine ===

ioc_records = []

if failed_ssh >= 20:
    ioc_records.append({
        "type": "Brute Force Indicator",
        "source": "SSH Authentication",
        "confidence": "Medium"
    })

if listening_ports >= 15:
    ioc_records.append({
        "type": "Exposure Indicator",
        "source": "Network Surface Expansion",
        "confidence": "Low"
    })

if suid_count >= 40:
    ioc_records.append({
        "type": "Privilege Escalation Indicator",
        "source": "SUID Binary Surface",
        "confidence": "High"
    })

if running_services >= 70:
    ioc_records.append({
        "type": "Persistence Indicator",
        "source": "Service Density",
        "confidence": "Medium"
    })

# Save IOC intelligence if indicators exist
if ioc_records:
    ioc_data = {
        "date": TODAY,
        "stage": current_stage,
        "risk_score": risk_score,
        "indicators": ioc_records
    }

    os.makedirs(f"{ARTIFACT_ROOT}/ioc", exist_ok=True)

    ioc_file = f"{ARTIFACT_ROOT}/ioc/ioc_{TODAY}.json"

    with open(ioc_file, "w") as f:
        json.dump(ioc_data, f, indent=2)

# === Threat Output ===
if threats:

    threat_output = ""

    for t in threats:
        threat_output += f"- {t}\n"

else:

    threat_output = "No active threat signatures detected.\n"


# === Format Delta ===
def fmt_delta(value):

    if value > 0:
        return f" (+{value})"

    elif value < 0:
        return f" ({value})"

    else:
        return ""


# === Dashboard Render ===
dashboard = f"""
<!-- CVX-REPORT-START -->
# 🕵️ CyberVector Containment Command

**Date:** {TODAY}  
**Containment Stage:** {current_stage}  
**Risk Score:** {risk_score}

{incident_note}

## 📊 Host Metrics
- Failed SSH Attempts: {failed_ssh}{fmt_delta(delta_ssh)}
- Listening Ports: {listening_ports}{fmt_delta(delta_ports)}
- Running Services: {running_services}{fmt_delta(delta_services)}
- SUID Binaries: {suid_count}{fmt_delta(delta_suid)}

## 🧬 Containment Status
{status_msg}
## 🧠 Threat Intelligence
{threat_output}
## 🔎 Indicators of Compromise (IOC)
{len(ioc_records)} indicators generated today.
## 📈 14-Day Risk Trend
{trend_output}
## 🎯 Campaign Intelligence
{campaign_alert if campaign_alert else "No active campaigns detected."}
## 🦠 Propagation Simulation
{propagation_output}
## 🛡️ Containment Recommendations
{containment_output}
## 📝 Adversary Behavior Profile
{behavior_output}
## 📂 Incident Log
{incident_list}
<!-- CVX-REPORT-END -->
"""


# === Inject Into README ===
with open("README.md", "r") as f:
    content = f.read()

start = "<!-- CVX-REPORT-START -->"
end = "<!-- CVX-REPORT-END -->"

if start in content and end in content:

    before = content.split(start)[0]
    after = content.split(end)[1]

    new_content = before + dashboard + after

else:

    new_content = content + dashboard


with open("README.md", "w") as f:
    f.write(new_content)
