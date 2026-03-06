#!/usr/bin/env python3
import os
import json
from datetime import date
from pathlib import Path

TODAY = date.today().isoformat()
ARTIFACT_ROOT = "artifacts"
STATE_FILE = f"{ARTIFACT_ROOT}/system/state.json"
INCIDENT_DIR = f"{ARTIFACT_ROOT}/incidents"

os.makedirs(INCIDENT_DIR, exist_ok=True)

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

def delta(current, previous):
    return current - previous if previous else 0

delta_ssh = delta(failed_ssh, previous_metrics.get("failed_ssh", 0))
delta_ports = delta(listening_ports, previous_metrics.get("listening_ports", 0))
delta_services = delta(running_services, previous_metrics.get("running_services", 0))
delta_suid = delta(suid_count, previous_metrics.get("suid_count", 0))

# === Threat Intelligence Engine ===
threats = []

if failed_ssh >= 20:
    threats.append("Brute Force Pattern Detected")

if listening_ports >= 15:
    threats.append("Service Exposure Increasing")

if suid_count >= 40:
    threats.append("Privilege Escalation Surface High")

if running_services >= 70:
    threats.append("Abnormal Service Density")

# Save threat record if any detected
if threats:
    threat_record = {
        "date": TODAY,
        "stage": current_stage,
        "risk": risk_score,
        "threats": threats
    }

    threat_file = f"{ARTIFACT_ROOT}/threats/threat_{TODAY}.json"

    with open(threat_file, "w") as f:
        json.dump(threat_record, f, indent=2)

# === Escalation Detection ===
escalation = previous_stage and previous_stage != current_stage

# === Maintain Rolling Risk History ===
risk_history = previous_data.get("risk_history", [])

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

def fmt_delta(value):
    if value > 0:
        return f" (+{value})"
    elif value < 0:
        return f" ({value})"
    else:
        return ""

# === Threat Output ===
threat_output = ""

if threats:
    for t in threats:
        threat_output += f"- {t}\n"
else:
    threat_output = "No active threat signatures detected.\n"

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

## 📈 14-Day Risk Trend
{trend_output}

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
