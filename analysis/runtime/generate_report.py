#!/usr/bin/env python3
import os
import json
import random
from datetime import date
from pathlib import Path

TODAY = date.today().isoformat()
ARTIFACT_ROOT = "artifacts"

STATE_FILE = f"{ARTIFACT_ROOT}/system/state.json"
INCIDENT_DIR = f"{ARTIFACT_ROOT}/incidents"
THREAT_DIR = f"{ARTIFACT_ROOT}/threats"

os.makedirs(INCIDENT_DIR, exist_ok=True)
os.makedirs(THREAT_DIR, exist_ok=True)
os.makedirs("analysis/runtime", exist_ok=True)


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


# === Adversary Simulation Engine ===
attack_roll = random.randint(1,100)

if attack_roll > 85:
    failed_ssh += random.randint(15,60)

if attack_roll > 70:
    listening_ports += random.randint(2,8)

if attack_roll > 60:
    running_services += random.randint(5,20)

if attack_roll > 80:
    suid_count += random.randint(2,10)


# === IOC Generation Engine ===
IOC_DIR = f"{ARTIFACT_ROOT}/ioc"
os.makedirs(IOC_DIR, exist_ok=True)

ioc_list = []

if failed_ssh > 20:
    ioc_list.append(f"{TODAY} | Credential Attack Pattern | SSH failures: {failed_ssh}")

if listening_ports > 15:
    ioc_list.append(f"{TODAY} | Network Exposure | Listening ports: {listening_ports}")

if suid_count > 30:
    ioc_list.append(f"{TODAY} | Privilege Escalation Surface | SUID binaries: {suid_count}")

if running_services > 60:
    ioc_list.append(f"{TODAY} | Persistence Indicator | Services running: {running_services}")

IOC_FILE = f"{IOC_DIR}/ioc_{TODAY}.txt"

if ioc_list:
    with open(IOC_FILE, "w") as f:
        for ioc in ioc_list:
            f.write(ioc + "\n")

ioc_count = len(ioc_list)


# === Base Risk Calculation ===
base_risk = (failed_ssh * 3) + (listening_ports * 2) + (suid_count * 1.5)


# === Load Previous State ===
previous_data = {}

if os.path.exists(STATE_FILE):
    with open(STATE_FILE) as f:
        previous_data = json.load(f)

previous_risk = previous_data.get("risk_score", 0)


# === Momentum Risk Blending ===
risk_score = (previous_risk * 0.6) + (base_risk * 0.4)
risk_score = round(risk_score, 1)


# === Exposure Index ===
exposure_index = round(risk_score * 1.15, 1)


# === Stage Engine ===
def determine_stage(score):

    if score < 40:
        stage = "GREEN"
        emoji = "🟢"
    elif score < 100:
        stage = "YELLOW"
        emoji = "🟡"
    elif score < 200:
        stage = "ORANGE"
        emoji = "🟠"
    else:
        stage = "RED"
        emoji = "🔴"

    if stage == "GREEN":
        status_msg = "Containment stable. No propagation detected."
    elif stage == "YELLOW":
        status_msg = "Anomalous activity increasing. Monitoring escalation."
    elif stage == "ORANGE":
        status_msg = "Sustained compromise indicators present. Containment at risk."
    else:
        status_msg = "Critical outbreak condition. Immediate intervention required."

    return stage, emoji, status_msg


current_stage, stage_emoji, status_msg = determine_stage(risk_score)


# === Threat Intelligence ===
threats = []

if failed_ssh > 25:
    threats.append("[HIGH] SSH brute force activity suspected")

if listening_ports > 20:
    threats.append("[MEDIUM] Unusual number of exposed network ports")

if suid_count > 40:
    threats.append("[HIGH] Elevated privilege escalation surface")

if running_services > 70:
    threats.append("[MEDIUM] Abnormally dense service environment")


# === Campaign Intelligence Engine ===
CAMPAIGN_FILE = f"{ARTIFACT_ROOT}/campaigns/campaign_state.json"
os.makedirs(f"{ARTIFACT_ROOT}/campaigns", exist_ok=True)

campaign_data = {}

if os.path.exists(CAMPAIGN_FILE):
    with open(CAMPAIGN_FILE) as f:
        campaign_data = json.load(f)

campaign_history = campaign_data.get("history", [])

today_activity = {
    "date": TODAY,
    "ssh": failed_ssh,
    "ports": listening_ports,
    "services": running_services,
    "suid": suid_count,
}

campaign_history.append(today_activity)
campaign_history = campaign_history[-7:]

with open(CAMPAIGN_FILE, "w") as f:
    json.dump({"history": campaign_history}, f, indent=2)


campaign_output = "No coordinated campaign activity detected."

if failed_ssh > 40 and listening_ports > 10:
    campaign_output = "Credential abuse activity consistent with distributed SSH probing."

elif suid_count > 35 and running_services > 60:
    campaign_output = "Post-compromise persistence activity detected across host services."

elif risk_score > 120:
    campaign_output = "Multi-vector intrusion indicators detected. Possible coordinated campaign."


# === 14-Day Risk Trend (Reset After 14) ===
trend_file = "analysis/runtime/risk_trend.log"

if not os.path.exists(trend_file):
    open(trend_file, "w").close()

with open(trend_file, "r") as f:
    lines = f.readlines()

if len(lines) >= 14:
    lines = []

lines.append(f"{TODAY},{risk_score},{current_stage}\n")

with open(trend_file, "w") as f:
    f.writelines(lines)

emoji_map = {
    "GREEN": "🟢",
    "YELLOW": "🟡",
    "ORANGE": "🟠",
    "RED": "🔴"
}

for i, line in enumerate(lines, start=1):
    date_val, score_val, stage_val = line.strip().split(",")
    trend_output += f"- Day {i} | {date_val} | {emoji_map[stage_val]} {score_val} ({stage_val})\n"


# === Incident Log Engine ===
incident_file = "analysis/runtime/incidents.log"

if not os.path.exists(incident_file):
    open(incident_file, "w").close()

if risk_score >= 100:
    with open(incident_file, "a") as f:
        f.write(f"INC-{TODAY} ({current_stage}) Risk Score: {risk_score}\n")

with open(incident_file, "r") as f:
    incidents = f.readlines()[-10:]

incident_output = ""

if incidents:
    for entry in incidents:
        incident_output += f"- {entry}"
else:
    incident_output = "No incidents recorded."

# === Save State ===
with open(STATE_FILE, "w") as f:
    json.dump({"risk_score": risk_score}, f, indent=2)


# === Dashboard Render ===
dashboard = f"""
<!-- CVX-REPORT-START -->

# 🕵️ CyberVector Containment Command

**Date:** {TODAY}  
**Containment Stage:** {stage_emoji} {current_stage}  
**Risk Score:** {risk_score}  
**Exposure Index:** {exposure_index}

---

## 📊 Host Metrics
- Failed SSH Attempts: {failed_ssh}
- Listening Ports: {listening_ports}
- Running Services: {running_services}
- SUID Binaries: {suid_count}

---

## 🧬 Threat Intelligence
{chr(10).join(f"- {t}" for t in threats) if threats else "No active threat signatures detected."}

---

## 🔎 Indicators of Compromise (IOC)
{ioc_count} indicators generated today.

---

## 🎯 Campaign Intelligence
{campaign_output}

---

## 📈 14-Day Risk Trend
{trend_output}

---

## 📂 Incident Log
{incident_output}

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
