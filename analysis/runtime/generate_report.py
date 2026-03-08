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

previous_stage = previous_data.get("stage")
previous_metrics = previous_data.get("metrics", {})
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


# === Outbreak Classification ===
if risk_score < 40:
    outbreak_class = "Baseline Activity"
elif risk_score < 100:
    outbreak_class = "Elevated Host Exposure"
elif risk_score < 200:
    outbreak_class = "Active Intrusion Environment"
else:
    outbreak_class = "Critical Compromise Condition"


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


# === Propagation Simulation ===
infection_score = (
    (listening_ports * 2)
    + (running_services * 0.5)
    + (suid_count * 1.2)
    + (failed_ssh * 1.5)
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


# === Adversary Behavior ===
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

behavior_output = "\n".join(f"- {b}" for b in behaviors)


# === Campaign Intelligence ===

CAMPAIGN_FILE = f"{ARTIFACT_ROOT}/campaigns/campaign_state.json"
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

campaign_pattern = []

for entry in campaign_history:
    if entry["ssh"] > 20:
        campaign_pattern.append("Credential Access")
    if entry["suid"] > 30:
        campaign_pattern.append("Privilege Escalation")
    if entry["ports"] > 15:
        campaign_pattern.append("Command and Control Exposure")
    if entry["services"] > 60:
        campaign_pattern.append("Persistence")

if len(set(campaign_pattern)) >= 2:
    campaign_output = f"""
Campaign ID: CVX-{TODAY}
Attack Pattern: {" → ".join(set(campaign_pattern))}
Confidence Level: MODERATE
"""
else:
    campaign_output = "No coordinated campaign activity detected."

with open(CAMPAIGN_FILE, "w") as f:
    json.dump({"history": campaign_history}, f, indent=2)


# === Dashboard Render ===
dashboard = f"""
<!-- CVX-REPORT-START -->
# 🕵️ CyberVector Containment Command

Date: {TODAY}  
Containment Stage: {current_stage}  
Risk Score: {risk_score}  
Exposure Index: {exposure_index}

## 🧬 Outbreak Classification
{outbreak_class}

## 📊 Host Metrics
- Failed SSH Attempts: {failed_ssh}
- Listening Ports: {listening_ports}
- Running Services: {running_services}
- SUID Binaries: {suid_count}

## 🧠 Threat Intelligence
{chr(10).join(f"- {t}" for t in threats) if threats else "No active threat signatures detected."}

## 🔎 Indicators of Compromise (IOC)
{ioc_count} indicators generated today.

## 🦠 Propagation Simulation
{propagation_output}

## 🎯 Campaign Intelligence
{campaign_output}

## 📝 Adversary Behavior Profile
{behavior_output}

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
