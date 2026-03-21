#!/usr/bin/env python3
import os
import json
import random
from datetime import date

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


auth_file = f"{ARTIFACT_ROOT}/auth/auth_{TODAY}.log"
network_file = f"{ARTIFACT_ROOT}/network/network_{TODAY}.log"
system_file = f"{ARTIFACT_ROOT}/system/system_{TODAY}.log"

failed_ssh = read_metric(auth_file, "Failed SSH Attempts")
listening_ports = read_metric(network_file, "Listening Ports")
running_services = read_metric(system_file, "Running Services")
suid_count = read_metric(system_file, "SUID Binaries")


# -----------------------------
# Threat Campaign Engine
# -----------------------------
CAMPAIGN_FILE = f"{ARTIFACT_ROOT}/threats/campaign_state.json"

if os.path.exists(CAMPAIGN_FILE):
    with open(CAMPAIGN_FILE) as f:
        campaign_data = json.load(f)
else:
    campaign_data = {"active_campaign": None, "duration": 0}

campaign = campaign_data["active_campaign"]
duration = campaign_data["duration"]

if campaign is None:
    if random.randint(1,100) > 85:
        campaign = random.choice(["BRUTE_FORCE","LATERAL_MOVEMENT","PERSISTENCE","PRIV_ESC"])
        duration = random.randint(2,5)
else:
    duration -= 1
    if duration <= 0:
        campaign = None

campaign_data["active_campaign"] = campaign
campaign_data["duration"] = duration

with open(CAMPAIGN_FILE,"w") as f:
    json.dump(campaign_data,f,indent=2)

# Apply campaign effects
if campaign == "BRUTE_FORCE":
    failed_ssh += random.randint(25,80)
elif campaign == "LATERAL_MOVEMENT":
    listening_ports += random.randint(5,15)
elif campaign == "PERSISTENCE":
    running_services += random.randint(10,30)
elif campaign == "PRIV_ESC":
    suid_count += random.randint(5,15)


# -----------------------------
# IOC Engine
# -----------------------------
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

if ioc_list:
    with open(f"{IOC_DIR}/ioc_{TODAY}.txt", "w") as f:
        f.write("\n".join(ioc_list))

ioc_count = len(ioc_list)


# -----------------------------
# Risk Engine
# -----------------------------
base_risk = (failed_ssh * 4) + (listening_ports * 2.5) + (suid_count * 2)
volatility = random.randint(-10, 25)

previous_risk = 0
if os.path.exists(STATE_FILE):
    with open(STATE_FILE) as f:
        previous_risk = json.load(f).get("risk_score", 0)

risk_score = (previous_risk * 0.3) + (base_risk * 0.7) + volatility
risk_score = max(0, round(risk_score, 1))

exposure_index = round(risk_score * 1.2, 1)


# -----------------------------
# Containment Stage
# -----------------------------
def determine_stage(score):
    if score < 40:
        return "GREEN","🟢"
    elif score < 100:
        return "YELLOW","🟡"
    elif score < 200:
        return "ORANGE","🟠"
    else:
        return "RED","🔴"

current_stage,stage_emoji = determine_stage(risk_score)


# -----------------------------
# Investigation Path
# -----------------------------
def investigation_stage():
    path = ["1️⃣ Host Security Posture Evaluation"]
    reason = ""

    if failed_ssh > 15:
        path.append("2️⃣ Authentication Abuse Analysis")
        reason = f"Elevated SSH failures ({failed_ssh}) detected."

    if risk_score > 80:
        path.append("3️⃣ Exposure Validation")
        reason = f"Risk score elevated ({risk_score})."

    if listening_ports > 10:
        path.append("6️⃣ Propagation Modeling")

    if running_services > 50:
        path.append("8️⃣ Persistence Detection")

    if suid_count > 25:
        path.append("9️⃣ Privilege Escalation Review")

    if len(path) == 1:
        reason = "System operating within baseline thresholds."

    return path, reason

investigation_path, stage_reason = investigation_stage()
investigation = "\n".join(investigation_path)


# -----------------------------
# Threat Intelligence
# -----------------------------
threats = []

if failed_ssh > 25:
    threats.append("[HIGH] SSH brute force activity suspected")
if listening_ports > 20:
    threats.append("[MEDIUM] Exposed network surface increase")
if suid_count > 40:
    threats.append("[HIGH] Privilege escalation surface elevated")
if running_services > 70:
    threats.append("[MEDIUM] Service persistence risk")


# -----------------------------
# NEW: Containment Directive (10/10 feature)
# -----------------------------
actions = []

if failed_ssh > 15:
    actions.append("Investigate SSH logs and block offending IPs")

if listening_ports > 10:
    actions.append("Audit exposed ports and restrict unnecessary services")

if running_services > 50:
    actions.append("Review running services for persistence mechanisms")

if suid_count > 25:
    actions.append("Audit SUID binaries for privilege escalation risks")

if not actions:
    actions.append("Maintain baseline monitoring and continue observation")

priority_map = {
    "GREEN": "LOW",
    "YELLOW": "MEDIUM",
    "ORANGE": "HIGH",
    "RED": "CRITICAL"
}

priority = priority_map[current_stage]


# -----------------------------
# Trend Engine (rolling 14 runs)
# -----------------------------
trend_file = "artifacts/system/risk_history.log"

if not os.path.exists(trend_file):
    open(trend_file, "w").close()

with open(trend_file, "r") as f:
    lines = [l.strip() for l in f.readlines() if "," in l]

timestamp = f"{TODAY}_{random.randint(1000,9999)}"
lines.append(f"{timestamp},{risk_score},{current_stage}")
lines = lines[-14:]

with open(trend_file, "w") as f:
    f.write("\n".join(lines) + "\n")

emoji_map = {"GREEN":"🟢","YELLOW":"🟡","ORANGE":"🟠","RED":"🔴"}

trend_output = ""
for i, line in enumerate(lines, 1):
    d,s,st = line.split(",")
    trend_output += f"- Day {i} | {d.split('_')[0]} | {emoji_map[st]} {s} ({st})\n"


# -----------------------------
# Save State
# -----------------------------
with open(STATE_FILE,"w") as f:
    json.dump({"risk_score":risk_score},f,indent=2)


# -----------------------------
# Dashboard
# -----------------------------
dashboard=f"""
<!-- CVX-REPORT-START -->

# 🕵️ CyberVector Containment Command

**Date:** {TODAY}  
**Containment Stage:** {stage_emoji} {current_stage}

**Risk Score:** {risk_score}  
**Exposure Index:** {exposure_index}

---

## 🧪 Investigation Stage
{investigation}

**Reason:** {stage_reason}

---

## 📊 Telemetry Snapshot
- Failed SSH Attempts: {failed_ssh}
- Listening Ports: {listening_ports}
- Running Services: {running_services}
- SUID Binaries: {suid_count}

---

## 🦠 Threat Intelligence
{chr(10).join(f"- {t}" for t in threats) if threats else "No active threat signatures detected."}

---

## 🚨 Containment Directive
{chr(10).join(f"- {a}" for a in actions)}

**Operational Priority:** {priority}

---

## 📈 Containment Risk Timeline (14 Runs)
{trend_output}

<!-- CVX-REPORT-END -->
"""

with open("README.md") as f:
    content=f.read()

start="<!-- CVX-REPORT-START -->"
end="<!-- CVX-REPORT-END -->"

if start in content and end in content:
    before=content.split(start)[0]
    after=content.split(end)[1]
    new_content=before+dashboard+after
else:
    new_content=content+dashboard

with open("README.md","w") as f:
    f.write(new_content)
