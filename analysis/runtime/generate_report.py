#!/usr/bin/env python3
import os
import json
import random
from datetime import date

TODAY = date.today().isoformat()

ARTIFACT_ROOT = "artifacts"
STATE_FILE = f"{ARTIFACT_ROOT}/system/state.json"
STATE_HISTORY_FILE = f"{ARTIFACT_ROOT}/system/state_changes.log"

INCIDENT_DIR = f"{ARTIFACT_ROOT}/incidents"
THREAT_DIR = f"{ARTIFACT_ROOT}/threats"

os.makedirs(INCIDENT_DIR, exist_ok=True)
os.makedirs(THREAT_DIR, exist_ok=True)
os.makedirs(f"{ARTIFACT_ROOT}/system", exist_ok=True)

# -----------------------------
# Read Metrics
# -----------------------------
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
# Campaign Engine (UNCHANGED)
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

if campaign == "BRUTE_FORCE":
    failed_ssh += random.randint(25,80)
elif campaign == "LATERAL_MOVEMENT":
    listening_ports += random.randint(5,15)
elif campaign == "PERSISTENCE":
    running_services += random.randint(10,30)
elif campaign == "PRIV_ESC":
    suid_count += random.randint(5,15)

# -----------------------------
# Risk Engine
# -----------------------------
base_risk = (failed_ssh * 4) + (listening_ports * 2.5) + (suid_count * 2)
volatility = random.randint(-10, 25)

previous_risk = 0
previous_stage = None

if os.path.exists(STATE_FILE):
    with open(STATE_FILE) as f:
        data = json.load(f)
        previous_risk = data.get("risk_score", 0)
        previous_stage = data.get("stage", None)

risk_score = (previous_risk * 0.3) + (base_risk * 0.7) + volatility
risk_score = max(0, round(risk_score, 1))

# -----------------------------
# Stage
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
# STATE CHANGE ENGINE (FIXED 🔥)
# -----------------------------
stage_levels = {"GREEN":1,"YELLOW":2,"ORANGE":3,"RED":4}

# Ensure file exists
if not os.path.exists(STATE_HISTORY_FILE):
    with open(STATE_HISTORY_FILE,"w") as f:
        pass

# Read safely (FIX: no destructive filtering)
with open(STATE_HISTORY_FILE,"r") as f:
    state_lines = [l.strip() for l in f.readlines() if l.strip()]

if previous_stage:
    prev = stage_levels[previous_stage]
    curr = stage_levels[current_stage]

    if curr > prev:
        change_type = "Escalation"
    elif curr < prev:
        change_type = "Containment"
    else:
        change_type = "Maintained"

    change_entry = f"{TODAY} | {stage_emoji} {current_stage} ({change_type})"
else:
    change_entry = f"{TODAY} | {stage_emoji} {current_stage} (Initial State)"

# Prevent duplicate same-run entries (IMPORTANT FIX)
if not state_lines or state_lines[-1] != change_entry:
    state_lines.append(change_entry)

# Keep last 10 entries (rolling history)
if len(state_lines) > 10:
    state_lines = state_lines[-10:]

# Write back properly
with open(STATE_HISTORY_FILE,"w") as f:
    f.write("\n".join(state_lines) + "\n")

state_output = "\n".join(f"- {l}" for l in state_lines)

# -----------------------------
# Save State
# -----------------------------
with open(STATE_FILE,"w") as f:
    json.dump({
        "risk_score":risk_score,
        "stage":current_stage
    },f,indent=2)

# -----------------------------
# Dashboard
# -----------------------------
dashboard=f"""
<!-- CVX-REPORT-START -->

# 🕵️ CyberVector Containment Command

**Date:** {TODAY}  
**Containment Stage:** {stage_emoji} {current_stage}

**Risk Score:** {risk_score}

---

## 🔄 Containment State Changes
{state_output}

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
