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

auth_file = f"{ARTIFACT_ROOT}/auth/auth_{TODAY}.log"
network_file = f"{ARTIFACT_ROOT}/network/network_{TODAY}.log"
system_file = f"{ARTIFACT_ROOT}/system/system_{TODAY}.log"

failed_ssh = read_metric(auth_file, "Failed SSH Attempts")
listening_ports = read_metric(network_file, "Listening Ports")
running_services = read_metric(system_file, "Running Services")
suid_count = read_metric(system_file, "SUID Binaries")

risk_score = (failed_ssh * 3) + (listening_ports * 2) + (suid_count * 1.5)

def determine_stage(score):
    if score >= 300:
        return "RED"
    elif score >= 200:
        return "ORANGE"
    elif score >= 100:
        return "YELLOW"
    else:
        return "GREEN"

current_stage = determine_stage(risk_score)

previous_stage = None
if os.path.exists(STATE_FILE):
    with open(STATE_FILE) as f:
        previous_stage = json.load(f).get("stage")

# Detect escalation
escalation = False
if previous_stage and previous_stage != current_stage:
    escalation = True

# Save current state
with open(STATE_FILE, "w") as f:
    json.dump({
        "date": TODAY,
        "stage": current_stage,
        "risk_score": risk_score
    }, f, indent=2)

# Create incident if escalation
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
    incident_note = f"\n🚨 Incident Created: {incident_id}\n"

stage_narrative = {
    "GREEN": "Containment stable. No propagation detected.",
    "YELLOW": "Elevated activity detected. Monitoring escalation vectors.",
    "ORANGE": "Active containment required. Exposure surface expanding.",
    "RED": "Critical outbreak condition. Immediate intervention required."
}

dashboard = f"""
<!-- CVX-REPORT-START -->
# 🕵️ CyberVector Containment Command

**Date:** {TODAY}
**Containment Stage:** {current_stage}
**Risk Score:** {risk_score}

## 📊 Host Metrics
- Failed SSH Attempts: {failed_ssh}
- Listening Ports: {listening_ports}
- Running Services: {running_services}
- SUID Binaries: {suid_count}

## 🧬 Containment Status
{stage_narrative[current_stage]}

{incident_note}

<!-- CVX-REPORT-END -->
"""

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
