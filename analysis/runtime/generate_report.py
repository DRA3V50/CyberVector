#!/usr/bin/env python3
import os
import json
import random
from datetime import date

TODAY = date.today().isoformat()

ARTIFACT_ROOT = "artifacts"
STATE_FILE = f"{ARTIFACT_ROOT}/system/state.json"
STATE_HISTORY_FILE = f"{ARTIFACT_ROOT}/system/state_changes.log"
TREND_FILE = f"{ARTIFACT_ROOT}/system/risk_history.log"

os.makedirs(f"{ARTIFACT_ROOT}/system", exist_ok=True)

# -----------------------------
# READ METRICS
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
# RISK ENGINE
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
# STAGE
# -----------------------------
def determine_stage(score):
    if score < 40:
        return "GREEN","🟢",1
    elif score < 100:
        return "YELLOW","🟡",2
    elif score < 200:
        return "ORANGE","🟠",3
    else:
        return "RED","🔴",4

current_stage,stage_emoji,current_phase = determine_stage(risk_score)

# -----------------------------
# STATUS (ESCALATION / CONTAINMENT)
# -----------------------------
status = "INITIAL"

if previous_stage:
    levels = {"GREEN":1,"YELLOW":2,"ORANGE":3,"RED":4}
    prev = levels[previous_stage]
    curr = levels[current_stage]

    if curr > prev:
        status = "ESCALATED"
    elif curr < prev:
        status = "CONTAINED"
    else:
        status = "MAINTAINED"

# -----------------------------
# SAVE STATE
# -----------------------------
with open(STATE_FILE,"w") as f:
    json.dump({
        "risk_score":risk_score,
        "stage":current_stage
    },f,indent=2)

# -----------------------------
# TREND ENGINE (FIXED SAFE PARSER)
# -----------------------------
if not os.path.exists(TREND_FILE):
    open(TREND_FILE, "w").close()

with open(TREND_FILE, "r") as f:
    trend_lines = [l.strip() for l in f.readlines() if l.strip()]

timestamp = f"{TODAY}_{random.randint(1000,9999)}"

# STORE WITH EXTRA DATA
trend_lines.append(f"{timestamp},{risk_score},{current_stage},{current_phase},{status}")

trend_lines = trend_lines[-14:]

with open(TREND_FILE, "w") as f:
    f.write("\n".join(trend_lines) + "\n")

emoji_map = {"GREEN":"🟢","YELLOW":"🟡","ORANGE":"🟠","RED":"🔴"}

phase_map = {
    1: "Host Security Posture",
    2: "Authentication Abuse",
    3: "Exposure Validation",
    4: "Patch Intelligence",
    5: "Compromise Simulation",
    6: "Propagation Modeling",
    7: "Lateral Movement",
    8: "Persistence Detection",
    9: "Privilege Escalation"
}

trend_output = ""

for i, line in enumerate(trend_lines, 1):
    parts = line.split(",")

    # SAFE PARSE (handles old + new formats)
    d = parts[0]
    s = parts[1]
    st = parts[2]

    phase = parts[3] if len(parts) > 3 else "?"
    stat = parts[4] if len(parts) > 4 else "UNKNOWN"

    trend_output += (
        f"- Day {i} | {d.split('_')[0]} | {emoji_map.get(st,'')} {s} "
        f"(→ {stat})\n"
        f"  ↳ Phase {phase}: {phase_map.get(int(phase), 'Unknown')}\n"
    )

# -----------------------------
# STATE CHANGE LOG
# -----------------------------
if not os.path.exists(STATE_HISTORY_FILE):
    open(STATE_HISTORY_FILE,"w").close()

with open(STATE_HISTORY_FILE,"r") as f:
    history = [l.strip() for l in f.readlines() if l.strip()]

entry = f"{TODAY} | {stage_emoji} {current_stage} ({status})"

if not history or history[-1] != entry:
    history.append(entry)

history = history[-10:]

with open(STATE_HISTORY_FILE,"w") as f:
    f.write("\n".join(history) + "\n")

state_output = "\n".join(f"- {l}" for l in history)

# -----------------------------
# DASHBOARD
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
