#!/usr/bin/env python3
import os
import json
import random
from datetime import date

TODAY = date.today().isoformat()

ARTIFACT_ROOT = "artifacts"
STATE_FILE = f"{ARTIFACT_ROOT}/system/state.json"
TREND_FILE = f"{ARTIFACT_ROOT}/system/risk_history.log"

os.makedirs(f"{ARTIFACT_ROOT}/system", exist_ok=True)

# -----------------------------
# Stage Logic
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

stage_levels = {"GREEN":1,"YELLOW":2,"ORANGE":3,"RED":4}

# -----------------------------
# Load Previous State
# -----------------------------
previous_risk = 0
previous_stage = None

if os.path.exists(STATE_FILE):
    with open(STATE_FILE) as f:
        data = json.load(f)
        previous_risk = data.get("risk_score", 0)
        previous_stage = data.get("stage", None)

# -----------------------------
# Simulated Risk (keep yours)
# -----------------------------
risk_score = max(0, round(previous_risk * 0.7 + random.randint(10,60),1))

current_stage, stage_emoji = determine_stage(risk_score)

# -----------------------------
# Status + Phase Logic
# -----------------------------
if previous_stage:
    prev = stage_levels[previous_stage]
    curr = stage_levels[current_stage]

    if curr > prev:
        status = "ESCALATED"
    elif curr < prev:
        status = "CONTAINED"
    else:
        status = "MAINTAINED"
else:
    status = "INITIAL"

# Phase mapping (SMART LOGIC)
if current_stage == "RED":
    phase = random.randint(6,9)
elif current_stage == "ORANGE":
    phase = random.randint(5,7)
elif current_stage == "YELLOW":
    phase = random.randint(3,5)
else:
    phase = random.randint(1,3)

phase_map = {
    1:"Host Security Posture Evaluation",
    2:"Authentication Abuse Analysis",
    3:"Exposure Validation",
    4:"Patch Intelligence",
    5:"Compromise Simulation",
    6:"Propagation Modeling",
    7:"Lateral Movement Analysis",
    8:"Persistence Detection",
    9:"Privilege Escalation Review"
}

# -----------------------------
# TREND ENGINE (FIXED)
# -----------------------------
if not os.path.exists(TREND_FILE):
    open(TREND_FILE,"w").close()

with open(TREND_FILE,"r") as f:
    lines = [l.strip() for l in f.readlines() if l.strip()]

# ADD NEW ENTRY (NEW FORMAT)
timestamp = f"{TODAY}_{random.randint(1000,9999)}"
new_entry = f"{timestamp},{risk_score},{current_stage},{status},{phase}"
lines.append(new_entry)

# KEEP LAST 14
lines = lines[-14:]

with open(TREND_FILE,"w") as f:
    f.write("\n".join(lines) + "\n")

# -----------------------------
# BUILD DISPLAY (BACKWARD SAFE)
# -----------------------------
trend_output = ""

for i, line in enumerate(lines,1):
    parts = line.split(",")

    try:
        # NEW FORMAT
        if len(parts) >= 5:
            d, s, st, stat, ph = parts[:5]

        # OLD FORMAT (fallback)
        else:
            d, s, st = parts[:3]
            stat = "UNKNOWN"
            ph = "?"

        emoji = determine_stage(float(s))[1]
        date_clean = d.split("_")[0]

        # Safe phase handling
        try:
            ph_int = int(ph)
            phase_name = phase_map.get(ph_int,"Unknown")
        except:
            ph_int = "?"
            phase_name = "Unknown"

        trend_output += (
            f"- Day {i} | {date_clean} | {emoji} {s} "
            f"(→ {stat})\n"
            f"  ↳ Phase {ph_int}: {phase_name}\n"
        )

    except:
        continue

# -----------------------------
# SAVE STATE
# -----------------------------
with open(STATE_FILE,"w") as f:
    json.dump({
        "risk_score":risk_score,
        "stage":current_stage
    },f,indent=2)

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
