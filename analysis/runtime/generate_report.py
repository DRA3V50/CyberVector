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
# Simulated Risk (UNCHANGED CORE)
# -----------------------------
base_risk = random.randint(20, 120)
volatility = random.randint(-10, 25)

risk_score = (previous_risk * 0.3) + (base_risk * 0.7) + volatility
risk_score = max(0, round(risk_score, 1))

current_stage, stage_emoji = determine_stage(risk_score)

# -----------------------------
# Save State
# -----------------------------
with open(STATE_FILE,"w") as f:
    json.dump({
        "risk_score":risk_score,
        "stage":current_stage
    },f,indent=2)

# -----------------------------
# TREND ENGINE (14 RUN FIXED)
# -----------------------------
if not os.path.exists(TREND_FILE):
    open(TREND_FILE, "w").close()

with open(TREND_FILE, "r") as f:
    trend_lines = [l.strip() for l in f.readlines() if "," in l]

timestamp = f"{TODAY}_{random.randint(1000,9999)}"
trend_lines.append(f"{timestamp},{risk_score},{current_stage}")

# KEEP LAST 14 RUNS
trend_lines = trend_lines[-14:]

with open(TREND_FILE, "w") as f:
    f.write("\n".join(trend_lines) + "\n")

# -----------------------------
# PHASE MAPPING (SMART)
# -----------------------------
def map_phase(score):
    if score < 40:
        return "Phase 1: Host Security Posture"
    elif score < 70:
        return "Phase 4: Patch Intelligence"
    elif score < 120:
        return "Phase 6: Propagation Modeling"
    elif score < 200:
        return "Phase 7: Lateral Movement Analysis"
    else:
        return "Phase 9: Privilege Escalation Review"

# -----------------------------
# BUILD TIMELINE OUTPUT
# -----------------------------
trend_output = ""

for i, line in enumerate(trend_lines, 1):
    d, s, st = line.split(",")

    emoji = {"GREEN":"🟢","YELLOW":"🟡","ORANGE":"🟠","RED":"🔴"}[st]

    # Determine change vs previous entry
    if i == 1:
        change = "Initial"
    else:
        prev_stage = trend_lines[i-2].split(",")[2]
        prev_lvl = stage_levels[prev_stage]
        curr_lvl = stage_levels[st]

        if curr_lvl > prev_lvl:
            change = "Escalation"
        elif curr_lvl < prev_lvl:
            change = "Containment"
        else:
            change = "Maintained"

    phase = map_phase(float(s))

    trend_output += (
        f"- Day {i} | {d.split('_')[0]} | {emoji} {s} ({change})\n"
        f"  ↳ {change.upper()} | {phase}\n"
    )

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

# -----------------------------
# Inject into README
# -----------------------------
with open("README.md") as f:
    content = f.read()

start="<!-- CVX-REPORT-START -->"
end="<!-- CVX-REPORT-END -->"

if start in content and end in content:
    before = content.split(start)[0]
    after = content.split(end)[1]
    new_content = before + dashboard + after
else:
    new_content = content + dashboard

with open("README.md","w") as f:
    f.write(new_content)
