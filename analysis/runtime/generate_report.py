import os
from datetime import date

today = date.today().isoformat()

auth_file = f"artifacts/auth/auth_{today}.log"
network_file = f"artifacts/network/network_{today}.log"
system_file = f"artifacts/system/system_{today}.log"

failed_count = 0
open_ports = 0
running_services = 0

# --- AUTH DATA ---
if os.path.exists(auth_file):
    with open(auth_file) as f:
        for line in f:
            if line.strip().isdigit():
                failed_count = int(line.strip())

# --- NETWORK DATA ---
if os.path.exists(network_file):
    with open(network_file) as f:
        for line in f:
            if "LISTEN" in line:
                open_ports += 1

# --- SYSTEM DATA ---
if os.path.exists(system_file):
    with open(system_file) as f:
        for line in f:
            if ".service" in line and "running" in line:
                running_services += 1

# --- RISK LOGIC ---
if failed_count > 50:
    risk = "🔴 High Risk"
elif failed_count > 10:
    risk = "🟡 Elevated"
else:
    risk = "🟢 Normal"

summary = f"""
### 📅 {today}

| Metric | Value |
|--------|--------|
| Failed SSH Attempts | {failed_count} |
| Listening Ports | {open_ports} |
| Running Services | {running_services} |
| Risk Level | {risk} |

_Last updated automatically via GitHub Actions._
"""

# --- Update README ---
with open("README.md", "r") as f:
    readme = f.read()

start = "<!-- CVX-REPORT-START -->"
end = "<!-- CVX-REPORT-END -->"

if start in readme and end in readme:
    before = readme.split(start)[0]
    after = readme.split(end)[1]
    new_readme = before + start + summary + end + after

    with open("README.md", "w") as f:
        f.write(new_readme)
