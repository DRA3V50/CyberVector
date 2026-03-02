import os
from datetime import date

today = date.today().isoformat()

def read_file(path):
    if os.path.exists(path):
        with open(path) as f:
            return f.read()
    return ""

def count_listen_ports(network_data):
    return network_data.count("LISTEN")

def count_running_services(system_data):
    return system_data.count(".service")

# File paths
auth_file = f"artifacts/auth/auth_{today}.log"
network_file = f"artifacts/network/network_{today}.log"
system_file = f"artifacts/system/system_{today}.log"

auth_data = read_file(auth_file)
network_data = read_file(network_file)
system_data = read_file(system_file)

# Extract failed SSH attempts (first numeric line)
failed_attempts = 0
for line in auth_data.splitlines():
    if line.strip().isdigit():
        failed_attempts = int(line.strip())
        break

listening_ports = count_listen_ports(network_data)
running_services = count_running_services(system_data)

# Composite Risk Calculation
risk_score = (failed_attempts * 2) + (listening_ports * 1.5) + (running_services * 0.5)

if risk_score > 150:
    risk_level = "🔴 Critical"
elif risk_score > 75:
    risk_level = "🟠 High"
elif risk_score > 30:
    risk_level = "🟡 Elevated"
else:
    risk_level = "🟢 Normal"

dashboard = f"""
## 📊 CyberVector Operational Dashboard
**Date:** {today}

---

### 🔍 Exposure Phase
| Metric | Value |
|--------|--------|
| Failed SSH Attempts | {failed_attempts} |
| Listening Ports | {listening_ports} |

---

### ⚙ System Posture
| Metric | Value |
|--------|--------|
| Running Services | {running_services} |

---

### 🛡 Containment Status
Composite Risk Score: **{risk_score}**  
Risk Level: **{risk_level}**

---

### 📂 Artifact References
- Auth Logs: `artifacts/auth/`
- Network Logs: `artifacts/network/`
- System Logs: `artifacts/system/`

_Last updated automatically via GitHub Actions._
"""

with open("README.md", "r") as f:
    readme = f.read()

start = "<!-- CVX-REPORT-START -->"
end = "<!-- CVX-REPORT-END -->"

if start in readme and end in readme:
    before = readme.split(start)[0]
    after = readme.split(end)[1]
    new_readme = before + start + dashboard + end + after

    with open("README.md", "w") as f:
        f.write(new_readme)
