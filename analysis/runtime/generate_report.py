import os
from datetime import date

today = date.today().isoformat()

def read_value(file_path, key):
    if not os.path.exists(file_path):
        return 0
    with open(file_path) as f:
        for line in f:
            if key in line:
                return int(line.split(":")[1].strip())
    return 0

auth_file = f"artifacts/auth/auth_{today}.log"
network_file = f"artifacts/network/network_{today}.log"
system_file = f"artifacts/system/system_{today}.log"

failed_ssh = read_value(auth_file, "Failed SSH Attempts")
listening_ports = read_value(network_file, "Listening Ports")
running_services = read_value(system_file, "Running Services")
suid_count = read_value(system_file, "SUID Binaries")

risk_score = (failed_ssh * 2) + (listening_ports * 1.5) + (suid_count * 1)

if risk_score > 200:
    risk = "🔴 Critical"
elif risk_score > 100:
    risk = "🟠 High"
elif risk_score > 50:
    risk = "🟡 Elevated"
else:
    risk = "🟢 Normal"

dashboard = f"""
## 📊 CyberVector Operational Dashboard
**Date:** {today}

### 🔐 Authentication
- Failed SSH Attempts: {failed_ssh}

### 🌐 Network Exposure
- Listening Ports: {listening_ports}

### 🖥 System Surface
- Running Services: {running_services}
- SUID Binaries: {suid_count}

### 🚨 Composite Risk
Score: {risk_score}
Level: {risk}

---
_Last updated automatically_
"""

with open("README.md", "r") as f:
    content = f.read()

start = "<!-- CVX-REPORT-START -->"
end = "<!-- CVX-REPORT-END -->"

if start in content and end in content:
    before = content.split(start)[0]
    after = content.split(end)[1]
    new_content = before + start + dashboard + end + after

    with open("README.md", "w") as f:
        f.write(new_content)
