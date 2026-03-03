#!/bin/bash

mkdir -p artifacts/system

DATE=$(date +%F)
OUTPUT="artifacts/system/system_${DATE}.log"

RUNNING_SERVICES=$(systemctl list-units --type=service --state=running 2>/dev/null | grep ".service" | wc -l)
SUID_COUNT=$(find / -perm -4000 2>/dev/null | wc -l)
INSTALLED_PACKAGES=$(dpkg -l 2>/dev/null | wc -l)

{
echo "[System Telemetry]"
echo "Date: ${DATE}"
echo "Running Services: ${RUNNING_SERVICES}"
echo "SUID Binaries: ${SUID_COUNT}"
echo "Installed Packages: ${INSTALLED_PACKAGES}"
} > "$OUTPUT"
