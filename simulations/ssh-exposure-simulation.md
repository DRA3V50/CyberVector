#!/bin/bash

mkdir -p artifacts/simulations

DATE=$(date +%F)
OUTPUT="artifacts/simulations/privilege_sim_${DATE}.log"

SUID_COUNT=$(find / -perm -4000 2>/dev/null | wc -l)
SUDO_ENTRIES=$(grep -vE '^#|^$' /etc/sudoers 2>/dev/null | wc -l)

{
echo "[Privilege Surface Simulation]"
echo "Date: ${DATE}"
echo "SUID Binaries: ${SUID_COUNT}"
echo "Active sudoers entries: ${SUDO_ENTRIES}"
} > "$OUTPUT"
