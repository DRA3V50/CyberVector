#!/bin/bash

mkdir -p artifacts/system

OUTPUT="artifacts/system/system_$(date +%F).log"

echo "[System Collection]" > "$OUTPUT"
echo "Collection Time: $(date)" >> "$OUTPUT"
echo "----------------------------" >> "$OUTPUT"

echo "" >> "$OUTPUT"
echo "Running Services:" >> "$OUTPUT"
systemctl list-units --type=service --state=running 2>/dev/null >> "$OUTPUT"

echo "" >> "$OUTPUT"
echo "Installed Security Updates Available:" >> "$OUTPUT"
apt list --upgradable 2>/dev/null | grep security >> "$OUTPUT"

echo "" >> "$OUTPUT"
echo "SUID Files:" >> "$OUTPUT"
find / -perm -4000 2>/dev/null >> "$OUTPUT"

echo "" >> "$OUTPUT"
echo "Cron Jobs:" >> "$OUTPUT"
ls -la /etc/cron* 2>/dev/null >> "$OUTPUT"

echo "" >> "$OUTPUT"
echo "SSH Configuration Snippet:" >> "$OUTPUT"
grep -E "PermitRootLogin|PasswordAuthentication" /etc/ssh/sshd_config 2>/dev/null >> "$OUTPUT"
