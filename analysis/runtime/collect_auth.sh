#!/bin/bash

mkdir -p artifacts/auth

OUTPUT="artifacts/auth/auth_$(date +%F).log"

echo "[Auth Collection]" > "$OUTPUT"
echo "Collection Time: $(date)" >> "$OUTPUT"
echo "----------------------------" >> "$OUTPUT"

FAILED=$(grep "Failed password" /var/log/auth.log 2>/dev/null | wc -l)

echo "$FAILED" >> "$OUTPUT"

echo "" >> "$OUTPUT"
echo "Top Failed IP Sources:" >> "$OUTPUT"
grep "Failed password" /var/log/auth.log 2>/dev/null | \
awk '{print $(NF-3)}' | sort | uniq -c | sort -nr | head >> "$OUTPUT"
