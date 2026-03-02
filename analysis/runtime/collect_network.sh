#!/bin/bash

mkdir -p artifacts/network

OUTPUT="artifacts/network/network_$(date +%F).log"

echo "[Network Collection]" > "$OUTPUT"
echo "Collection Time: $(date)" >> "$OUTPUT"
echo "----------------------------" >> "$OUTPUT"

echo "" >> "$OUTPUT"
echo "Listening Ports:" >> "$OUTPUT"
ss -tulnp 2>/dev/null >> "$OUTPUT"

echo "" >> "$OUTPUT"
echo "Firewall Status:" >> "$OUTPUT"
sudo ufw status 2>/dev/null >> "$OUTPUT"
