#!/bin/bash

mkdir -p artifacts/network

DATE=$(date +%F)
OUTPUT="artifacts/network/network_${DATE}.log"

LISTENING_PORTS=$(ss -tuln 2>/dev/null | grep LISTEN | wc -l)
ESTABLISHED_CONN=$(ss -tan 2>/dev/null | grep ESTAB | wc -l)
PUBLIC_IP=$(curl -s ifconfig.me 2>/dev/null)

{
echo "[Network Telemetry]"
echo "Date: ${DATE}"
echo "Listening Ports: ${LISTENING_PORTS}"
echo "Established Connections: ${ESTABLISHED_CONN}"
echo "Public IP: ${PUBLIC_IP}"
} > "$OUTPUT"
