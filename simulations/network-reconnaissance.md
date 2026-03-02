#!/bin/bash

mkdir -p artifacts/simulations

DATE=$(date +%F)
OUTPUT="artifacts/simulations/network_sim_${DATE}.log"

LISTEN_COUNT=$(ss -tuln 2>/dev/null | grep LISTEN | wc -l)
ESTABLISHED_COUNT=$(ss -tan 2>/dev/null | grep ESTAB | wc -l)

{
echo "[Network Simulation Metrics]"
echo "Date: ${DATE}"
echo "Listening Ports: ${LISTEN_COUNT}"
echo "Established Connections: ${ESTABLISHED_COUNT}"
} > "$OUTPUT"
