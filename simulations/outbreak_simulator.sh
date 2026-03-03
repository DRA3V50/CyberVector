#!/bin/bash

# CyberVector Controlled Outbreak Simulator
# This script artificially increases exposure metrics
# to test lifecycle escalation logic.

TODAY=$(date +%F)

AUTH_FILE="artifacts/auth/auth_${TODAY}.log"
NETWORK_FILE="artifacts/network/network_${TODAY}.log"
SYSTEM_FILE="artifacts/system/system_${TODAY}.log"

echo "⚠ Injecting simulated outbreak metrics..."

# Overwrite metrics with elevated values
echo "Failed SSH Attempts: 60" > $AUTH_FILE
echo "Listening Ports: 25" > $NETWORK_FILE

echo "Running Services: 80" > $SYSTEM_FILE
echo "SUID Binaries: 60" >> $SYSTEM_FILE

echo "Outbreak simulation complete."
