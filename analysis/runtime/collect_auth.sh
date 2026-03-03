#!/bin/bash

mkdir -p artifacts/auth

DATE=$(date +%F)
OUTPUT="artifacts/auth/auth_${DATE}.log"

FAILED_SSH=$(grep -i "Failed password" /var/log/auth.log 2>/dev/null | wc -l)
INVALID_USERS=$(grep -i "Invalid user" /var/log/auth.log 2>/dev/null | wc -l)
SUDO_COMMANDS=$(grep -i "sudo:" /var/log/auth.log 2>/dev/null | wc -l)

{
echo "[Authentication Telemetry]"
echo "Date: ${DATE}"
echo "Failed SSH Attempts: ${FAILED_SSH}"
echo "Invalid Users: ${INVALID_USERS}"
echo "Sudo Command Executions: ${SUDO_COMMANDS}"
} > "$OUTPUT"
