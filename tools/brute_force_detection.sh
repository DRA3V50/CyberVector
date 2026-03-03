#!/bin/bash

LOG="artifacts/auth/auth_$(date +%F).log"

if [ -f "$LOG" ]; then
    FAILED=$(grep "Failed SSH Attempts" "$LOG" | awk '{print $4}')
    if [ "$FAILED" -gt 20 ]; then
        echo "⚠ Possible brute-force activity detected."
    else
        echo "No brute-force threshold exceeded."
    fi
else
    echo "Auth log not found."
fi
