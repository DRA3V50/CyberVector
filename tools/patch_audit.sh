#!/bin/bash

mkdir -p artifacts/system

DATE=$(date +%F)
OUTPUT="artifacts/system/patch_audit_${DATE}.log"

OUTDATED=$(apt list --upgradable 2>/dev/null | grep -v "Listing..." | wc -l)

{
echo "[Patch Audit]"
echo "Date: ${DATE}"
echo "Upgradable Packages: ${OUTDATED}"
} > "$OUTPUT"
