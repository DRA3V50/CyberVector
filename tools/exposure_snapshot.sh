#!/bin/bash

DATE=$(date +%F)

echo "===== Exposure Snapshot ====="
echo "Date: $DATE"
echo "Open Ports:"
ss -tuln | grep LISTEN
echo
echo "Active Connections:"
ss -tan | grep ESTAB
