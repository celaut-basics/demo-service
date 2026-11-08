#!/bin/sh
# Stop the child that run.sh started, and give the refund that the node answered.
echo "Content-Type: application/json"
echo
lease=$(sed -n 's/.*"lease": *\([0-9][0-9]*\).*/\1/p' /www/acquire.json)
if [ -z "$lease" ]; then
    echo '{"error": "no child"}'
    exit 0
fi
celaut stop "$lease" 2>&1
