#!/usr/bin/env bash
# Build a single-file executable for macOS or Linux. Output: dist/iot-scanner
set -euo pipefail
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt pyinstaller
pyinstaller --onefile --name iot-scanner \
  --add-data "app/static:app/static" \
  --collect-submodules uvicorn --hidden-import psutil \
  run.py
echo "Built dist/iot-scanner. Run it with: sudo ./dist/iot-scanner"
