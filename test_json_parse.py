#!/usr/bin/env python3
"""Quick test of JSON parsing"""

import json
import os

report_file = 'test/report.json'

print(f"File exists: {os.path.exists(report_file)}")
print(f"File size: {os.path.getsize(report_file)} bytes")

with open(report_file, 'r') as f:
    data = json.load(f)

print(f"Top-level type: {type(data)}")
if isinstance(data, dict):
    print(f"Top-level keys: {list(data.keys())}")
    if 'device' in data:
        print(f"Device: {data['device']}")
    if 'findings' in data:
        print(f"Number of findings: {len(data['findings'])}")
        print(f"First finding: {data['findings'][0]}")
