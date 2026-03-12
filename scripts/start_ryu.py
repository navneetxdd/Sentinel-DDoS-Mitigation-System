#!/usr/bin/env python3
"""
Sentinel SDN Controller Startup Script
Verified for Python 3.13 and OS-Ken (with manual Ryu app restoration).
"""
import os
import sys
from pathlib import Path

# 1. Setup paths
# Note: This script assumes you have followed the setup in README.md
# and have the os-ken source in ~/os-ken-source
source_path = os.path.expanduser("~/os-ken-source")
manager_path = os.path.expanduser("~/Sentinel-DDoS-Mitigation-System/.venv/bin/osken-manager")

if not os.path.exists(source_path):
    print(f"[ERROR] OS-Ken source not found at {source_path}")
    print("Please follow the setup steps in README.md to clone and patch OS-Ken.")
    sys.exit(1)

# 2. Inject the source folder into Python's environment
# This allows successfully importing the patched 'os_ken' modules
os.environ["PYTHONPATH"] = source_path + ":" + os.environ.get("PYTHONPATH", "")

# 3. Define the applications to load
args = [
    sys.executable, 
    manager_path, 
    "os_ken.app.simple_switch_13", 
    "os_ken.app.ofctl_rest"
]

print(f"Starting OS-Ken Manager from {source_path}...")
print(f"Loading apps: {args[2:]}")

try:
    os.execv(sys.executable, args)
except Exception as e:
    print(f"[ERROR] Failed to start manager: {e}")
    sys.exit(1)
