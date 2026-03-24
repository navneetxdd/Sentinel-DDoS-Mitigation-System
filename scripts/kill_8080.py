import os
import subprocess

try:
    output = subprocess.check_output("netstat -tlnp 2>/dev/null", shell=True).decode()
    for line in output.split('\n'):
        if ':8080' in line:
            parts = line.split()
            if len(parts) >= 7 and '/' in parts[-1]:
                pid = parts[-1].split('/')[0]
                print(f"Killing PID {pid}")
                os.system(f"kill -9 {pid}")
except Exception as e:
    print(e)
