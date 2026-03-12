@echo off
title Sentinel Launch Manager
color 0A
echo ========================================================
2: title Sentinel Launch Manager
3: color 0A
4: echo ========================================================
5: echo   Sentinel DDoS Mitigation System - One-Click Launcher
6: echo ========================================================
7: echo.
8: 
9: echo [1/4] Verifying and Compiling C Backend Pipeline in WSL...
10: wsl -d kali-linux -u root -e bash -c "cd /mnt/c/Users/navne/Downloads/Sentinel-main && make pipeline"
11: 
12: echo.
13: echo [2/4] Launching C Backend Data Plane...
14: start cmd /k "title Sentinel C Backend && wsl -d kali-linux -u root -e bash -c 'cd /mnt/c/Users/navne/Downloads/Sentinel-main && sudo ./sentinel_pipeline -i lo -q 0 -w 8765'"
15: 
16: echo.
17: echo [3/4] Launching SHAP Explain API (Python)...
18: start cmd /k "title Sentinel Explain API && python explain_api.py --port 5001"
19: 
20: echo.
21: echo [4/4] Launching React Frontend Web UI...
22: start cmd /k "title Sentinel Frontend && cd frontend && npm run dev"
23: 
24: echo.
25: echo ========================================================
26: echo All subsystems launched!
27: echo ========================================================
28: echo.
29: echo Use THIS terminal window to launch Mininet or run tests.
30: echo.
31: echo Quick Commands:
32: echo   Start SDN Controller: wsl -d kali-linux -u root -e bash -c "cd /mnt/c/Users/navne/Downloads/Sentinel-main && python3 scripts/start_ryu.py"
33: echo   Open WSL Shell:       wsl -d kali-linux -u root
34: echo.
35: cmd /k
36: 
