# MT7601U Beacon Injection Patch

A minimal C-based toolkit for sending custom 802.11 beacon frames on **MT7601U** and similar low‑cost Wi‑Fi adapters.  
This patch enables beacon spam on devices that normally **cannot create VIF/VAP interfaces** and are limited to a single AP.

## Features
- Raw beacon frame injection  
- Manual 802.11 frame construction (radiotap + beacon header + IEs)  
- Multi‑SSID beacon broadcasting  
- Works on MT7601U chipset and most low‑end USB Wi‑Fi adapters  
- No external tools required (airmon-ng, mdk3/mdk4, aircrack-ng not needed)

## Requirements
- Linux  
- `libnl-3` and `libnl-genl-3`  
- MT7601U or compatible USB Wi‑Fi adapter  
- GCC / Make

Install dependencies (Debian/Ubuntu):
```bash
sudo apt install libnl-3-dev libnl-genl-3-dev build-essential
```

# Build

```bash
gcc -O2 spammer.c -o spammer -I/usr/include/libnl3 -lnl-3 -lnl-genl-3
```
# Usage

```sudo ./spammer```
