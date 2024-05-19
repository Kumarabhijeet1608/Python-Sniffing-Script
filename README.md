# Python-Wifi-Sniffing-Script

## Overview 👀🎯
This project uses Scapy to perform WiFi sniffing, specifically focusing on detecting probe requests from wireless devices. Probe requests are sent by devices searching for available WiFi networks, and capturing these can provide insights into network activity and device behavior.

## Requirements
**Wireless Network Card and set it to monitor mode.**
**Virtual Machine to Execute the Script.**
**Install Kali-Linux in the VM.**

## Python Script  ✔🔥
## Here's a simple Python Script using Scapy to sniff for WiFi probe requests.
 
from scapy.all import * 

interface = 'wlan0' 
probeReqs = []   

def sniffProbes(p):  
    if p.getlayer(Dot11ProbeReq):   
        netName = p.getlayer(Dot11ProbeReq).info
        if netName not in probeReqs:
            probeReqs.append(netName)
            print('[+] Detected New Probe Request: ' + netName)

sniff(iface=interface, prn=sniffProbes)

## Execution Steps in Kali Linux 👩‍💻👨‍💻

- ifconfig
- wlan0 (Wireless Setup)
- ifconfig wlan0 down                   # We are closing it.
- iwconfig wlan0 mode monitor           # Set it to monitor mode.
- ifconfig wlan0 up                     # We are turning it on.
- ifconfig                              # To check it for monitor mode.
- ls                                    # We need to execute the Python Script from the terminal.
- cd Desktop
- python [File Name.py]                 # To execute the script.


## Features 😎💰

### 1. **Packet Capture**
- Captures live network packets on a specified wireless interface.
- Utilizes Scapy, a powerful Python library for network packet manipulation.

### 2. **Probe Request Detection**
- Identifies and captures 802.11 probe request packets.
- Extracts the SSID (network name) from probe requests.

### 3. **Unique SSID Logging**
- Maintains a list of unique SSIDs detected from probe requests.
- Avoids duplicate entries by checking if the SSID is already logged.

### 4. **Real-time Notification**
- Prints a notification to the console whenever a new probe request with a unique SSID is detected.
- Provides real-time updates for immediate insights.


## Installation
To get started, clone the repository and install the required dependencies.

```bash
git clone https://github.com/yourusername/python-sniffing-project.git
cd python-sniffing-project
pip install -r requirements.txt
