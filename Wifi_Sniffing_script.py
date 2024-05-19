from scapy.all import *                                         # Import the Python Library
interface = 'wlan0'                                             # Variable interface that has been set to the wireless internet interface.
probeReqs = []                                                  # It is also a variable which is an empty array. 

def sniffProves (p):                                            # This is our main methord.

        if p.haslayer(Dot11ProbeReq):                           #It defines the actual packages that we were looking for from the scapy.all library and It also requests for the network packages.
            netName = p.getlayer(Dot11ProbeReq).info
            if netName not in probeReqs:
                probeReqs.append(netName)
                print('[+] Detected New Probe Request:' + netName)

sniff(iface=interface, prn = sniffProbes)                       #A callback function that processes each captured packet to check for probe requests and prints new ones.