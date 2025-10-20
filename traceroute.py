#!/usr/bin/env python3

from scapy.all import *

ttl = 1
while True:
  a = IP(dst='8.8.8.8', ttl=ttl)
  b = ICMP()
  p = a/b
  pkt = sr1(p, verbose=0)
  
  if pkt[ICMP].type == 0:
    print("Complete ", pkt[IP].src)
    break
  else:
    print("TTL: %d, Source: " %ttl, pkt[IP].src)
    ttl += 1
