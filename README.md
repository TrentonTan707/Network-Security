Simulated various network based attacks using Python.

synflood.py
  Simulated a DoS attack by sending a flood of SYN packets in Python.
    Had to run multiple instances of the program in parellel to be able to send SYN packets fast enough to cause network disruption.
  Also written in C so packets could be generated and sent faster to be able to cause network disruption without needing multiple instances running in parallel.

tcprstauto.py
  Simulated a TCP reset attack that terminates an established TCP connection between two victims.
  Automated the attack using Scapy's sniff function to automatically terminate the TCP connection as soon as it is made.
    Scapy's sniff function foundd the required IP addresses, port numbers, and sequence and ACK numbers from the sniffed IP and TCP packets.

hijackshell.py
  Simulated a TCP session hijacking attack that opens a reverse shell on the victim's machine. This allowed the attacker to execute arbitrary commands on the victim's machine.

traceroute.py
  Simulated an ICMP traceroute program using Scapy by sending ICMP packets and incrementing TTL parameter by 1 until the ICMP packet reached the desired destination.

ARPsniffspoof.py
  Simpulated an ARP spoofing/ARP cache poisoning using Scapy's sniff function.
    Sniffed for ARP requests for a specific destination, spoofed an ARP reply to poison the ARP cache.
    
