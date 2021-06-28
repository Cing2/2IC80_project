
# 2IC80 - Man in the middle attacking tool

### Requirements
- python 3.5>=
- scapy 2.4.5>=


## Functionality

This tool can be used to perform man in the middle attacks, on a local network.

Including automatic arp poisoning, dns spoofing and ssl stripping.

Needed is to know the ip addresses of the targets.


## How to use:

The tool is commandline tool.

Type, python mitm_attack.py -h in a terminal to get the full help section and show all the arguments the tool takes.

A few example usages are:

mitm_attack.py -targets 192.168.56.101 192.168.56.102 -arp -dns 0 1 -dns_q * -dns_ip 192.168.56.103 
- This will arp poison the targets 192.168.56.101 and 192.168.56.102, as well as dns spoof any message 
  coming from them by responding with dns response with ip: 192.168.56.103 
  

mitm_attack.py -targets_file targets_ip.txt -arp -dns 0 -dns_q * -dns_ip 192.168.56.103 -ssl 0
- This will read the targets_ip.txt file for the targets and sets up arp poisoning between them. 
  It will also setup dns spoofing for the first target in the list, as given by the 0 index, as well as ssl strip message from this target.



