# get packets sends to use but for another ip
from scapy.sendrecv import AsyncSniffer

host_ip = '192.168.56.102'
host_mac = '08:00:27:d0:25:4b'

filter_requests = 'ip and not ip dst host %s and ether dst host %s' % (host_ip, host_mac)
print(filter_requests)
t = AsyncSniffer(filter=filter_requests,
                 prn=lambda x: x.summary(), iface='eth0')
t.start()
t.join()