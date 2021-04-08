import dpkt, pcap, datetime
from dpkt.utils import mac_to_str, inet_to_str


cap = pcap.pcap(name=None, promisc=True, immediate=True, timeout_ms=50)
cap.setnonblock()

pkts = cap.readpkts()
print(len(pkts))

for timestamp, buf in pkts:
    eth = dpkt.ethernet.Ethernet(buf)
    if not isinstance(eth.data, dpkt.ip.IP):
        print('Non IP Packet type not supported %s\n' % eth.data.__class__.__name__)
        continue
    ip = eth.data
    if isinstance(ip.data, dpkt.tcp.TCP):
        tcp = ip.data
        try:
                request = dpkt.http.Request(tcp.data)
        except (dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError):
                continue
        print('HTTP request: %s\n' % repr(request))
