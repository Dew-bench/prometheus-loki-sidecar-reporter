import dpkt, pcap, datetime
from dpkt.utils import mac_to_str, inet_to_str

# https://dpkt.readthedocs.io/en/latest/_modules/dpkt/ip.html#IP

PROMETHEUS_HTTP_HEADER_KEYS = [
    "prometheus-type",  # string, packet type
    "prometheus-id",  # int, packet id
    "prometheus-sender" # string, name sender
]

class sniffer:
    def __init__(self, iana_prot_filter):
        self.cap = pcap.pcap(name=None, promisc=True, immediate=True, timeout_ms=50)
        self.cap.setnonblock()
        self.iana_prot_filter = iana_prot_filter

    def get_pkts(self):
        return self.cap.readpkts()

    def get_batch(self):
        pkts = self.get_pkts()
        pkts_final = []

        for time, pkt in pkts:
            pkt_final = {}

            eth = dpkt.ethernet.Ethernet(pkt) # eth frame

            if not isinstance(eth.data, dpkt.ip.IP):
                continue # if eth pkt data not an IP frame
                
            if not eth.data.p in self.iana_prot_filter:  
                continue # if ip data frame not an OK protocol
            
            ip = eth.data
            protocol_frame = ip.data

            try:
                request = dpkt.http.Request(protocol_frame.data)
            except (dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError):
                continue

            headers = request.headers
            header_keys = headers.keys()

            pkt_final["src"] = ip.src
            pkt_final["dst"] = ip.dst
            pkt_final["protocol"] = ip.p  # iana protocol number
            pkt_final["timestamp"] = time

            for PR_KEY in PROMETHEUS_HTTP_HEADER_KEYS:
                if PR_KEY in header_keys:
                    pkt_final[PR_KEY] = headers[PR_KEY]
            
            print(pkt_final)
            
            
    
