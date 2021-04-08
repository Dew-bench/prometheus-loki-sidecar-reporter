from prometheus_client import Counter
from prometheus_client import start_http_server

import dpkt, pcap, datetime
from dpkt.utils import mac_to_str, inet_to_str

import subprocess, os, signal
import time

# start prom. server
start_http_server(5000)

#   Metrics : 
# 
#  - Network :
#  packet src
#  packet dst
#  packet src port
#  packet dst port
#  packet timestamp
#  packet type (http header)
#  packet id (http header)
#  packet sender (http header)
#  
#  - Proc :
#  sec
#  insn per cycle
#  instructions
#  CPUs utilized

# watch -n 1 "curl --location --request GET 'www.google.com' --header 'prometheus-type: dfbfgn' --header 'prometheus-id: cfv' --header 'prometheus-sender: dfgb' --header 'Content-Type: application/json' --data-raw '{"val":-2}'"

PROMETHEUS_HTTP_HEADER_KEYS = [
    "prometheus-type",  # string, packet type
    "prometheus-id",  # int, packet id
    "prometheus-sender" # string, name sender
]

PROCESS_FILTER = ["none"]

#  TODO get pid of every process but this
# for process in psutil.process_iter ():
    # c=c+1
    # Name = process.name () # Name of the process
    # ID = process.pid # ID of the process

class Performance:
    def __init__(self):
        self.proc = None
        self.metrics = {}
        self.cmd = "perf stat -x, "
        self.cap = pcap.pcap(name=None, promisc=True, immediate=True, timeout_ms=50)
        self.cap.setnonblock()
        self.iana_prot_filter = [6] # only TCP
        self.perf_start_time = None
        self.pcap_last_received = 0
        # total number of packets received, dropped, and dropped by the interface

    def start_perf(self):
        self.perf_start_time = time.time()
        self.proc = subprocess.Popen(self.cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True, preexec_fn=os.setsid)
    
    def stop_perf(self):
        os.killpg(os.getpgid(self.proc.pid), signal.SIGINT)
        perf_out = self.proc.stderr.read()
        perf_out = perf_out.decode('ascii').split('\n')

        perf_descriptor = {}
        perf_descriptor["sec"] = time.time() - self.perf_start_time
        perf_descriptor["CPUs utilized"] = perf_out[0].split(',')[5]
        perf_descriptor["insn per cycle"] = perf_out[5].split(',')[5]
        perf_descriptor["instructions"] = perf_out[5].split(',')[0]
        
        self.add_perf_to_prom(perf_descriptor)

    def run(self):
        self.start_perf()

        while True: 

            # if we received new packets, proccess them
            if self.pcap_last_received < self.cap.stats()[0]:
                self.cap.dispatch(-1, self.packet_handler)
                self.pcap_last_received = self.cap.stats()[0]

            # after 60 seconds report perf stats and start perf
            if time.time() - self.perf_start_time > 60:
                self.stop_perf() 
                self.start_perf()
        
    def packet_handler(self, time, pkt):
        pckt_descriptor = {}

        eth = dpkt.ethernet.Ethernet(pkt) # eth frame

        if not isinstance(eth.data, dpkt.ip.IP):
            return # if eth pkt data not an IP frame
            
        if not eth.data.p in self.iana_prot_filter:  
            return # if ip data frame not an OK protocol
        
        ip = eth.data
        protocol_frame = ip.data

        try:
            request = dpkt.http.Request(protocol_frame.data)
        except (dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError):
            return

        headers = request.headers
        header_keys = headers.keys()

        pckt_descriptor["src"] = ip.src
        pckt_descriptor["dst"] = ip.dst
        pckt_descriptor["protocol"] = ip.p  # iana protocol number
        pckt_descriptor["timestamp"] = time

        for PR_KEY in PROMETHEUS_HTTP_HEADER_KEYS:
            if PR_KEY in header_keys:
                pckt_descriptor[PR_KEY] = headers[PR_KEY]
        
        self.add_packet_to_prom(pckt_descriptor)

    def add_packet_to_prom(self, pckt_descriptor):
        print(pckt_descriptor)

    def add_perf_to_prom(self, perf_descriptor):
        print(perf_descriptor)        


monitor = Performance()
monitor.run()
