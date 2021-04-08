import os
import psutil

print(os.getpid())

c=0
for process in psutil.process_iter ():
    c=c+1
    Name = process.name () # Name of the process
    ID = process.pid # ID of the process
    print ("Process name =", Name ,",","Process ID =", ID)
print ("\nTotal number of running process are ", c)

import subprocess
test = subprocess.Popen(["ping","-W","2","-c", "1", "192.168.0.1"], stdout=subprocess.PIPE)
output = test.communicate()[0]

print(output)


import subprocess

s = subprocess.check_output(["echo", "Hello World!"])

c=0
for process in psutil.process_iter ():
    c=c+1
    Name = process.name () # Name of the process
    ID = process.pid # ID of the process
    print ("Process name =", Name ,",","Process ID =", ID)
print ("\nTotal number of running process are ", c)
print(str(s))

import dpkt, pcap
pc = pcap.pcap()     # construct pcap object
pc.setfilter('icmp') # filter out unwanted packets
for timestamp, packet in pc:
    print(dpkt.ethernet.Ethernet(packet))
