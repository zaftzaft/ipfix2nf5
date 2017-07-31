import struct
import ipaddress
import argparse
from scapy.all import *
from decoder import IPFIXDecoder
from flow_printer import flow_printer

parser = argparse.ArgumentParser()
parser.add_argument("file")
args = parser.parse_args()

p = rdpcap(args.file)

ipfix = IPFIXDecoder()

#for i in range(0, 10):
for i in range(0, len(p)):
    ipfix.set_raw(bytes(p[i][Raw]))
    flows = ipfix.decode()

    for flow in flows:
        flow_printer(flow)
