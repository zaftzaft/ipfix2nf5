import struct
import ipaddress
from scapy.all import *
from decoder import IPFIXDecoder

p = rdpcap("/home/kouta/Desktop/ipfix3.pcap")

proto = {
    1: "ICMP",
    2: "IGMP",
    6: "TCP",
    17: "UDP",
    89: "OSPF",
    118: "STP"
    }

ipfix = IPFIXDecoder()

for i in range(0, 10):
    ipfix.set_raw(bytes(p[i][Raw]))
    flows = ipfix.decode()

    for flow in flows:
        print("-----")
        isV4 = 8 in flow
        if not isV4:
            continue

        pr = struct.unpack("B", flow[4])[0]

        if pr is 6 or p is 17:
            src_port = struct.unpack(">H", flow[7])[0]
            dst_port = struct.unpack(">H", flow[11])[0]
            print(ipaddress.ip_address(flow[8]), src_port)
            print(ipaddress.ip_address(flow[12]), dst_port)

        print(proto[pr])
        octets = struct.unpack(">II", flow[85])[0]
        pkts = struct.unpack(">II", flow[86])[0]
        start = struct.unpack(">Q", flow[152])[0]
        end = struct.unpack(">Q", flow[153])[0]
        #print(flow)

