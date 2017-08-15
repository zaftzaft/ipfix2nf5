import socket
import struct
import ipaddress
import argparse
from encoder import nf5encoder
from decoder import IPFIXDecoder
from flow_printer import flow_printer

parser = argparse.ArgumentParser()

parser.add_argument("-s", "--saddr", required=False, help="bind address", default="0.0.0.0")
parser.add_argument("-p", "--sport", required=False, type=int, help="bind port", default=9400)
parser.add_argument("--buf", required=False, type=int, help="buffer size", default=30000)

parser.add_argument("daddr")
parser.add_argument("dport", type=int)
args = parser.parse_args()


ipfix = IPFIXDecoder()

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((args.saddr, args.sport))

def exporter(flow):
    if not 4 in flow:
        # not IP
        return False

    protocol = struct.unpack("B", flow[4])[0]
    src_port = 0
    dst_port = 0

    # UDP TCP ICMP
    if not protocol in (6, 17, 1):
        # not supported protocol
        return False

    # 8 is IPv4 src addr
    if not 8 in flow:
        # ipv6 isnt support
        return False

    src_addr = ipaddress.ip_address(flow[8])
    dst_addr = ipaddress.ip_address(flow[12])

    if protocol in (6, 17):
        src_port = struct.unpack(">H", flow[7])[0]
        dst_port = struct.unpack(">H", flow[11])[0]

    octetsFmt = ">I" if len(flow[85]) is 4 else ">Q"
    pktsFmt = ">I" if len(flow[86]) is 4 else ">Q"

    octets = struct.unpack(octetsFmt, flow[85])[0]
    pkts = struct.unpack(pktsFmt, flow[86])[0]

    start = int(struct.unpack(">Q", flow[152])[0] / 1000)
    end = int(struct.unpack(">Q", flow[153])[0] / 1000)

    return {
        "src_addr": src_addr,
        "dst_addr": dst_addr,
        "pkts": pkts,
        "octets": octets,
        "src_port": src_port,
        "dst_port": dst_port,
        "protocol": protocol,
        "first": start,
        "last": end
    }



while True:
    data, addr = sock.recvfrom(args.buf)

    ipfix.set_raw(data)
    flows = ipfix.decode()

    for flow in flows:
        flow_printer(flow)

        nf5 = exporter(flow)
        if nf5:
            try:
                sock.sendto(nf5encoder([nf5]), (args.daddr, args.dport))
            except: 
                pass



