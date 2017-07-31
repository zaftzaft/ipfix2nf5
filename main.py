import socket
import struct
from decoder import IPFIXDecoder
import ipaddress
from flow_printer import flow_printer

ipfix = IPFIXDecoder()

bind_address = "0.0.0.0"
bind_port = 9400
buf = 30000

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((bind_address, bind_port))

while True:
    data, addr = sock.recvfrom(buf)

    ipfix.set_raw(data)

    flows = ipfix.decode()
    for flow in flows:
        flow_printer(flow)
