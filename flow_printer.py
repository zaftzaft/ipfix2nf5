import struct
import ipaddress

proto = {
    1: "ICMP",
    2: "IGMP",
    6: "TCP",
    17: "UDP",
    89: "OSPF",
    118: "STP"
    }

def flow_printer(flow):
    print("-----")
    isV4 = 8 in flow
    if not isV4:
        # IPv6 ?
        return False
        #continue

    pr = struct.unpack("B", flow[4])[0]

    if pr is 6 or pr is 17:
        src_port = struct.unpack(">H", flow[7])[0]
        dst_port = struct.unpack(">H", flow[11])[0]
        #print(ipaddress.ip_address(flow[8]), src_port)
        #print(ipaddress.ip_address(flow[12]), dst_port)
        print("{0}:{1} -> {2}:{3}".format(
            ipaddress.ip_address(flow[8]),
            src_port,
            ipaddress.ip_address(flow[12]),
            dst_port
            ))

    if pr in proto:
        print(proto[pr])
    else:
        print("undef proto", pr)
        print(flow)


    if 85 in flow:
        print(len(flow[85]), len(flow[86]))
        octets = struct.unpack(">I", flow[85])[0]
        pkts = struct.unpack(">I", flow[86])[0]
        print("octets:", octets, "pkts:", pkts)

    start = struct.unpack(">Q", flow[152])[0]
    end = struct.unpack(">Q", flow[153])[0]
