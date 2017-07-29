# Netflow v5 encoder
import struct
import ipaddress

def nf5encoder(flows):
    data = b"";

    default_record = {
        "src_addr": "0.0.0.0",
        "dst_addr": "0.0.0.0",
        "next_hop": "0.0.0.0",
        "input": 0,
        "output": 0,
        "pkts": 0,
        "octets": 0,
        "first": 0,
        "last": 0,
        "src_port": 0,
        "dst_port": 0,
        "tcp_flags": 0,
        "protocol": 0,
        "tos": 0,
        "src_as": 0,
        "dst_as": 0,
        "src_mask": 0,
        "dst_mask": 0
    }

    header = struct.pack(">HHIIIIBBH",
        0x0005,
        0x0001,
        0x00000000,
        0x00000000,
        0x00000000,
        0x00000000,
        0x00,
        0x00,
        0x0000
        )

    data += header

    for flow in flows:
        record = default_record.copy()

        for key, val in flow.items():
            record[key] = val

        data += struct.pack(">IIIHHIIIIHHBBBBHHBBH",
            int(ipaddress.IPv4Address(record.src_addr)),
            int(ipaddress.IPv4Address(record.dst_addr)),
            int(ipaddress.IPv4Address(record.next_hop)),
            record.input,
            record.output,
            record.pkts,
            record.octets,
            record.first,
            record.last,
            record.src_port,
            record.dst_port,
            0x00,
            record.tcp_flags,
            record.tos,
            record.src_as,
            record.dst_as,
            record.src_mask,
            record.dst_mask,
            0x0000
            )

    return data


