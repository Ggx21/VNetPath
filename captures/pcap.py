"""Decode Ethernet/IPv4/ICMP and Geneve v0 from classic pcap (RFC 8926)."""
from __future__ import annotations

import hashlib
import ipaddress
from pathlib import Path
import struct


def require(data, count, what):
    if len(data) < count:
        raise ValueError(f"Truncated {what}: {len(data)} < {count}")


def ethernet(data, depth=0):
    require(data, 14, "Ethernet frame")
    protocol = int.from_bytes(data[12:14], "big")
    offset = 14
    vlans = []
    while protocol in (0x8100, 0x88A8):
        require(data, offset + 4, "VLAN header")
        vlans.append(int.from_bytes(data[offset:offset + 2], "big") & 0xFFF)
        protocol = int.from_bytes(data[offset + 2:offset + 4], "big")
        offset += 4
    if protocol != 0x0800:
        return None
    result = ipv4(data[offset:], depth)
    if result is not None:
        result.setdefault("ethernet", []).insert(0, {"source": data[6:12].hex(":"),
                                                    "destination": data[:6].hex(":"), "vlans": vlans})
    return result


def ipv4(data, depth=0):
    require(data, 20, "IPv4 header")
    if data[0] >> 4 != 4:
        raise ValueError("Expected IPv4")
    header_length = (data[0] & 0xF) * 4
    total_length = int.from_bytes(data[2:4], "big")
    if header_length < 20 or total_length < header_length:
        raise ValueError("Invalid IPv4 lengths")
    require(data, total_length, "IPv4 packet")
    fragments = int.from_bytes(data[6:8], "big")
    if fragments & 0x3FFF:
        raise ValueError("IPv4 fragments require reassembly")
    source = str(ipaddress.IPv4Address(data[12:16]))
    destination = str(ipaddress.IPv4Address(data[16:20]))
    body = data[header_length:total_length]
    if data[9] == 1:
        require(body, 8, "ICMP header")
        if body[0] not in (0, 8) or body[1] != 0:
            return None
        return {"source_ip": source, "destination_ip": destination,
                "ip_header_length": header_length, "ip_total_length": total_length,
                "icmp_type": body[0], "icmp_id": int.from_bytes(body[4:6], "big"),
                "icmp_sequence": int.from_bytes(body[6:8], "big"),
                "payload_sha256": hashlib.sha256(body[8:]).hexdigest(), "geneve_layers": []}
    if data[9] != 17:
        return None
    require(body, 8, "UDP header")
    source_port, destination_port, length, checksum = struct.unpack("!HHHH", body[:8])
    if destination_port != 6081:
        return None
    if length < 16:
        raise ValueError("Geneve UDP length too small")
    require(body, length, "UDP packet")
    geneve = body[8:length]
    if geneve[0] >> 6 != 0:
        raise ValueError("Unsupported Geneve version")
    if geneve[1] & 0x80:
        return None  # Geneve control packet, not an encapsulated tenant packet.
    option_length = (geneve[0] & 0x3F) * 4
    require(geneve, 8 + option_length, "Geneve options")
    if depth >= 4:
        raise ValueError("Nested Geneve depth exceeds decoder budget")
    protocol = int.from_bytes(geneve[2:4], "big")
    payload = geneve[8 + option_length:]
    if protocol == 0x6558:
        result = ethernet(payload, depth + 1)
    elif protocol == 0x0800:
        result = ipv4(payload, depth + 1)
    else:
        return None
    if result is not None:
        result["geneve_layers"].insert(0, {"source_ip": source, "destination_ip": destination,
                                         "udp_source_port": source_port, "udp_destination_port": destination_port,
                                         "vni": int.from_bytes(geneve[4:7], "big"),
                                         "option_length": option_length, "options_hex": geneve[8:8 + option_length].hex(),
                                         "outer_ip_header_length": header_length, "outer_ip_total_length": total_length,
                                         "udp_checksum": checksum})
    return result


def request_identity(packet):
    source, destination = packet["source_ip"], packet["destination_ip"]
    if packet["icmp_type"] == 0:
        source, destination = destination, source
    return source, destination, packet["icmp_id"], packet["icmp_sequence"], packet["payload_sha256"]


def read_packets(path, stats):
    """Yield decoded echo observations with frame numbers in the original capture."""
    formats = {b"\xd4\xc3\xb2\xa1": ("<", 1000), b"\xa1\xb2\xc3\xd4": (">", 1000),
               b"\x4d\x3c\xb2\xa1": ("<", 1), b"\xa1\xb2\x3c\x4d": (">", 1)}
    path = Path(path)
    file_size = path.stat().st_size
    with path.open("rb") as stream:
        header = stream.read(24)
        require(header, 24, "pcap global header")
        if header[:4] not in formats:
            raise ValueError(f"{path}: expected classic pcap")
        endian, fraction_ns = formats[header[:4]]
        major, minor, _, _, snaplen, link_type = struct.unpack(endian + "HHiIII", header[4:])
        if (major, minor, link_type) != (2, 4, 1):
            raise ValueError(f"{path}: expected pcap 2.4 with Ethernet link type")
        while record := stream.read(16):
            require(record, 16, "pcap record header")
            seconds, fraction, captured, original = struct.unpack(endian + "IIII", record)
            if captured > min(snaplen, original, file_size - stream.tell()) or fraction * fraction_ns >= 10**9:
                raise ValueError(f"{path}: invalid pcap record length or timestamp")
            raw = stream.read(captured)
            require(raw, captured, "pcap record")
            stats["frames"] += 1
            try:
                packet = ethernet(raw)
            except ValueError:
                stats["undecodable_frames"] += 1
                continue
            if packet is not None:
                packet.update(frame=stats["frames"], timestamp_ns=seconds * 10**9 + fraction * fraction_ns)
                yield packet
