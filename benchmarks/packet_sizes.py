"""Measure Figure 4(b)'s per-request overhead in a filtered Ethernet pcap.

Capture the client-to-server TCP flow on the receiver with full snap length
and Ethernet headers (DLT_EN10MB). Report raw frame lengths as saved by pcap.
"""

import argparse
import hashlib
import json
from pathlib import Path
import re
import struct

from replay.plan import ipv4_probe_option


def packets(path):
    byte_orders = {b"\xd4\xc3\xb2\xa1": "<", b"\xa1\xb2\xc3\xd4": ">",
                   b"\x4d\x3c\xb2\xa1": "<", b"\xa1\xb2\x3c\x4d": ">"}
    with path.open("rb") as source:
        header = source.read(24)
        if len(header) != 24 or header[:4] not in byte_orders:
            raise ValueError("expected a classic pcap")
        order = byte_orders[header[:4]]
        if struct.unpack_from(order + "I", header, 20)[0] != 1:
            raise ValueError("expected Ethernet link type")
        while record := source.read(16):
            if len(record) != 16:
                raise ValueError("incomplete pcap record header")
            _, _, captured, wire = struct.unpack(order + "IIII", record)
            if captured > 1_048_576 or captured != wire:
                raise ValueError("capture must include complete frames")
            data = source.read(captured)
            if len(data) != captured:
                raise ValueError("incomplete pcap record")
            yield data


def posts(path):
    for data in packets(path):
        ip = 14
        while data[ip - 2:ip] in (b"\x81\x00", b"\x88\xa8"):
            ip += 4
        if data[ip - 2:ip] != b"\x08\x00" or len(data) < ip + 20 or data[ip + 9] != 6:
            continue
        ihl = (data[ip] & 15) * 4
        tcp = ip + ihl
        end = ip + int.from_bytes(data[ip + 2:ip + 4], "big")
        if ihl < 20 or tcp + 20 > end or end > len(data):
            raise ValueError("invalid TCP/IP length")
        thl = (data[tcp + 12] >> 4) * 4
        if thl < 20 or tcp + thl > end:
            raise ValueError("invalid TCP header")
        payload = data[tcp + thl:end]
        if not payload:
            continue
        match = re.fullmatch(rb"POST /(\d{6}) HTTP/1\.1\r\nHost: vnetpath\r\nContent-Length: (\d{3})\r\n\r\n(x*)", payload)
        if not match or int(match[2]) != len(match[3]):
            raise ValueError("capture contains unrelated, split or coalesced TCP data")
        index = int(match[1])
        option = data[ip + 20:tcp]
        if option and (len(option) != len(ipv4_probe_option(index)) or option[:12] != ipv4_probe_option(index)[:12]):
            raise ValueError(f"unexpected IPv4 options for POST {index}")
        yield ("marked" if option else "baseline", index, len(data), end - ip,
               len(option), hashlib.sha256(payload).digest())


def compare(path, count):
    samples = {"baseline": {}, "marked": {}}
    for mode, index, *row in posts(path):
        if index in samples[mode]:
            raise ValueError(f"duplicate POST {index} in {mode}; inspect retransmissions")
        samples[mode][index] = row
    expected = set(range(1, count + 1))
    for mode, observed in samples.items():
        if observed.keys() != expected:
            raise ValueError(f"{mode} workload has {len(observed)} distinct POSTs; expected IDs 1..{count}")
    rows = []
    for index in sorted(expected):
        baseline, marked = (samples[mode][index] for mode in ("baseline", "marked"))
        if baseline[3] != marked[3]:
            raise ValueError(f"payload mismatch at POST {index}")
        if baseline[1] - baseline[2] != marked[1] - marked[2] or baseline[0] - baseline[1] != marked[0] - marked[1]:
            raise ValueError(f"TCP or link-layer overhead changed at POST {index}")
        rows.append({"request": index, "baseline_frame": baseline[0], "marked_frame": marked[0],
                     "baseline_ip": baseline[1], "marked_ip": marked[1], "option_bytes": marked[2],
                     "extra_frame_bytes": marked[0] - baseline[0],
                     "frame_overhead_pct": 100 * (marked[0] - baseline[0]) / baseline[0]})
    ranges = {key: [min(row[key] for row in rows), max(row[key] for row in rows)]
              for key in rows[0] if key != "request"}
    return {"paired_requests": count, "ranges": ranges}, rows


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("pcap", type=Path)
    parser.add_argument("--count", type=int, default=1000)
    parser.add_argument("--rows", type=Path, help="new JSONL file of paired measurements")
    args = parser.parse_args()
    if args.count < 1:
        parser.error("count must be positive")
    result, rows = compare(args.pcap, args.count)
    if args.rows:
        with args.rows.open("x", encoding="utf-8") as stream:
            for row in rows:
                print(json.dumps(row), file=stream)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
