"""Construct and validate the probe declaration before any datagram is sent."""

import ipaddress
import secrets
import struct

from diagnosis.inventory import nic_inventory
from pathbuilder import EventLinker


MAX_PROBES = 10
MIN_INTERVAL_MS = 250
MAX_INTERVAL_MS = 5000
LOCAL_NETWORKS = tuple(
    ipaddress.IPv4Network(cidr)
    for cidr in ("127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16")
)


def _validate_endpoint(ip, port):
    if not isinstance(ip, str):
        raise ValueError("each endpoint requires a literal IPv4 address")
    address = ipaddress.IPv4Address(ip)
    if not any(address in network for network in LOCAL_NETWORKS):
        raise ValueError(f"{address} must be loopback, RFC 1918 private, or link-local")
    if type(port) is not int or not 1 <= port <= 65535:
        raise ValueError("UDP port must be between 1 and 65535")


def validate_plan(plan):
    if not isinstance(plan, dict) or not isinstance(plan.get("udp_replay"), dict):
        raise ValueError("the manifest must contain a udp_replay object")
    ids = plan["probe_ids"]
    if not isinstance(ids, list) or not 1 <= len(ids) <= MAX_PROBES:
        raise ValueError(f"a UDP replay must contain 1 to {MAX_PROBES} probe IDs")
    EventLinker(ids)  # The registration and send steps use the same ID rules.
    nic_inventory(plan["vm_nics"])
    flow = plan["udp_replay"]
    _validate_endpoint(flow["source_ip"], flow["source_port"])
    _validate_endpoint(flow["destination_ip"], flow["destination_port"])
    interval = flow["interval_ms"]
    if type(interval) is not int or not MIN_INTERVAL_MS <= interval <= MAX_INTERVAL_MS:
        raise ValueError(f"interval_ms must be between {MIN_INTERVAL_MS} and {MAX_INTERVAL_MS}")


def create_plan(source_ip, source_port, destination_ip, destination_port, vm_nics, count=10, interval_ms=250):
    if type(count) is not int or not 1 <= count <= MAX_PROBES:
        raise ValueError(f"count must be between 1 and {MAX_PROBES}")
    ids = []
    while len(ids) < count:
        probe_id = secrets.randbits(64)
        if probe_id not in ids:
            ids.append(probe_id)
    plan = {
        "vm_nics": vm_nics,
        "probe_ids": ids,
        "udp_replay": {
            "source_ip": source_ip, "source_port": source_port,
            "destination_ip": destination_ip, "destination_port": destination_port,
            "interval_ms": interval_ms,
        },
    }
    validate_plan(plan)
    return plan


def ipv4_probe_option(probe_id):
    # The IPv4 type and length are the first two bytes of the four-byte magic.
    return struct.pack("!BB2sQI", 0x1E, 16, b"VN", probe_id, 0)
