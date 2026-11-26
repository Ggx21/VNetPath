from collections import Counter, defaultdict
import ipaddress
from pathlib import Path
import re

from .pcap import read_packets, request_identity


_CONTEXT_FIELDS = ("source_ip", "destination_ip", "udp_source_port", "udp_destination_port", "vni", "options_hex")


def _point(path, tunnel, endpoints):
    stats = {"frames": 0, "undecodable_frames": 0, "other_layer_echoes": 0, "matching_echoes": 0}
    observations = defaultdict(lambda: {"request": [], "reply": []})
    for packet in read_packets(path, stats):
        identity = request_identity(packet)
        if identity[:2] != endpoints:
            continue
        if bool(packet["geneve_layers"]) != tunnel:
            stats["other_layer_echoes"] += 1
            continue
        direction = "request" if packet["icmp_type"] == 8 else "reply"
        observations[identity][direction].append({
            "frame": packet["frame"], "timestamp_ns": packet["timestamp_ns"],
            "ethernet": packet["ethernet"], "geneve_layers": packet["geneve_layers"],
        })
        stats["matching_echoes"] += 1
    return observations, stats


def _geneve_match(points, labels):
    if len(labels) < 2 or any(len(points[label]) != 1 for label in labels):
        return None
    stacks = {
        tuple(tuple(layer[field] for field in _CONTEXT_FIELDS) for layer in points[label][0]["geneve_layers"])
        for label in labels
    }
    return len(stacks) == 1


def correlate(source_ip, destination_ip, source_tap, destination_tap, geneve_points, destination_mac=None):
    """Group observations by inner endpoints, echo ID, sequence and payload digest.

    Tap files contain bare inner packets. Named tunnel files observe the same
    Geneve segment at different points. A missing frame remains unobserved.
    """
    endpoints = str(ipaddress.IPv4Address(source_ip)), str(ipaddress.IPv4Address(destination_ip))
    if endpoints[0] == endpoints[1]:
        raise ValueError("source and destination IP addresses must differ")
    if destination_mac is not None:
        destination_mac = destination_mac.lower()
        if not re.fullmatch(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}", destination_mac):
            raise ValueError("destination MAC must contain six colon-separated octets")
    paths = {"source_tap": source_tap, "destination_tap": destination_tap}
    if any(not label or label in paths for label in geneve_points):
        raise ValueError("Geneve capture labels must be nonempty and distinct from the tap labels")
    paths.update(geneve_points)
    # A file supplied twice would fabricate independent observation points.
    files = [Path(path).stat() for path in paths.values()]
    if len({(stat.st_dev, stat.st_ino) for stat in files}) != len(files):
        raise ValueError("supply a different pcap file for every capture point")
    captures = {}
    stats = {}
    for label, path in paths.items():
        captures[label], stats[label] = _point(path, label in geneve_points, endpoints)
    identities = sorted(set().union(*(set(group) for group in captures.values())))
    summary = dict.fromkeys(("source_request_identities", "unanchored_identities", "unique_requests_at_all_points",
                             "unique_replies_at_all_points", "destination_replies_with_matching_binding"), 0)
    tunnel_comparisons = {direction: Counter() for direction in ("request", "reply")}
    rows = []
    for identity in identities:
        row = {"icmp_id": identity[2], "sequence": identity[3], "payload_sha256": identity[4]}
        anchored = identity in captures["source_tap"] and bool(captures["source_tap"][identity]["request"])
        summary["source_request_identities" if anchored else "unanchored_identities"] += 1
        for direction in ("request", "reply"):
            points = {label: group[identity][direction] if identity in group else []
                      for label, group in captures.items()}
            agrees = _geneve_match(points, geneve_points)
            row[direction] = {"observations": points, "same_geneve_context": agrees}
            if anchored:
                if all(len(matches) == 1 for matches in points.values()):
                    key = "unique_requests_at_all_points" if direction == "request" else "unique_replies_at_all_points"
                    summary[key] += 1
                tunnel_comparisons[direction][{True: "consistent", False: "different", None: "unavailable"}[agrees]] += 1
        source = row["request"]["observations"]["source_tap"]
        dest_requests = row["request"]["observations"]["destination_tap"]
        dest_replies = row["reply"]["observations"]["destination_tap"]
        bound = None
        if destination_mac is not None and len(source) == len(dest_requests) == len(dest_replies) == 1:
            bound = (dest_requests[0]["ethernet"][-1]["destination"] == destination_mac
                     and dest_replies[0]["ethernet"][-1]["source"] == destination_mac)
        row["destination_reply_matches_binding"] = bound
        summary["destination_replies_with_matching_binding"] += bound is True
        rows.append(row)
    return {"type": "icmp_echo_capture_observations", "source_ip": endpoints[0], "destination_ip": endpoints[1],
            "destination_mac": destination_mac, "capture_points": stats, "summary": summary,
            "geneve_context_comparisons": tunnel_comparisons, "echoes": rows}
