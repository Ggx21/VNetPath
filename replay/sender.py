"""Send each declared probe once via an explicitly bound kernel UDP socket."""

import json
import socket
import time

from .plan import ipv4_probe_option, validate_plan


def _record(receipt, status, **fields):
    row = {"status": status, "timestamp_ms": time.time_ns() // 1_000_000, **fields}
    receipt.write(json.dumps(row) + "\n")
    receipt.flush()


def send_plan(plan, receipt_path):
    """Reserve a new JSONL receipt before touching the socket. Stop at the first send error."""
    validate_plan(plan)
    flow = plan["udp_replay"]
    source = (flow["source_ip"], flow["source_port"])
    destination = (flow["destination_ip"], flow["destination_port"])
    ids = plan["probe_ids"]
    with receipt_path.open("x", encoding="utf-8") as receipt:
        _record(receipt, "start", udp_replay=flow, probe_ids=ids)
        sent = 0
        probe = None
        try:
            option = getattr(socket, "IP_OPTIONS", None)
            if option is None:
                raise OSError("this Python/socket platform does not expose IPv4 IP_OPTIONS")
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.bind(source)
                for probe in ids:
                    if sent:
                        time.sleep(flow["interval_ms"] / 1000)
                    _record(receipt, "attempt", probe_ID=probe)
                    sock.setsockopt(socket.IPPROTO_IP, option, ipv4_probe_option(probe))
                    payload = b"VNetPath UDP probe"
                    if sock.sendto(payload, destination) != len(payload):
                        raise OSError("the kernel did not accept the full UDP datagram")
                    sent += 1
                    _record(receipt, "accepted_by_kernel", probe_ID=probe)
        except OSError as exc:
            _record(receipt, "failed", probe_ID=probe, accepted_count=sent, errno=exc.errno, error=str(exc))
            raise
        _record(receipt, "finished", accepted_count=sent)
    return sent
