"""Send paired HTTP POST workloads for the packet-size experiment in Figure 4(b).

Start serve on the receiving machine, capture the selected flow there, then run
client on the sending machine. Each request gets a response before the next
send. Use python -m benchmarks.packet_sizes on the receiver's Ethernet pcap.
Linux requires CAP_NET_RAW on the sender to set the experimental IPv4 option.
"""

import argparse
import http.client
import json
import random
import socket
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

from replay.plan import ipv4_probe_option


def request_bytes(index, size):
    prefix = f"POST /{index:06d} HTTP/1.1\r\nHost: vnetpath\r\nContent-Length: "
    body_size = size - len(prefix) - 7
    if not 0 <= body_size <= 999:
        raise ValueError("request size cannot be encoded")
    return (prefix + f"{body_size:03d}\r\n\r\n").encode("ascii") + b"x" * body_size


class Endpoint(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    timeout = 8

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "-1"))
        if self.client_address[0] != self.server.peer or not 0 <= length <= 999:
            self.send_error(400)
            self.close_connection = True
            return
        body = self.rfile.read(length)
        if body != b"x" * length or len(self.path) != 7 or not self.path[1:].isdigit():
            self.send_error(400)
            self.close_connection = True
            return
        self.server.received += 1
        self.send_response_only(204)
        self.end_headers()

    def log_message(self, fmt, *args):
        pass


def serve(args):
    with HTTPServer((args.bind, args.port), Endpoint) as server:
        server.peer = args.peer
        server.received = 0
        server.timeout = 2
        deadline = time.monotonic() + args.timeout
        print(json.dumps({"ready": True, "port": server.server_port}), flush=True)
        while server.received < 2 * args.count and time.monotonic() < deadline:
            server.handle_request()
        print(json.dumps({"received": server.received}), flush=True)
        if server.received != 2 * args.count:
            raise RuntimeError("incomplete workload")


def send(args):
    generator = random.Random(args.seed)
    sizes = [generator.randint(104, 134) for _ in range(args.count)]
    for mode in ("baseline", "marked"):
        with socket.create_connection((args.peer, args.port), timeout=8,
                                      source_address=(args.bind, 0)) as sock:
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            for index, size in enumerate(sizes, 1):
                if mode == "marked":
                    sock.setsockopt(socket.IPPROTO_IP, socket.IP_OPTIONS, ipv4_probe_option(index))
                request = request_bytes(index, size)
                start = time.perf_counter_ns()
                sock.sendall(request)
                with http.client.HTTPResponse(sock) as response:
                    response.begin()
                    if response.status != 204 or response.read():
                        raise RuntimeError(f"unexpected response to request {index}")
                elapsed = time.perf_counter_ns() - start
                print(json.dumps({"mode": mode, "request": index, "payload_bytes": len(request),
                                  "response_ns": elapsed}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("role", choices=("serve", "client"))
    parser.add_argument("--bind", required=True, help="local experiment IPv4 address")
    parser.add_argument("--peer", required=True, help="other experiment endpoint")
    parser.add_argument("--port", type=int, default=18264)
    parser.add_argument("--count", type=int, default=1000, help="requests per condition")
    parser.add_argument("--seed", type=int, default=1)
    parser.add_argument("--timeout", type=int, default=90, help="receiver deadline in seconds")
    args = parser.parse_args()
    if not 1 <= args.count <= 999999 or args.timeout <= 0:
        parser.error("choose 1 to 999999 requests and a positive receiver timeout")
    (serve if args.role == "serve" else send)(args)


if __name__ == "__main__":
    main()
