"""Match ICMP echo requests and replies across existing tap and Geneve pcap files."""

import argparse
import json
from pathlib import Path
import sys

from . import correlate


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source_ip", help="inner IPv4 address of the echo sender")
    parser.add_argument("destination_ip", help="inner IPv4 address of the echo responder")
    parser.add_argument("--source-tap", type=Path, required=True)
    parser.add_argument("--destination-tap", type=Path, required=True)
    parser.add_argument("--geneve", nargs=2, action="append", default=[], metavar=("POINT", "PCAP"),
                        help="capture point on the same outer Geneve segment (repeat per point)")
    parser.add_argument("--destination-mac", help="MAC from the measured destination port binding")
    parser.add_argument("--summary", action="store_true", help="omit per-packet records")
    args = parser.parse_args()
    tunnels = dict(args.geneve)
    if len(tunnels) != len(args.geneve):
        parser.error("each Geneve capture point must have a unique name")
    try:
        result = correlate(args.source_ip, args.destination_ip, args.source_tap, args.destination_tap,
                           tunnels, args.destination_mac)
        if args.summary:
            del result["echoes"]
        json.dump(result, sys.stdout, indent=2)
        print()
    except (ValueError, OSError) as exc:
        parser.exit(2, f"{parser.prog}: {exc}\n")


if __name__ == "__main__":
    main()
