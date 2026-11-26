"""Create a replay manifest or send its marked IPv4 UDP probes."""

import argparse
import json
from pathlib import Path

from .plan import create_plan
from .sender import send_plan


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    plan = commands.add_parser("plan", help="write the declaration for registration, without sending")
    plan.add_argument("--source-ip", required=True, help="IPv4 address assigned to the sending host")
    plan.add_argument("--source-port", required=True, type=int)
    plan.add_argument("--destination-ip", required=True, help="one private, link-local or loopback IPv4 address")
    plan.add_argument("--destination-port", required=True, type=int)
    inventory = plan.add_mutually_exclusive_group(required=True)
    inventory.add_argument("--vm-nic", action="append", help="unique VM/container port name, repeatable")
    inventory.add_argument("--inventory", type=Path, help="JSON list of VM/container NICs from the deployment")
    plan.add_argument("--count", type=int, default=10, help="probe count, 1 to 10")
    plan.add_argument("--interval-ms", type=int, default=250, help="interval between packets, 250 to 5000 ms")
    plan.add_argument("--output", type=Path, required=True, help="new manifest path")

    send = commands.add_parser("send", help="bind the declared source and send to the manifest destination")
    send.add_argument("manifest", type=Path)
    send.add_argument("--receipt", type=Path, help="new JSONL file (default: MANIFEST.send.jsonl)")
    args = parser.parse_args()
    try:
        if args.command == "plan":
            vm_nics = args.vm_nic
            if args.inventory is not None:
                vm_nics = json.loads(args.inventory.read_text(encoding="utf-8"))
            manifest = create_plan(
                args.source_ip, args.source_port, args.destination_ip, args.destination_port,
                vm_nics, args.count, args.interval_ms,
            )
            with args.output.open("x", encoding="utf-8") as output:
                json.dump(manifest, output, indent=2)
                output.write("\n")
            print(f"Created {args.output} with {len(manifest['probe_ids'])} probe IDs")
        else:
            manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
            receipt = args.receipt or args.manifest.with_name(args.manifest.name + ".send.jsonl")
            count = send_plan(manifest, receipt)
            print(f"Kernel accepted {count} datagrams. Receipt: {receipt}")
    except (KeyError, TypeError, ValueError, OSError) as exc:
        parser.exit(2, f"{parser.prog}: {exc}\n")


if __name__ == "__main__":
    main()
