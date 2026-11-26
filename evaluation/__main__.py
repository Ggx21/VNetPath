"""Compare VNetPath diagnosis locations to the device port recorded at fault injection."""

import argparse
import json
import sys
from pathlib import Path

from . import score
from .reference import compare_published


def _read(path):
    return json.loads(path.read_text(encoding="utf-8"))


def main():
    parser = argparse.ArgumentParser(description=__doc__,
        epilog="Optional trial.baselines entries: Traceroute with expected_ip and reported_ip; "
               "Zoonet with expected_device and reported_device. A null reported location is a measured miss. "
               "An absent observation is counted as missing. All declared trials enter each requested denominator.")
    parser.add_argument("trials", type=Path, help="JSON rows with trial_id, ground_truth {phy_device_ID,port_name}, "
                        "optional environment, fault_type (Table II, 1-15), observed failure_type "
                        "(Disconnection, Delay, Packet Loss), and prediction")
    parser.add_argument("--predictions", type=Path, help="JSON VNetPath reports keyed by trial_id within each row")
    parser.add_argument("--links", type=Path, help="optional JSON array of point-to-point connections with from and to device-port objects")
    parser.add_argument("--compare-published", action="store_true",
                        help="compare measured counts and rates to Tables III-V; use the paper's exact "
                             "environment names: Static Network, + NAT, + ECMP, + BGP, + Load Balancer")
    parser.add_argument("--output", type=Path, help="new JSON summary path (default: stdout)")
    args = parser.parse_args()
    try:
        trials = _read(args.trials)
        predictions = _read(args.predictions) if args.predictions else []
        links = _read(args.links) if args.links else []
        result = score(trials, predictions, links)
        if args.compare_published:
            result["comparison"] = compare_published(result)
        text = json.dumps(result, indent=2, ensure_ascii=False) + "\n"
        if args.output is None:
            sys.stdout.write(text)
        else:
            with args.output.open("x", encoding="utf-8") as out:
                out.write(text)
    except (KeyError, TypeError, ValueError, OSError) as exc:
        parser.exit(2, f"{parser.prog}: {exc}\n")


if __name__ == "__main__":
    main()
