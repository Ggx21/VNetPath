"""Link VNetPath probe events and diagnose a recorded replay."""

import argparse
import json
import sys
from pathlib import Path

from diagnosis import MIXED_NIC_POLICIES, build_report, classify, diagnose, ends_at_nic, nic_inventory
from pathbuilder import ACTIONS, EventLinker, index_events


def reconstruct(recording, threshold, *, mixed_nic_policy="algorithm1"):
    vm_nics = nic_inventory(recording["vm_nics"])
    if recording.get("capture_complete", True) is not True:
        raise ValueError("the event recording is incomplete")

    linker = EventLinker(recording["probe_ids"])
    if "events" in recording:
        linker.extend(recording["events"])
    elif "event_streams" not in recording:
        raise ValueError("a recording requires events or event_streams")
    for stream in recording.get("event_streams", ()):
        linker.extend(stream)

    paths = linker.paths()
    outcome, findings = classify(
        paths, vm_nics, threshold, recording.get("clocks_aligned", True) is True,
        mixed_nic_policy=mixed_nic_policy,
    )
    report = build_report(outcome, findings, paths)
    if "trial_id" in recording:
        report["trial_id"] = recording["trial_id"]
    return report


def analyze(document, *, mixed_nic_policy=None):
    threshold = document.get("delay_threshold_ms", 100)
    if type(threshold) is not int or threshold < 0:
        raise ValueError("delay_threshold_ms must be a nonnegative integer")
    if mixed_nic_policy is None:
        mixed_nic_policy = document.get("mixed_nic_policy", "algorithm1")
    recordings = document["recordings"]
    if not isinstance(recordings, list) or not recordings:
        raise ValueError("recordings must contain at least one replay")
    return [
        reconstruct(recording, threshold, mixed_nic_policy=mixed_nic_policy)
        for recording in recordings
    ]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("file", type=Path, help="JSON with probe events grouped by replay")
    parser.add_argument(
        "--mixed-nic-policy", choices=MIXED_NIC_POLICIES,
        help="equal-length paths ending at NICs with both drop and forward (default: algorithm1)",
    )
    args = parser.parse_args()
    try:
        result = analyze(json.loads(args.file.read_text(encoding="utf-8")), mixed_nic_policy=args.mixed_nic_policy)
    except (KeyError, TypeError, ValueError, OSError) as exc:
        parser.exit(2, f"{parser.prog}: {exc}\n")
    json.dump(result, sys.stdout, indent=2)
    print()


if __name__ == "__main__":
    main()
