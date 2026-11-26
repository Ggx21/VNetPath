"""Keep each reported device associated with the probe and event that identified it."""

from dataclasses import dataclass


def _device(event):
    return {key: event[key] for key in ("phy_device_ID", "in_port_name", "out_port_name")}


@dataclass
class Finding:
    event: dict
    next_event: dict = None

    def describe(self):
        event = self.event
        result = {
            "probe_ID": event["probe_ID"],
            "sequence_num": event["sequence_num"],
            "device": _device(event),
            "action": event["action"],
        }
        if self.next_event is not None:
            result["next_sequence_num"] = self.next_event["sequence_num"]
            result["next_device"] = _device(self.next_event)
            result["delta_ms"] = self.next_event["timestamp"] - event["timestamp"]
        return result


def build_report(outcome, findings, paths):
    devices = [_device(finding.event) for finding in findings]
    actions = None
    if outcome in ("Packet Loss", "Disconnection"):
        actions = [finding.event["action"] for finding in findings]
    return {
        "diagnosis": outcome,
        "devices": devices or None,
        "actions": actions,
        "paths": paths,
        "findings": [finding.describe() for finding in findings],
    }
