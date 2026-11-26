"""Validate fields from the VNetPath event table and decode wire action codes."""

ACTIONS = {1: "forward", 2: "drop", 3: "encapsulate", 4: "decapsulate"}
REQUIRED_FIELDS = (
    "probe_ID", "sequence_num", "phy_device_ID", "in_port_name", "out_port_name",
    "timestamp", "action", "packet_info",
)


def normalize_event(event):
    """Preserve the captured header and optional fields exactly as supplied."""
    if not isinstance(event, dict):
        raise ValueError("each event must be an object")
    for key in REQUIRED_FIELDS:
        if key not in event:
            raise ValueError(f"missing event field: {key}")

    probe, seq = event["probe_ID"], event["sequence_num"]
    if type(probe) is not int or not 0 <= probe < 2**64:
        raise ValueError(f"invalid probe ID: {probe!r}")
    if type(seq) is not int or not 1 <= seq < 2**32:
        raise ValueError(f"invalid sequence number: {seq!r}")
    for key in ("phy_device_ID", "in_port_name", "out_port_name"):
        if not isinstance(event[key], str) or not event[key]:
            raise ValueError(f"missing {key} on probe {probe}, event {seq}")

    action = event["action"]
    if type(action) is int:
        action = ACTIONS.get(action)
    if action not in ACTIONS.values():
        raise ValueError(f"unknown action on probe {probe}, event {seq}")
    if (action == "drop") != (event["out_port_name"] == "dropped"):
        raise ValueError("out_port_name must be dropped exactly when the action is drop")
    if type(event["timestamp"]) is not int:
        raise ValueError("timestamp must be Unix time in milliseconds")
    if not isinstance(event["packet_info"], dict):
        raise ValueError("packet_info must be an object")
    return {**event, "action": action}
