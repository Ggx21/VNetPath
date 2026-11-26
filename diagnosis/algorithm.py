"""VNetPath Algorithm 1 and its configurable per-hop delay threshold."""

from .inventory import ends_at_nic
from .report import Finding


MIXED_NIC_POLICIES = ("algorithm1", "packet_loss")


def _detect_delay(paths, threshold, clocks_aligned):
    slow = []
    for path in paths:
        for earlier, later in zip(path, path[1:]):
            delta = later["timestamp"] - earlier["timestamp"]
            different_host = earlier["phy_device_ID"] != later["phy_device_ID"]
            if delta < 0 or (different_host and not clocks_aligned):
                raise ValueError("adjacent timestamps must share a comparable clock for delay diagnosis")
            if delta > threshold:
                slow.append(Finding(earlier, later))
    return ("Delay", slow) if slow else ("Replay Divergence", [])


def classify(paths, vm_nics, threshold, clocks_aligned, *, mixed_nic_policy="algorithm1"):
    if mixed_nic_policy not in MIXED_NIC_POLICIES:
        raise ValueError(f"unknown mixed_nic_policy: {mixed_nic_policy!r}")
    last = [path[-1] for path in paths]
    incomplete = [event for event in last if not ends_at_nic(event, vm_nics)]
    if len({len(path) for path in paths}) != 1:
        if incomplete:
            return "Packet Loss", [Finding(event) for event in incomplete]
        return "Replay Divergence", []

    actions = {event["action"] for event in last}
    if incomplete or actions == {"drop"}:
        return "Disconnection", [Finding(event) for event in last]
    # Section IV's text labels this case loss. The printed pseudocode instead
    # proceeds to DetectDelay, which remains the default.
    if mixed_nic_policy == "packet_loss" and actions == {"forward", "drop"}:
        return "Packet Loss", [Finding(event) for event in last if event["action"] == "drop"]
    return _detect_delay(paths, threshold, clocks_aligned)


def diagnose(paths, vm_nics, threshold, clocks_aligned, *, mixed_nic_policy="algorithm1"):
    """Return the historical (category, implicated events) result."""
    outcome, findings = classify(paths, vm_nics, threshold, clocks_aligned, mixed_nic_policy=mixed_nic_policy)
    return outcome, [finding.event for finding in findings]
