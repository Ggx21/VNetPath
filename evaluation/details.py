"""Summarize independently observed failure types and terminal actions (Table V)."""

FAILURE_TYPES = ("Disconnection", "Delay", "Packet Loss")


def _last_action(report):
    # For packet loss, the unaffected probes can have a different last action.
    # The diagnosis lists the terminal events of the implicated probes (§IV).
    actions = report.get("actions")
    if report.get("diagnosis") == "Delay":
        actions = [path[-1]["action"] for path in report.get("paths", []) if path]
    if not actions:
        return "(unreported)"
    distinct = set(actions)
    return next(iter(distinct)) if len(distinct) == 1 else "(mixed)"


def count_failure_details(groups, trial, report, hit):
    observed = trial.get("failure_type", "(unspecified)")
    if "failure_type" in trial and observed not in FAILURE_TYPES:
        raise ValueError(f"unknown observed failure_type: {observed!r}")
    if observed not in groups:
        groups[observed] = {"total": 0, "correct_location": 0,
                            "correct_failure_type": 0 if observed in FAILURE_TYPES else None,
                            "port_reported": 0, "by_last_action": {}, "by_fault_type": {}}
    row = groups[observed]
    row["total"] += 1
    row["correct_location"] += int(hit)
    report = report or {}
    if row["correct_failure_type"] is not None:
        row["correct_failure_type"] += int(report.get("diagnosis") == observed)
    # A last observed port is useful evidence even when the next hop is unknown.
    row["port_reported"] += int(bool(report.get("devices") or report.get("located_ports")))
    for counts, key in ((row["by_last_action"], _last_action(report)),
                        (row["by_fault_type"], str(trial.get("fault_type", "(unspecified)")))):
        counts[key] = counts.get(key, 0) + 1
