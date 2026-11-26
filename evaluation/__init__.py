"""Score one injected fault per trial using the location granularity of each tool (§V-C)."""

from ipaddress import ip_address
from diagnosis.inventory import device_port
from .details import count_failure_details

GENERIC_REACHABILITY = {2, 6, 7, 8, 12, 13, 14, 15}
FLOW_SPECIFIC = {1, 3, 4, 5, 9, 10, 11}


def _port(value):
    if not isinstance(value, dict):
        raise ValueError("a port must be an object with phy_device_ID and port_name")
    pair = value.get("phy_device_ID"), value.get("port_name")
    if not all(isinstance(part, str) and part for part in pair) or pair[1] == "dropped":
        raise ValueError(f"invalid device-port location: {value!r}")
    return device_port(*pair)


def _trial_id(row):
    key = row.get("trial_id")
    if type(key) not in (str, int) or key == "":
        raise ValueError("each trial needs a nonempty string or integer trial_id")
    return key


def _index(rows, kind):
    result = {}
    for row in rows:
        if not isinstance(row, dict):
            raise ValueError(f"each {kind} must be an object")
        key = _trial_id(row)
        if key in result:
            raise ValueError(f"duplicate {kind} ID: {key!r}")
        result[key] = row
    return result


def _point_to_point_peers(links):
    peers = {}
    for link in links:
        left, right = _port(link["from"]), _port(link["to"])
        for a, b in ((left, right), (right, left)):
            if a == b or peers.setdefault(a, b) != b:
                raise ValueError(f"ambiguous point-to-point link at {a!r}")
    return peers


def _reported_ports(report, peers):
    outcome = report.get("diagnosis")
    if outcome == "Replay Divergence":
        return set()
    if "located_ports" in report:
        return {_port(entry) for entry in report["located_ports"]}
    if outcome not in ("Disconnection", "Packet Loss", "Delay"):
        raise ValueError("a prediction needs a VNetPath diagnosis or explicit located_ports")

    devices = report.get("devices") or []
    actions = report.get("actions")
    if actions is not None and len(actions) != len(devices):
        raise ValueError("diagnosis devices and actions must have the same length")
    ports = set()
    for index, device in enumerate(devices):
        action = actions[index] if actions is not None else None
        dropped = device["out_port_name"] == "dropped"
        if action is not None and (action == "drop") != dropped:
            raise ValueError("a drop action and the dropped egress marker must agree")
        name = device["in_port_name"] if dropped else device["out_port_name"]
        endpoint = _port({"phy_device_ID": device["phy_device_ID"], "port_name": name})
        # The last forward places the failure beyond this observed interface
        # (§IV, §V-C4). Resolve the next port only on a known point-to-point link.
        if action == "forward" and outcome in ("Disconnection", "Packet Loss"):
            if endpoint in peers:
                ports.add(peers[endpoint])
        elif action is None and not dropped and outcome in ("Disconnection", "Packet Loss"):
            # Without a terminal action the last observer does not identify which side failed.
            continue
        else:
            ports.add(endpoint)
    return ports


def _family(trial):
    if "fault_type" not in trial:
        return trial.get("fault_family", "(unspecified)")
    fault_type = trial["fault_type"]
    if type(fault_type) is not int or fault_type not in GENERIC_REACHABILITY | FLOW_SPECIFIC:
        raise ValueError("fault_type must be an integer from Table II (1–15)")
    family = "Generic Reachability" if fault_type in GENERIC_REACHABILITY else "Flow-Specific"
    if trial.get("fault_family", family) != family:
        raise ValueError(f"fault_type {fault_type} belongs to {family}")
    return family


def _count(counts, hit, missing):
    counts["total"] += 1
    counts["hits"] += int(hit)
    counts["missing_predictions"] += int(missing)


def _counts():
    return {"total": 0, "hits": 0, "missing_predictions": 0}


def _new_summary():
    return {"overall": _counts(), "by_environment": {}, "by_fault_family": {}}


def _record(summary, environment, family, hit, missing):
    _count(summary["overall"], hit, missing)
    for group, label in (("by_environment", environment), ("by_fault_family", family)):
        if not isinstance(label, str) or not label:
            raise ValueError(f"invalid {group} label: {label!r}")
        _count(summary[group].setdefault(label, _counts()), hit, missing)


def _add_rates(summary):
    for counts in (summary["overall"], *summary["by_environment"].values(), *summary["by_fault_family"].values()):
        n = counts["total"]
        counts["accuracy_pct"] = 100.0 * counts["hits"] / n if n else None


BASELINE_FIELDS = {"Traceroute": ("expected_ip", "reported_ip"), "Zoonet": ("expected_device", "reported_device")}


def _baseline_result(tool, observation):
    """An explicit null output records a completed run that supplied no location."""
    if observation is None:
        return False, True
    if not isinstance(observation, dict):
        raise ValueError(f"{tool} baseline requires a location record")
    expected_key, reported_key = BASELINE_FIELDS[tool]
    if expected_key not in observation:
        raise ValueError(f"{tool} baseline requires {expected_key}; use null for an unaddressable target")
    expected, reported = observation[expected_key], observation.get(reported_key)
    if any(value is not None and (not isinstance(value, str) or not value.strip()) for value in (expected, reported)):
        raise ValueError(f"invalid {tool} location")
    if tool == "Traceroute":
        expected = ip_address(expected) if expected is not None else None
        reported = ip_address(reported) if reported is not None else None
    return expected is not None and expected == reported, reported_key not in observation


def score(trials, predictions=(), links=()):
    """One truth row supplies trial_id, ground_truth and optional environment/fault_family.

    A row may embed prediction or join an external report by trial_id. A single
    exported CLI report can be paired with a single truth without a trial ID.
    Any exactly matching reported device-port scores one hit for that trial.
    Optional trial.baselines maps Traceroute to {expected_ip, reported_ip} and
    Zoonet to {expected_device, reported_device}. Scores use all declared trials.
    """
    truth = _index(trials, "ground truth")
    if isinstance(predictions, dict):
        predictions = [predictions]
    predictions = list(predictions)
    if len(truth) == 1 and len(predictions) == 1 and "trial_id" not in predictions[0]:
        predictions = [{**predictions[0], "trial_id": next(iter(truth))}]
    reports = _index(predictions, "prediction")
    unknown = reports.keys() - truth.keys()
    if unknown:
        raise ValueError(f"prediction for an undeclared trial: {next(iter(unknown))!r}")
    peers = _point_to_point_peers(links)
    summary, details = _new_summary(), {}
    baseline_summaries = {}
    for trial in truth.values():
        baselines = trial.get("baselines", {})
        if not isinstance(baselines, dict) or baselines.keys() - BASELINE_FIELDS.keys():
            raise ValueError("baselines must map Traceroute or Zoonet to a location record")
        for name in baselines:
            baseline_summaries.setdefault(name, _new_summary())
    for key, trial in truth.items():
        expected = _port(trial["ground_truth"])
        if "prediction" in trial and key in reports:
            raise ValueError(f"duplicate prediction for trial {key!r}")
        report = trial.get("prediction", reports.get(key))
        if report is not None and not isinstance(report, dict):
            raise ValueError(f"invalid prediction for trial {key!r}")
        if report is not None and "trial_id" in report and _trial_id(report) != key:
            raise ValueError(f"embedded prediction trial_id differs from {key!r}")
        located = _reported_ports(report, peers) if report is not None else set()
        hit = expected in located
        environment = trial.get("environment", "(unspecified)")
        family = _family(trial)
        _record(summary, environment, family, hit, report is None)
        for name, baseline_summary in baseline_summaries.items():
            matched, missing = _baseline_result(name, trial.get("baselines", {}).get(name))
            _record(baseline_summary, environment, family, matched, missing)
        count_failure_details(details.setdefault(environment, {}), trial, report, hit)
    _add_rates(summary)
    for baseline_summary in baseline_summaries.values():
        _add_rates(baseline_summary)
    summary["failure_details_by_environment"] = details
    if baseline_summaries:
        summary["baselines"] = baseline_summaries
    return summary
