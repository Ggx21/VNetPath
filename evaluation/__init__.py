"""Score one injected fault per trial at device-port granularity (VNetPath §V-C)."""

from diagnosis.inventory import device_port

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
        ports.add(endpoint)
        # A terminal forward can indicate the unseen next hop (§V-C4).
        # Only a supplied point-to-point mapping can identify that peer.
        if action == "forward" and outcome in ("Disconnection", "Packet Loss") and endpoint in peers:
            ports.add(peers[endpoint])
    return ports


def _family(trial):
    if "fault_family" in trial:
        return trial["fault_family"]
    fault_type = trial.get("fault_type")
    if type(fault_type) is int and fault_type in GENERIC_REACHABILITY:
        return "Generic Reachability"
    if type(fault_type) is int and fault_type in FLOW_SPECIFIC:
        return "Flow-Specific"
    return "(unspecified)"


def _count(counts, hit, missing):
    counts["total"] += 1
    counts["hits"] += int(hit)
    counts["missing_predictions"] += int(missing)


def _counts():
    return {"total": 0, "hits": 0, "missing_predictions": 0}


def score(trials, predictions=(), links=()):
    """One truth row supplies trial_id, ground_truth and optional environment/fault_family.

    A row may embed prediction or join an external report by trial_id. A single
    exported CLI report can be paired with a single truth without a trial ID.
    Any exactly matching reported device-port scores one hit for that trial.
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
    total, environments, families = _counts(), {}, {}
    for key, trial in truth.items():
        expected = _port(trial["ground_truth"])
        if "prediction" in trial and key in reports:
            raise ValueError(f"duplicate prediction for trial {key!r}")
        report = trial.get("prediction", reports.get(key))
        if report is not None and not isinstance(report, dict):
            raise ValueError(f"invalid prediction for trial {key!r}")
        if report is not None and "trial_id" in report and _trial_id(report) != key:
            raise ValueError(f"embedded prediction trial_id differs from {key!r}")
        hit = report is not None and expected in _reported_ports(report, peers)
        _count(total, hit, report is None)
        for groups, label in ((environments, trial.get("environment", "(unspecified)")), (families, _family(trial))):
            if not isinstance(label, str) or not label:
                raise ValueError(f"invalid group label for trial {key!r}")
            _count(groups.setdefault(label, _counts()), hit, report is None)
    for counts in (total, *environments.values(), *families.values()):
        n = counts["total"]
        counts["accuracy_pct"] = 100.0 * counts["hits"] / n if n else None
    return {"overall": total, "by_environment": environments, "by_fault_family": families}
