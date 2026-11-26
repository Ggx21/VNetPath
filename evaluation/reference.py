"""Published aggregate targets, kept separate from the trial records being scored."""

from decimal import Decimal, ROUND_HALF_UP


# VNetPath, IEEE INFOCOM 2026, Tables III and IV. The three rates in each row
# are printed for VNetPath, Traceroute, and Zoonet, in that order.
TABLE_III = {
    "Static Network": (1386, "100.00", "18.75", "77.63"),
    "+ NAT": (1407, "100.00", "19.90", "78.89"),
    "+ ECMP": (1389, "92.44", "15.19", "78.69"),
    "+ BGP": (1350, "82.22", "18.07", "60.81"),
    "+ Load Balancer": (1410, "92.20", "19.15", "70.00"),
}
TABLE_IV = {
    "Generic Reachability": (3400, "96.00", "37.21", "91.18"),
    "Flow-Specific": (3542, "90.99", "0.00", "56.10"),
}
OVERALL = (6942, "93.45", "18.22", "73.27")

# Table V includes only the Static Network subset.
TABLE_V = {
    "Disconnection": (972, {"drop": 739, "forward": 233},
                      {1: 114, 2: 88, 3: 92, 4: 110, 5: 106, 6: 144, 9: 102, 11: 108,
                       12: 12, 13: 12, 14: 24, 15: 60}),
    "Delay": (250, {"forward": 250}, {8: 146, 10: 104}),
    "Packet Loss": (164, {"drop": 164}, {7: 140, 10: 24}),
}


def _accuracy_rows(reported, summary, group=None, label=None):
    comparisons = {}
    n, *rates = reported
    for name, expected_rate in zip(("VNetPath", "Traceroute", "Zoonet"), rates):
        tool = summary if name == "VNetPath" else summary.get("baselines", {}).get(name)
        measured = None
        if tool is not None:
            measured = tool["overall"] if group is None else tool[group].get(label)
        actual_rate = None
        if measured and measured["total"]:
            rate = Decimal(100) * measured["hits"] / measured["total"]
            actual_rate = str(rate.quantize(Decimal("0.01"), rounding=ROUND_HALF_UP))
        comparisons[name] = {
            "published_trials": n, "published_accuracy_pct": expected_rate,
            "measured_trials": measured["total"] if measured else 0,
            "measured_hits": measured["hits"] if measured else None,
            "missing_predictions": measured["missing_predictions"] if measured else None,
            "measured_accuracy_pct": actual_rate,
            "matches_published": bool(measured and measured["total"] == n
                                      and measured["missing_predictions"] == 0 and actual_rate == expected_rate),
        }
    return comparisons


def compare_published(summary):
    comparison = {
        "overall": _accuracy_rows(OVERALL, summary),
        "table_iii": {label: _accuracy_rows(row, summary, "by_environment", label)
                      for label, row in TABLE_III.items()},
        "table_iv": {label: _accuracy_rows(row, summary, "by_fault_family", label)
                     for label, row in TABLE_IV.items()},
    }
    static = summary["failure_details_by_environment"].get("Static Network", {})
    details = {}
    for symptom, (n, actions, faults) in TABLE_V.items():
        expected = {"total": n, "correct_location": n, "correct_failure_type": n, "port_reported": n,
                    "by_last_action": actions, "by_fault_type": {str(key): count for key, count in faults.items()}}
        measured = static.get(symptom)
        details[symptom] = {"published": expected, "measured": measured, "matches_published": measured == expected}
    comparison["table_v"] = details
    return comparison
