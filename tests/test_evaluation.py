import unittest

from evaluation import score
from evaluation.reference import compare_published
from vnetpath import analyze


def port(device, name):
    return {"phy_device_ID": device, "port_name": name}


def event(probe, seq, host, ingress, egress, action, ms):
    return {"probe_ID": probe, "sequence_num": seq, "phy_device_ID": host, "in_port_name": ingress,
            "out_port_name": egress, "action": action, "packet_info": {}, "timestamp": ms}


class EvaluationTests(unittest.TestCase):
    def test_terminal_forward_only_localizes_mapped_next_port(self):
        sender = port("bridge", "uplink")
        receiver = port("peer", "ingress")
        document = {"recordings": [{"events": [event(1, 1, "bridge", "vm", "uplink", "forward", 0)],
                                    "probe_ids": [1], "vm_nics": ["destination"]}]}
        report = analyze(document)[0]
        links = [{"from": sender, "to": receiver}]
        truth = {"trial_id": "t", "failure_type": "Disconnection", "fault_type": 15,
                 "prediction": report, "environment": "Static Network"}
        for target, inventory, expected in ((sender, links, 0), (receiver, links, 1), (sender, [], 0)):
            with self.subTest(target=target, inventory=inventory):
                result = score([{**truth, "ground_truth": target}], links=inventory)
                self.assertEqual(result["overall"]["hits"], expected)
                details = result["failure_details_by_environment"]["Static Network"]["Disconnection"]
                self.assertEqual((details["correct_failure_type"], details["port_reported"]), (1, 1))
                self.assertEqual(details["by_last_action"], {"forward": 1})
        no_actions = {**truth, "ground_truth": sender, "prediction": {**report, "actions": None}}
        self.assertEqual(score([no_actions], links=links)["overall"]["hits"], 0)

    def test_independent_symptoms_and_missing_predictions(self):
        target = port("br", "port")
        trials = [{"trial_id": 1, "ground_truth": target, "environment": "static", "fault_type": 10,
                   "failure_type": "Delay", "prediction": {"diagnosis": "Disconnection", "located_ports": [target]}},
                  {"trial_id": 2, "ground_truth": target, "environment": "static", "fault_type": 10,
                   "failure_type": "Delay"},
                  {"trial_id": 3, "ground_truth": target, "environment": "nat", "fault_type": 2,
                   "prediction": {"diagnosis": "Replay Divergence"}}]
        result = score(trials)
        self.assertEqual((result["overall"]["total"], result["overall"]["hits"],
                          result["overall"]["missing_predictions"]), (3, 1, 1))
        self.assertEqual(result["by_environment"]["static"]["accuracy_pct"], 50.0)
        self.assertEqual(result["by_fault_family"]["Flow-Specific"]["total"], 2)
        details = result["failure_details_by_environment"]["static"]["Delay"]
        self.assertEqual(details, {"total": 2, "correct_location": 1, "correct_failure_type": 0,
                                   "port_reported": 1, "by_last_action": {"(unreported)": 2},
                                   "by_fault_type": {"10": 2}})
        unlabeled = result["failure_details_by_environment"]["nat"]["(unspecified)"]
        self.assertIsNone(unlabeled["correct_failure_type"])

    def test_delay_location_and_terminal_action_have_distinct_sources(self):
        document = {"recordings": [{"probe_ids": [1], "vm_nics": ["dst"],
                                    "events": [event(1, 1, "br1", "src", "tunnel", "encapsulate", 10),
                                               event(1, 2, "br2", "peer", "dst", "forward", 111)]}]}
        report = analyze(document)[0]
        truth = {"trial_id": 0, "failure_type": "Delay", "ground_truth": port("br1", "tunnel")}
        row = score([truth], [report])["failure_details_by_environment"]["(unspecified)"]["Delay"]
        self.assertEqual((row["correct_location"], row["by_last_action"]), (1, {"forward": 1}))

    def test_family_must_agree_with_table_ii_id(self):
        with self.assertRaisesRegex(ValueError, "belongs to Flow-Specific"):
            score([{"trial_id": 1, "ground_truth": port("a", "b"), "fault_type": 3,
                    "fault_family": "Generic Reachability"}])

    def test_published_counts_are_never_used_as_measurements(self):
        result = score([{"trial_id": 1, "ground_truth": port("br", "in"), "fault_type": 3,
                         "environment": "Static Network", "failure_type": "Disconnection"}])
        comparison = compare_published(result)
        static = comparison["table_iii"]["Static Network"]
        self.assertEqual(static["VNetPath"]["measured_trials"], 1)
        self.assertEqual(static["VNetPath"]["published_trials"], 1386)
        self.assertFalse(static["VNetPath"]["matches_published"])
        self.assertIsNone(static["Traceroute"]["measured_accuracy_pct"])
        details = comparison["table_v"]["Disconnection"]
        self.assertEqual(details["measured"]["total"], 1)
        self.assertEqual(details["published"]["total"], 972)
        self.assertIsNone(comparison["table_v"]["Delay"]["measured"])

    def test_baselines_use_published_granularities_and_same_denominator(self):
        trials = [{"trial_id": 1, "ground_truth": port("br", "port"), "fault_type": 6,
                   "baselines": {"Traceroute": {"expected_ip": "2001:db8::1", "reported_ip": "2001:db8:0::1"},
                                 "Zoonet": {"expected_device": "br", "reported_device": "br"}}},
                  {"trial_id": 2, "ground_truth": port("br", "port"), "fault_type": 3,
                   "baselines": {"Traceroute": {"expected_ip": None, "reported_ip": None},
                                 "Zoonet": {"expected_device": "br", "reported_device": "br2"}}},
                  {"trial_id": 3, "ground_truth": port("br", "port"), "fault_type": 3,
                   "baselines": {"Zoonet": {"expected_device": "br", "reported_device": None}}}]
        result = score(trials)["baselines"]
        for name, misses in (("Traceroute", 1), ("Zoonet", 0)):
            with self.subTest(name=name):
                self.assertEqual(result[name]["overall"]["total"], 3)
                self.assertEqual(result[name]["overall"]["hits"], 1)
                self.assertEqual(result[name]["overall"]["missing_predictions"], misses)
                self.assertEqual(result[name]["by_fault_family"]["Generic Reachability"]["accuracy_pct"], 100.0)
