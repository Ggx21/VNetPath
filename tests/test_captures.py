import struct
import tempfile
import unittest
from pathlib import Path

from captures import correlate


CLIENT, SERVER = bytes([192, 0, 2, 10]), bytes([192, 0, 2, 20])
CLIENT_MAC, SERVER_MAC = bytes.fromhex("020000000001"), bytes.fromhex("020000000002")


def ethernet(ip, source=CLIENT_MAC, destination=SERVER_MAC):
    return destination + source + b"\x08\x00" + ip


def ipv4(body, protocol, source, destination):
    return struct.pack("!BBHHHBBH4s4s", 0x45, 0, len(body) + 20, 1, 0, 64, protocol, 0,
                       source, destination) + body


def echo(reply=False, payload=b"echo"):
    message = struct.pack("!BBHHH", 0 if reply else 8, 0, 0, 42, 1) + payload
    if reply:
        return ethernet(ipv4(message, 1, SERVER, CLIENT), SERVER_MAC, CLIENT_MAC)
    return ethernet(ipv4(message, 1, CLIENT, SERVER))


def geneve(inner, vni=5):
    wrapped = struct.pack("!BBH", 0, 0, 0x6558) + vni.to_bytes(3, "big") + b"\0" + inner
    udp = struct.pack("!HHHH", 40000, 6081, len(wrapped) + 8, 0) + wrapped
    return ethernet(ipv4(udp, 17, bytes([198, 51, 100, 1]), bytes([198, 51, 100, 2])))


class CaptureTest(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.folder = Path(folder.name)

    def write_capture(self, name, frames):
        path = self.folder / name
        with path.open("wb") as stream:
            stream.write(b"\xd4\xc3\xb2\xa1" + struct.pack("<HHiIII", 2, 4, 0, 0, 65535, 1))
            for n, frame in enumerate(frames, 1):
                stream.write(struct.pack("<IIII", n, 20, len(frame), len(frame)) + frame)
        return path

    def analyze(self, source, dest, tunnels=(), mac=None):
        outer = {label: self.write_capture(label, frames) for label, frames in tunnels}
        return correlate("192.0.2.10", "192.0.2.20", self.write_capture("source", source),
                         self.write_capture("destination", dest), outer, mac)

    def test_endpoints_and_geneve_contexts_are_independent_observations(self):
        frames = [echo(), echo(True)]
        outer = [geneve(packet) for packet in frames]
        result = self.analyze(frames, frames, [("left", outer), ("right", outer)], SERVER_MAC.hex(":"))
        row = result["echoes"][0]
        self.assertEqual(result["summary"]["unique_replies_at_all_points"], 1)
        self.assertTrue(row["request"]["same_geneve_context"])
        self.assertTrue(row["destination_reply_matches_binding"])
        reply = row["reply"]["observations"]["right"][0]
        self.assertEqual((reply["frame"], reply["timestamp_ns"]), (2, 2_000_020_000))
        self.assertEqual(reply["geneve_layers"][0]["vni"], 5)

    def test_duplicate_frames_missing_replies_and_mismatched_payload(self):
        result = self.analyze([echo()], [echo(), echo(), echo(True, b"other")], mac=SERVER_MAC.hex(":"))
        self.assertEqual(result["summary"]["unanchored_identities"], 1)
        self.assertEqual(result["summary"]["unique_requests_at_all_points"], 0)
        row = next(r for r in result["echoes"] if r["request"]["observations"]["source_tap"])
        self.assertEqual(len(row["request"]["observations"]["destination_tap"]), 2)
        self.assertEqual(row["reply"]["observations"]["destination_tap"], [])
        self.assertIsNone(row["destination_reply_matches_binding"])

    def test_tunnel_conflict_and_wrong_endpoint_binding_are_exposed(self):
        frames = [echo(), echo(True)]
        result = self.analyze(frames, frames, [("left", [geneve(echo())]), ("right", [geneve(echo(), 9)])],
                              CLIENT_MAC.hex(":"))
        self.assertEqual(result["geneve_context_comparisons"]["request"]["different"], 1)
        self.assertIsNone(result["echoes"][0]["reply"]["same_geneve_context"])
        self.assertFalse(result["echoes"][0]["destination_reply_matches_binding"])
        self.assertEqual(result["summary"]["destination_replies_with_matching_binding"], 0)

    def test_truncated_frame_and_wrong_layer_are_accounted_for(self):
        result = self.analyze([echo()], [echo()], [("outer", [b"truncated", echo()])])
        self.assertEqual(result["capture_points"]["outer"]["undecodable_frames"], 1)
        self.assertEqual(result["capture_points"]["outer"]["other_layer_echoes"], 1)
        self.assertEqual(result["summary"]["unique_requests_at_all_points"], 0)

    def test_truncated_pcap_container_fails(self):
        path = self.write_capture("damaged", [])
        with path.open("ab") as stream:
            stream.write(b"bad")
        with self.assertRaisesRegex(ValueError, "pcap record header"):
            correlate("192.0.2.10", "192.0.2.20", path, self.write_capture("empty", []), {})


if __name__ == "__main__":
    unittest.main()
