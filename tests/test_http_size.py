from pathlib import Path
import struct
import tempfile
import unittest

from benchmarks.http_size import request_bytes
from benchmarks.packet_sizes import compare
from replay.plan import ipv4_probe_option


def request_frame(index, payload_size, option=b"", timestamps=True):
    payload = request_bytes(index, payload_size)
    ethernet = bytes.fromhex("0200000000020200000000010800")
    tcp_options = bytes.fromhex("0101080a0000000100000001") if timestamps else b""
    tcp_words = 5 + len(tcp_options) // 4
    tcp = struct.pack("!HHIIHHHH", 40000, 18264, 1, 1, (tcp_words << 12) | 0x18, 65535, 0, 0)
    tcp += tcp_options
    ip_bytes = 20 + len(option)
    ip = struct.pack("!BBHHHBBH4s4s", 0x40 | (ip_bytes // 4), 0, ip_bytes + len(tcp) + len(payload),
                     index, 0, 64, 6, 0, bytes([192, 0, 2, 1]), bytes([192, 0, 2, 2]))
    return ethernet + ip + option + tcp + payload


class HttpSizeTests(unittest.TestCase):
    def compare_frames(self, frames, count=1):
        with tempfile.TemporaryDirectory() as directory:
            capture = Path(directory) / "http.pcap"
            with capture.open("wb") as f:
                f.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
                for frame in frames:
                    f.write(struct.pack("<IIII", 0, 0, len(frame), len(frame)))
                    f.write(frame)
            return compare(capture, count)

    def test_same_request_compared_with_forwarded_mark(self):
        frames = []
        for index, payload in ((1, 104), (2, 134)):
            option = ipv4_probe_option(index)[:-4] + (3).to_bytes(4, "big")
            frames += [request_frame(index, payload), request_frame(index, payload, option)]
        summary, rows = self.compare_frames(frames, count=2)
        self.assertEqual(summary["paired_requests"], 2)
        self.assertEqual(summary["ranges"]["baseline_frame"], [170, 200])
        self.assertEqual(summary["ranges"]["extra_frame_bytes"], [16, 16])
        self.assertEqual(summary["ranges"]["option_bytes"], [16, 16])
        self.assertAlmostEqual(rows[0]["frame_overhead_pct"], 1600 / 170)
        self.assertAlmostEqual(rows[1]["frame_overhead_pct"], 8)

    def test_mismatched_payload_and_retransmission_do_not_count(self):
        baseline = request_frame(1, 104)
        marked = request_frame(1, 105, ipv4_probe_option(1))
        for frames in ([baseline, marked], [baseline, baseline], [baseline]):
            with self.subTest(frames=len(frames)), self.assertRaises(ValueError):
                self.compare_frames(frames)

    def test_rejects_truncated_or_extra_options(self):
        baseline = request_frame(1, 104)
        mark = ipv4_probe_option(1)
        for option in [mark[:12], mark + bytes(4)]:
            with self.subTest(length=len(option)), self.assertRaises(ValueError):
                self.compare_frames([baseline, request_frame(1, 104, option)])

    def test_rejects_mismatched_tcp_or_link_header_sizes(self):
        baseline = request_frame(1, 104)
        marked = request_frame(1, 104, ipv4_probe_option(1))
        tagged = marked[:12] + bytes.fromhex("81000001") + marked[12:]
        for frame in (tagged, request_frame(1, 104, ipv4_probe_option(1), timestamps=False)):
            with self.subTest(size=len(frame)), self.assertRaises(ValueError):
                self.compare_frames([baseline, frame])


if __name__ == "__main__":
    unittest.main()
