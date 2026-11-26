import csv
import io
from pathlib import Path
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
import unittest


@unittest.skipUnless(sys.platform.startswith("linux") and shutil.which("cc"), "Linux C compiler required")
class BenchmarkTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        folder = tempfile.TemporaryDirectory()
        cls.addClassCleanup(folder.cleanup)
        cls.build = Path(folder.name)
        sources = Path(__file__).resolve().parents[1] / "benchmarks"
        for name in ("http_rtt", "echo_rtt"):
            subprocess.run(["cc", "-O2", "-std=c11", "-Wall", "-Wextra", "-Werror",
                            str(sources / (name + ".c")), "-o", str(cls.build / name)], check=True)

    def http(self, responses, mode, timeout=1000):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
            server.bind(("127.0.0.1", 0))
            server.listen()
            server.settimeout(3)
            port = str(server.getsockname()[1])
            requests = []

            def respond():
                for response in responses:
                    peer, _ = server.accept()
                    with peer:
                        data = bytearray()
                        while b"\r\n\r\n" not in data:
                            part = peer.recv(512)
                            if not part:
                                break
                            data.extend(part)
                        requests.append(bytes(data))
                        if response is None:
                            time.sleep(0.2)
                        else:
                            peer.sendall(response)

            thread = threading.Thread(target=respond)
            thread.start()
            try:
                proc = subprocess.run([str(self.build / "http_rtt"), "127.0.0.1", "127.0.0.1", port,
                                       "/health", mode, "23", str(len(responses)), "1", str(timeout)],
                                      text=True, capture_output=True, timeout=5)
            finally:
                thread.join(4)
            self.assertEqual(len(requests), len(responses))
            self.assertTrue(all(r.startswith(b"GET /health HTTP/1.0\r\n") for r in requests))
            return proc.returncode, list(csv.DictReader(io.StringIO(proc.stdout)))

    def require_mark_if_tracing(self, mode):
        if mode != "trace":
            return
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            try:
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_OPTIONS,
                                struct.pack("!BB2sQI", 0x1e, 16, b"VN", 1, 0))
            except OSError as exc:
                self.skipTest(f"Linux did not permit the experimental IPv4 option: {exc}")

    def test_http_explicit_path_completed_body_and_timestamps(self):
        for mode in ("baseline", "agent-only", "trace"):
            with self.subTest(mode=mode):
                self.require_mark_if_tracing(mode)
                code, rows = self.http([b"HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\nok",
                                        b"HTTP/1.0 200 OK\r\n\r\nhello"], mode)
                self.assertEqual(code, 0)
                self.assertEqual([int(r["probe_id"]) for r in rows], [(23 << 32) + 1, (23 << 32) + 2])
                self.assertEqual([int(r["body_bytes"]) for r in rows], [2, 5])
                for row in rows:
                    self.assertEqual(int(row["rtt_ns"]), int(row["response_complete_ns"]) - int(row["request_send_ns"]))
                    self.assertGreaterEqual(int(row["total_ns"]), int(row["rtt_ns"]))

    def test_http_incomplete_status_and_timeout_exclude_rtt(self):
        code, rows = self.http([b"HTTP/1.0 200 OK\r\nContent-Length: 9\r\n\r\nshort",
                                b"HTTP/1.0 404 Not Found\r\nContent-Length: 0\r\n\r\n", None],
                               "baseline", timeout=80)
        self.assertEqual(code, 2)
        self.assertEqual([r["status"] for r in rows], ["truncated_response", "http_error", "timeout"])
        self.assertTrue(all(r["rtt_ns"] == "" and r["total_ns"] == "" for r in rows))

    def test_udp_checks_mark_id_and_preserves_every_reply(self):
        for mode in ("baseline", "agent-only", "trace"):
            with self.subTest(mode=mode):
                self.require_mark_if_tracing(mode)
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as first, \
                        socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as second:
                    first.bind(("127.0.0.1", 0))
                    second.bind(("127.0.0.1", 0))
                    client = ["127.0.0.1", str(first.getsockname()[1])]
                    server = ["127.0.0.1", str(second.getsockname()[1])]
                binary = str(self.build / "echo_rtt")
                settings = [mode, "22", "4", "1", "500"]
                with subprocess.Popen([binary, "server", *server, *client, *settings], stdout=subprocess.PIPE,
                                      stderr=subprocess.PIPE, text=True) as peer:
                    try:
                        self.assertIn("ready", peer.stderr.readline())
                        sent = subprocess.run([binary, "client", *client, *server, *settings],
                                              capture_output=True, text=True, timeout=5, check=True)
                        received, _ = peer.communicate(timeout=5)
                    finally:
                        if peer.poll() is None:
                            peer.kill()
                    self.assertEqual(peer.returncode, 0)
                s, r = list(csv.DictReader(io.StringIO(sent.stdout))), list(csv.DictReader(io.StringIO(received)))
                self.assertEqual([x["probe_id"] for x in s], [x["probe_id"] for x in r])
                self.assertEqual(len(s), 4)
                self.assertTrue(all(int(x["rtt_ns"]) > 0 for x in s))
                self.assertTrue(all(x["request_mark"] == ("present" if mode == "trace" else "absent") for x in r))


if __name__ == "__main__":
    unittest.main()
