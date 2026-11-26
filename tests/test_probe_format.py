import ctypes
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest

from replay.plan import ipv4_probe_option


class ProbeFormatTests(unittest.TestCase):
    def test_sender_wire_bytes(self):
        for probe_id in (0, 0x0123456789ABCDEF, 2**64 - 1):
            with self.subTest(probe_id=probe_id):
                expected = b"\x1e\x10VN" + probe_id.to_bytes(8, "big") + bytes(4)
                self.assertEqual(ipv4_probe_option(probe_id), expected)


@unittest.skipUnless(sys.platform.startswith("linux") and shutil.which("cc"),
                     "the agent header requires Linux and a C compiler")
class AgentProbeFormatTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        tmp = tempfile.TemporaryDirectory()
        cls.addClassCleanup(tmp.cleanup)
        library = Path(tmp.name) / "mark.so"
        agent = Path(__file__).resolve().parents[1] / "agent"
        wrapper = """
#include "trace.h"
int probe_offset(const __u8 ip[60], __u32 size) {
    return vnetpath_probe_id_offset(ip, size);
}
"""
        subprocess.run(["cc", "-shared", "-fPIC", "-O2", "-I", str(agent),
                        "-x", "c", "-", "-o", str(library)], input=wrapper, text=True, check=True)
        cls.parse = ctypes.CDLL(str(library)).probe_offset
        cls.parse.argtypes = [ctypes.c_char_p, ctypes.c_uint32]
        cls.parse.restype = ctypes.c_int

    def find(self, options):
        packet = bytes(20) + options
        self.assertLessEqual(len(packet), 60)
        return self.parse(packet.ljust(60, b"\0"), len(packet))

    def test_sender_and_legacy_marks(self):
        probe_id = 0x0123456789ABCDEF
        current = ipv4_probe_option(probe_id)
        legacy = struct.pack("!BB4sQI2x", 0x1E, 18, b"VNPT", probe_id, 19)
        for option, offset in [(current, 24), (legacy, 26), (bytes([1]) * 24 + current, 48)]:
            with self.subTest(option=option):
                self.assertEqual(self.find(option), offset)
                self.assertEqual(struct.unpack_from("!Q", bytes(20) + option, offset)[0], probe_id)

    def test_rejects_truncated_and_unrelated_options(self):
        current = ipv4_probe_option(0)
        for option in (current[:-1], b"\0" + current, b"\x1e\x00VN" + bytes(12),
                       b"\x1e\x10XX" + bytes(12), b"\x1e\x12VNXX" + bytes(12)):
            with self.subTest(option=option):
                self.assertEqual(self.find(option), -1)


if __name__ == "__main__":
    unittest.main()
