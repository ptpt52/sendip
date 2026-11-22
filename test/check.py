import struct
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def run_sendip(*arguments, data=None):
    return subprocess.run(
        [str(ROOT / "sendip"), "-D", *arguments],
        cwd=ROOT,
        input=data,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=10,
    )


class PacketOptions(unittest.TestCase):
    def dump(self, *arguments, data=None):
        result = run_sendip(*arguments, data=data)
        self.assertEqual(result.returncode, 0, result.stderr.decode(errors="replace"))
        return result.stdout

    def test_mutable_callback_options_survive_loops(self):
        packets = self.dump(
            "-l", "3", "-p", "ipv4", "-ii", "1",
            "-p", "./test/loop_module.so", "--ql=r", "127.0.0.1",
        )
        self.assertEqual(len(packets), 63)
        self.assertEqual(packets[20::21], b"!!!")

    def test_file_values_follow_option_order(self):
        with tempfile.TemporaryDirectory() as directory:
            values = Path(directory) / "options.txt"
            values.write_text("7\n2400\n8\n2401\n", encoding="ascii")
            argument = "f" + str(values)
            packets = self.dump(
                "-l", "2", "-p", "ipv4", "-ii", "1", "-d", argument,
                "-p", "udp", "-ud", argument, "127.0.0.1",
            )
        self.assertEqual(len(packets), 58)
        self.assertEqual(struct.unpack_from("!H", packets, 22), (2400,))
        self.assertEqual(struct.unpack_from("!H", packets, 51), (2401,))
        self.assertEqual(packets[28::29], b"78")

    def test_repeated_module_selectors_keep_separate_fields(self):
        packets = self.dump(
            "-ii", "1", "-p", "ipv4", "-p", "ipv4", "-ii", "2",
            "-p", "udp", "--ud=5000", "-l2", "127.0.0.1",
        )
        self.assertEqual(len(packets), 96)
        self.assertEqual(packets[:48], packets[48:])
        self.assertEqual(struct.unpack_from("!H", packets, 4), (1,))
        self.assertEqual(struct.unpack_from("!H", packets, 24), (2,))

    def test_repeated_modules_share_option_registration(self):
        selector = ["-p", "ipv4"]
        single = run_sendip("-v", *selector, "127.0.0.1")
        repeated = run_sendip("-v", *(selector * 24), "127.0.0.1")
        self.assertEqual(single.returncode, 0, single.stderr)
        self.assertEqual(repeated.returncode, 0, repeated.stderr)
        single_options = next(line for line in single.stderr.splitlines() if line.startswith(b"Added "))
        self.assertIn(single_options, repeated.stderr.splitlines())
        self.assertEqual(len(repeated.stdout), 24 * len(single.stdout))

    def test_extra_hostname_rejected_before_opening_payload(self):
        with tempfile.TemporaryDirectory() as directory:
            missing = str(Path(directory) / "missing")
            result = run_sendip("-f", missing, "first", "second")
        self.assertEqual(result.returncode, 1)
        self.assertIn(b"More than one hostname specified", result.stderr)
        self.assertEqual(result.stdout, b"")

    def test_packet_sizes_can_grow_and_shrink_between_iterations(self):
        payloads = [b"short", b"Y" * 100, b"last"]
        with tempfile.TemporaryDirectory() as directory:
            values = Path(directory) / "payloads.txt"
            values.write_bytes(b"\n".join(payloads) + b"\n")
            packets = self.dump(
                "-l", "3", "-p", "ipv4", "-ii", "1", "-p", "udp",
                "-ud", "5000", "-d", "f" + str(values), "127.0.0.1",
            )
        offset = 0
        for payload in payloads:
            length = 28 + len(payload)
            self.assertEqual(struct.unpack_from("!H", packets, offset + 2), (length,))
            self.assertEqual(packets[offset + 28:offset + length], payload)
            offset += length
        self.assertEqual(len(packets), offset)

    def test_later_option_failure_keeps_completed_packets(self):
        with tempfile.TemporaryDirectory() as directory:
            values = Path(directory) / "ports.txt"
            values.write_text("5000\ninvalid\n", encoding="ascii")
            result = run_sendip(
                "-l", "2", "-p", "ipv4", "-ii", "1", "-p", "udp",
                "-ud", "f" + str(values), "127.0.0.1",
            )
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn(b"Invalid integer argument", result.stderr)
        self.assertEqual(len(result.stdout), 28)
        self.assertEqual(struct.unpack_from("!H", result.stdout, 22), (5000,))

    @unittest.skipUnless(Path("/dev/stdin").exists(), "/dev/stdin is unavailable")
    def test_raw_stream_is_cached_for_each_packet(self):
        payload = bytes(range(256)) * 64
        packets = self.dump("-l", "2", "-f", "/dev/stdin", "127.0.0.1", data=payload)
        self.assertEqual(packets, payload * 2)


if __name__ == "__main__":
    unittest.main()
