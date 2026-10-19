import tempfile
import unittest
import zipfile
from pathlib import Path

from setup.build_windows_vm_acceptance import sha256, write_zip
from setup.run_utm_deploy import VmEntry, parse_vm_list


class WindowsVmAcceptanceTests(unittest.TestCase):
    def test_payload_zip_is_deterministic(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "payload.bin"
            source.write_bytes(b"payload")
            first = root / "first.zip"
            second = root / "second.zip"
            write_zip(first, {"target/payload.bin": source})
            write_zip(second, {"target/payload.bin": source})
            self.assertEqual(sha256(first), sha256(second))
            with zipfile.ZipFile(first) as archive:
                self.assertEqual(archive.namelist(), ["target/payload.bin"])
                self.assertEqual(archive.read("target/payload.bin"), b"payload")

    def test_utm_target_parser_preserves_exact_identity(self):
        output = (
            "UUID                                 Status   Name\n"
            "F659FCF2-AC83-4072-86A6-F7538781A1FC started  "
            "Whiny-Windows11-x64\n"
        )
        self.assertEqual(
            parse_vm_list(output),
            [
                VmEntry(
                    "F659FCF2-AC83-4072-86A6-F7538781A1FC",
                    "started",
                    "Whiny-Windows11-x64",
                )
            ],
        )


if __name__ == "__main__":
    unittest.main()
