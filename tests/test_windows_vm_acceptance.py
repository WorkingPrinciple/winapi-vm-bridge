import tempfile
import unittest
import zipfile
from pathlib import Path

from setup.build_windows_vm_acceptance import sha256, write_zip
from setup.run_utm_correlated_acceptance import (
    complete_host_state,
    reserve_host_state,
    validate_qemu_command,
)
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

    def test_qemu_disk_mismatch_and_snapshot_fail_closed(self):
        uuid = "F659FCF2-AC83-4072-86A6-F7538781A1FC"
        disk = "065112D9-3B2D-4E40-AF74-C6B29CA4D133"
        path = f"/vm/{disk}.qcow2"
        command = (
            f"qemu-x86_64-softmmu -uuid {uuid} "
            f"-drive id=drive{disk},file.filename={path}"
        )
        validate_qemu_command(command, uuid, disk, path)
        with self.assertRaises(RuntimeError):
            validate_qemu_command(command, uuid, "wrong-disk", path)
        with self.assertRaises(RuntimeError):
            validate_qemu_command(command + " -snapshot ", uuid, disk, path)

    def test_receipt_sequence_and_challenge_reservation_fail_closed(self):
        initial = {"lastSequence": 0, "challenges": [], "pending": None}
        reserved = reserve_host_state(
            initial,
            sequence=1,
            challenge_sha256="11" * 32,
            attempt_id="22" * 16,
            authorization_sha256="33" * 32,
        )
        self.assertEqual(reserved["lastSequence"], 0)
        self.assertEqual(reserved["challenges"], [])
        with self.assertRaises(RuntimeError):
            reserve_host_state(
                reserved,
                sequence=2,
                challenge_sha256="44" * 32,
                attempt_id="55" * 16,
                authorization_sha256="66" * 32,
            )
        completed = complete_host_state(
            reserved,
            sequence=1,
            challenge_sha256="11" * 32,
            attempt_id="22" * 16,
            receipt_sha256="77" * 32,
        )
        self.assertEqual(completed["lastSequence"], 1)
        self.assertEqual(completed["challenges"], ["11" * 32])
        self.assertIsNone(completed["pending"])
        with self.assertRaises(RuntimeError):
            reserve_host_state(
                completed,
                sequence=2,
                challenge_sha256="11" * 32,
                attempt_id="88" * 16,
                authorization_sha256="99" * 32,
            )


if __name__ == "__main__":
    unittest.main()
