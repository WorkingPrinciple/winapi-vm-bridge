import hashlib
import json
import unittest
from pathlib import Path


class WhinyPinTests(unittest.TestCase):
    def test_frozen_scalar_pin_matches_imported_bytes(self):
        root = Path("external/whiny/v0.3.0")
        pin = json.loads((root / "PIN.json").read_text(encoding="utf-8"))
        self.assertEqual(
            pin["revision"],
            "870da868f3d3d48f1da1a36123a9aaf1a6435e53",
        )
        for name, fields in pin["bundles"].items():
            bundle = root / "frozen-bundles" / name
            expected = {
                "bundleSha256": bundle / "bundle.json",
                "contractSha256": bundle / "contract.canonical.json",
            }
            descriptor = json.loads((bundle / "bundle.json").read_text(encoding="utf-8"))
            expected["dispatcherSha256"] = bundle / descriptor["dispatcher"]["path"]
            expected["targetSha256"] = bundle / descriptor["target"]["path"]
            for field, path in expected.items():
                self.assertEqual(
                    hashlib.sha256(path.read_bytes()).hexdigest(),
                    fields[field],
                    f"{name} {field}",
                )

    def test_execution_admissions_match_loadable_files(self):
        root = Path("runtime-artifacts/whiny-v0.3.0")
        for name in ["native-scalar", "managed-scalar"]:
            directory = root / name
            admission_bytes = (directory / "execution-admission.json").read_bytes()
            admission = json.loads(admission_bytes)
            build_receipt = directory / "build-receipt.json"
            self.assertEqual(
                hashlib.sha256(build_receipt.read_bytes()).hexdigest(),
                admission["buildReceiptSha256"],
            )
            for entry in admission["files"]:
                self.assertEqual(
                    hashlib.sha256((directory / entry["path"]).read_bytes()).hexdigest(),
                    entry["sha256"],
                )

    def test_runtime_acceptance_receipts_are_exact_and_acceptance_only(self):
        root = (
            Path("runtime-artifacts/whiny-v0.3.0")
            / "acceptance"
            / "runtime-receipts-v1"
        )
        expected_hashes = {
            "native-scalar-receipt.json":
                "f1a6b46da911033d5aef97570ead963fc9b6819d7c4051782db6a666ca8abad8",
            "managed-scalar-receipt.json":
                "f2f3c804a25af272ad62bffaead6746f91730e21b33611147ec9cb09734f4380",
            "native-scalar-receipt-jcs.json":
                "eb02139899a73b93f11bd273ee9a27c9d599b7e0723c0a2695eb91d39ce422cd",
            "managed-scalar-receipt-jcs.json":
                "bcbb3a8086fca5aa705e9577bdc93e875ea51e76aca514314d54867814e458b6",
            "whiny-trust-policy.json":
                "fedfc843772405c0dd799ba83e6a108f56e2c98ea06a1935efd61f114fa292e9",
            "index.json":
                "b57ad845e28054a969705f1f3c1cc8f60478f6d07242693a9e9f4af8f9cb357c",
        }
        for name, expected in expected_hashes.items():
            self.assertEqual(
                hashlib.sha256((root / name).read_bytes()).hexdigest(),
                expected,
                name,
            )

        policy = json.loads((root / "whiny-trust-policy.json").read_text())
        self.assertEqual(policy["schema"], "whiny.runtime-receipt.trust-policy.v1")
        self.assertEqual(policy["signing_domain"], "whiny.runtime-receipt.v1\\u0000")
        self.assertEqual(
            policy["historical_invalid_receipts"],
            ["native-scalar-receipt.json", "managed-scalar-receipt.json"],
        )
        self.assertEqual(policy["host_ids"], ["crossover-XOdeLabRPC"])
        self.assertTrue(policy["signers"])
        for signer in policy["signers"]:
            self.assertEqual(signer["scope"], "acceptance-only")
            self.assertFalse(signer["production_runtime_identity"])

        receipts = [
            json.loads((root / "native-scalar-receipt-jcs.json").read_text()),
            json.loads((root / "managed-scalar-receipt-jcs.json").read_text()),
        ]
        self.assertEqual([receipt["sequence"] for receipt in receipts], [1, 2])
        self.assertTrue(all(receipt["status"] == "ok" for receipt in receipts))
        self.assertTrue(
            all(
                receipt["runtime_identity"]["host_id"] == "crossover-XOdeLabRPC"
                for receipt in receipts
            )
        )


if __name__ == "__main__":
    unittest.main()
