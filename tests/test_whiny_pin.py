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


if __name__ == "__main__":
    unittest.main()
