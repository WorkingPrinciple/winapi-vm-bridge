import hashlib
import json
import unittest

from setup.generate_runtime_metadata import (
    canonical_json,
    provenance_document,
    spdx_document,
)


class RuntimeMetadataTests(unittest.TestCase):
    def test_spdx_and_provenance_are_deterministic_and_unsigned(self):
        metadata = {
            "version": 1,
            "packages": [
                {"id": "b", "name": "beta", "version": "2.0.0", "license": None},
                {
                    "id": "a",
                    "name": "alpha",
                    "version": "1.0.0",
                    "license": "Apache-2.0",
                },
            ],
        }
        source = "a" * 64
        first = canonical_json(spdx_document(metadata, source))
        second = canonical_json(spdx_document(metadata, source))
        self.assertEqual(first, second)
        relocated = json.loads(json.dumps(metadata))
        relocated["packages"][0]["id"] = "path+file:///tmp/other#beta@2.0.0"
        relocated["packages"][1]["id"] = "path+file:///tmp/other#alpha@1.0.0"
        self.assertEqual(first, canonical_json(spdx_document(relocated, source)))
        provenance = provenance_document(
            metadata,
            source,
            hashlib.sha256(first).hexdigest(),
            [{"name": "runtime.zip", "digest": {"sha256": "b" * 64}}],
            ["cargo build --release --locked -p wvb-runtime"],
        )
        self.assertEqual(provenance["signatures"], [])
        self.assertEqual(
            provenance["predicate"]["buildDefinition"]["externalParameters"][
                "sourceSha256"
            ],
            source,
        )
        self.assertEqual(provenance["subject"][0]["name"], "runtime.zip")


if __name__ == "__main__":
    unittest.main()
