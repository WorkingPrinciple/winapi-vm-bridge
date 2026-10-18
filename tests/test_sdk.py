import json
import tempfile
import unittest
from pathlib import Path

from sdk.generate import generate, validate


class GeneratorTests(unittest.TestCase):
    def test_example_generates_review_bundle(self):
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory)
            generate(Path("examples/example-math/adapter.json"), out)
            target = out / "example-math"
            self.assertTrue((target / "contract.json").is_file())
            self.assertIn("ExampleAdd", (target / "dispatch.generated.cpp").read_text())
            self.assertIn("real application operation", (target / "CHECKLIST.md").read_text())

    def test_unknown_top_level_field_rejected(self):
        data = json.loads(Path("examples/example-math/adapter.json").read_text())
        data["unsafeDllPath"] = "anything.dll"
        with self.assertRaises(ValueError):
            validate(data)

    def test_unbounded_buffer_rejected(self):
        data = json.loads(Path("examples/example-math/adapter.json").read_text())
        data["operations"]["Add"]["parameters"][0] = {
            "name": "input", "type": "bytes", "direction": "in"
        }
        with self.assertRaises(ValueError):
            validate(data)


if __name__ == "__main__":
    unittest.main()

