import unittest

from setup.run_utm_acceptance import VmEntry, exact_target, parse_vm_list


class RuntimeAcceptanceTests(unittest.TestCase):
    def test_vm_list_parser_and_exact_identity(self):
        entries = parse_vm_list(
            "UUID Status Name\n"
            "F18FAD97-5A85-4AB5-8D1B-D529D493B981 stopped Windows\n"
            "F659FCF2-AC83-4072-86A6-F7538781A1FC started Whiny-Windows11-x64\n"
        )
        self.assertEqual(
            exact_target(
                entries,
                "Whiny-Windows11-x64",
                "F659FCF2-AC83-4072-86A6-F7538781A1FC",
            ),
            VmEntry(
                "F659FCF2-AC83-4072-86A6-F7538781A1FC",
                "started",
                "Whiny-Windows11-x64",
            ),
        )

    def test_identity_mismatch_fails_closed(self):
        entries = [
            VmEntry(
                "F659FCF2-AC83-4072-86A6-F7538781A1FC",
                "started",
                "Whiny-Windows11-x64",
            )
        ]
        with self.assertRaises(RuntimeError):
            exact_target(
                entries,
                "Whiny-Windows11-x64",
                "00000000-0000-0000-0000-000000000000",
            )


if __name__ == "__main__":
    unittest.main()
