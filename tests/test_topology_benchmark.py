import unittest

from setup.run_topology_benchmark import percentile


class TopologyBenchmarkTests(unittest.TestCase):
    def test_percentiles_are_stable(self):
        values = [50.0, 10.0, 40.0, 20.0, 30.0]
        self.assertEqual(percentile(values, 0.50), 30.0)
        self.assertEqual(percentile(values, 0.95), 50.0)
        self.assertEqual(percentile(values, 0.99), 50.0)

    def test_empty_samples_are_rejected(self):
        with self.assertRaises(ValueError):
            percentile([], 0.5)


if __name__ == "__main__":
    unittest.main()
