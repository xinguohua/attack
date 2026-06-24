"""scenario validation 单测 — 测加载 + schema。"""
import json
import os
import unittest


ATTACK_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                          "scenarios", "juiceshop")


class TestValidation(unittest.TestCase):

    def test_scenarios_count(self):
        files = [f for f in os.listdir(ATTACK_DIR) if f.endswith(".json")]
        self.assertGreaterEqual(len(files), 10)

    def test_scenarios_have_required_fields(self):
        for fn in os.listdir(ATTACK_DIR):
            if not fn.endswith(".json"):
                continue
            with open(os.path.join(ATTACK_DIR, fn)) as f:
                sc = json.load(f)
            self.assertIn("scenario_id", sc, msg=fn)
            self.assertIn("steps", sc, msg=fn)
            self.assertIn("final_attack_check", sc, msg=fn)
            self.assertIsInstance(sc["steps"], list)
            self.assertGreaterEqual(len(sc["steps"]), 1)
            for step in sc["steps"]:
                self.assertIn("step_id", step)
                self.assertIn("command", step)
                self.assertIn("checker", step)
                self.assertIn("type", step["checker"])


if __name__ == "__main__":
    unittest.main()
