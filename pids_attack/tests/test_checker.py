"""checker 单元测试 — 不进容器，用合成 CommandOutput 测 checker 派发。"""
import unittest

from range import checker as checker_mod
from range.checker import run_checker, CHECKER_DISPATCH, execute_with_checks
from range.execute import CommandOutput


def _co(stdout="", exit_code=0):
    return CommandOutput(command="x", stdout=stdout, stderr="", exit_code=exit_code,
                          response_time_sec=0.0)


class TestChecker(unittest.TestCase):

    def test_http_status_code_pass(self):
        spec = {"type": "http_status_code", "expected": 200}
        out = _co(stdout="HTTP/1.1 200 OK\r\nServer: x\r\n\r\nbody")
        r = run_checker(spec, out)
        self.assertTrue(r.success)

    def test_http_status_code_fail(self):
        spec = {"type": "http_status_code", "expected": 200}
        out = _co(stdout="HTTP/1.1 404 Not Found\r\n\r\n")
        r = run_checker(spec, out)
        self.assertFalse(r.success)

    def test_http_response_contains(self):
        spec = {"type": "http_response_contains", "expected": "admin@juice"}
        out = _co(stdout="HTTP/1.1 200 OK\r\n\r\n{\"email\":\"admin@juice-sh.op\"}")
        r = run_checker(spec, out)
        self.assertTrue(r.success)

    def test_exit_code(self):
        out = _co(exit_code=0)
        self.assertTrue(run_checker({"type": "exit_code", "expected": 0}, out).success)
        out2 = _co(exit_code=1)
        self.assertFalse(run_checker({"type": "exit_code", "expected": 0}, out2).success)

    def test_stdout_contains_and_not(self):
        out = _co(stdout="hello world")
        self.assertTrue(run_checker({"type": "stdout_contains", "expected": "world"}, out).success)
        self.assertTrue(run_checker({"type": "stdout_not_contains", "expected": "missing"}, out).success)
        self.assertFalse(run_checker({"type": "stdout_contains", "expected": "missing"}, out).success)

    def test_stdout_regex(self):
        out = _co(stdout="user: admin@example.com")
        self.assertTrue(run_checker({"type": "stdout_regex_match", "expected": r"\w+@\w+\.\w+"}, out).success)

    def test_unknown_checker_type(self):
        out = _co()
        r = run_checker({"type": "this_is_not_a_real_checker"}, out)
        self.assertFalse(r.success)
        self.assertIsNotNone(r.error_message)

    def test_checker_dispatch_complete(self):
        must_have = [
            "http_response_contains", "exit_code", "stdout_contains",
            "file_exists", "exfiltrated_data_present", "custom",
        ]
        for k in must_have:
            self.assertIn(k, CHECKER_DISPATCH)

    def test_batch_safe_segments_stop_after_failed_step(self):
        scenario = {
            "scenario_id": "unit_batch",
            "steps": [
                {
                    "step_id": 1,
                    "command": "step one",
                    "checker": {"type": "stdout_contains", "expected": "OK1"},
                },
                {
                    "step_id": 2,
                    "command": "step two",
                    "checker": {"type": "stdout_contains", "expected": "OK2"},
                },
                {
                    "step_id": 3,
                    "command": "step three",
                    "checker": {"type": "stdout_contains", "expected": "OK3"},
                },
            ],
        }
        calls = []

        def fake_batch(commands, trace_path, capture_trace):
            calls.append(list(commands))
            out = []
            for cmd in commands:
                stdout = {
                    "step one": "OK1",
                    "step two": "not ok",
                    "step three": "OK3",
                }.get(cmd, "")
                out.append(CommandOutput(cmd, stdout, "", 0, 0.0))
            return out

        old_batch = checker_mod._exec_traced_batch_safe
        checker_mod._exec_traced_batch_safe = fake_batch
        try:
            res = execute_with_checks(
                scenario,
                delta_commands=["delta before one", "delta before two", "delta before three"],
                delta_positions=[0, 1, 2],
                capture_trace=False,
                reset=False,
            )
        finally:
            checker_mod._exec_traced_batch_safe = old_batch

        self.assertFalse(res.all_steps_passed)
        self.assertEqual(res.failed_step, 2)
        self.assertEqual(calls, [
            ["delta before one", "step one"],
            ["delta before two", "step two"],
        ])
        self.assertEqual([r.step_id for r in res.step_results], [1, 2])


if __name__ == "__main__":
    unittest.main()
