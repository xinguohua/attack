"""Phase 5 Nettack §4.1 unnoticeable perturbation constraints 单测。

承 p3 Phase 5 Validation "单测必须覆盖"清单。
"""
from __future__ import annotations
import unittest

from cmd_graph.graph import CommandGraph
from cmd_graph.nettack import (
    precompute_co_occurrence, precompute_power_law,
    eq12_check, eq10_incremental_lambda, r3_filter,
    resource_type, is_system_library, filter_resources,
    _power_law_likelihood, _fit_power_law_alpha,
)


def _build_benign_g():
    """搭一个 G_benign:3 个 process 节点,只连过 file 类型,没连过 netflow。"""
    g = CommandGraph()
    g.add_node(raw_command="cat /etc/passwd", inputs={"/etc/passwd"})
    g.add_node(raw_command="cat /tmp/foo", inputs={"/tmp/foo"})
    g.add_node(raw_command="ls /var/log", inputs={"/var/log"})
    g.refresh_e_res()
    return g


class TestResourceType(unittest.TestCase):

    def test_resource_type_classification(self):
        self.assertEqual(resource_type("/etc/passwd"), "file")
        self.assertEqual(resource_type("127.0.0.1:3000"), "netflow")
        self.assertEqual(resource_type("localhost:8080"), "netflow")
        self.assertEqual(resource_type("unix:/var/run/nscd/socket"), "unix")
        self.assertEqual(resource_type(""), "other")


class TestSystemLibraryFilter(unittest.TestCase):

    def test_known_system_libs(self):
        self.assertTrue(is_system_library("/lib/x86_64-linux-gnu/libc.so.6"))
        self.assertTrue(is_system_library("/etc/ld.so.cache"))
        self.assertTrue(is_system_library("/usr/lib/x86_64-linux-gnu/libcurl.so"))
        self.assertTrue(is_system_library("/etc/nsswitch.conf"))

    def test_non_system_paths(self):
        self.assertFalse(is_system_library("/tmp/x"))
        self.assertFalse(is_system_library("/home/u/data"))
        self.assertFalse(is_system_library("127.0.0.1:3000"))

    def test_filter_resources_strips_system_libs(self):
        resources = {"/etc/passwd", "/lib/x86_64-linux-gnu/libc.so.6",
                     "/tmp/x", "/etc/ld.so.cache"}
        filtered = filter_resources(resources)
        self.assertIn("/etc/passwd", filtered)
        self.assertIn("/tmp/x", filtered)
        self.assertNotIn("/lib/x86_64-linux-gnu/libc.so.6", filtered)
        self.assertNotIn("/etc/ld.so.cache", filtered)


class TestEq12CoOccurrence(unittest.TestCase):

    def test_precompute_returns_type_pairs(self):
        g = _build_benign_g()
        c = precompute_co_occurrence(g)
        # 3 个节点都只连 file → type_pairs 空(单类型自身不算 pair)
        self.assertEqual(c["type_pairs"], set())
        self.assertEqual(c["type_freq"]["file"], 3)

    def test_eq12_rejects_unseen_pair(self):
        """G_benign 中进程只连过 file;手搭 op 让 P 同时连 file + netflow → reject。"""
        g = _build_benign_g()
        c = precompute_co_occurrence(g)
        # before: 该进程已连 file;after: 加了 netflow → 引入 (file, netflow) 新对
        passed = eq12_check(
            op_affected_node_types_before={"file"},
            op_affected_node_types_after={"file", "netflow"},
            cmd_name="cat",
            c_benign=c,
            sigma=0.05,
        )
        self.assertFalse(passed)

    def test_eq12_passes_when_already_paired(self):
        """G_benign 中已有 (file, netflow) 共现 → 同类型 op 应该 pass。"""
        g = CommandGraph()
        g.add_node(raw_command="curl http://x:80/y", inputs={"x:80", "/etc/x"})
        g.refresh_e_res()
        c = precompute_co_occurrence(g)
        # 现在 G_benign 已经有节点同时连 file + netflow
        passed = eq12_check(
            op_affected_node_types_before={"file"},
            op_affected_node_types_after={"file", "netflow"},
            cmd_name="curl",
            c_benign=c,
            sigma=0.0,                                # σ=0 让 p>0 即 pass
        )
        self.assertTrue(passed)

    def test_eq12_passes_when_no_new_types(self):
        """before == after → 无新类型,trivially pass。"""
        g = _build_benign_g()
        c = precompute_co_occurrence(g)
        self.assertTrue(eq12_check({"file"}, {"file"}, "cat", c))


class TestEq10PowerLaw(unittest.TestCase):

    def test_fit_alpha_on_skewed_degrees(self):
        """简单 power-law 序列拟合应该给合理 α(2-3 范围)。"""
        degrees = [1, 1, 1, 1, 1, 1, 2, 2, 3, 5, 8, 15]
        alpha = _fit_power_law_alpha(degrees)
        self.assertTrue(1.0 < alpha < 5.0, f"α={alpha} out of expected range")

    def test_likelihood_finite(self):
        degrees = [1, 2, 3, 4, 5]
        l = _power_law_likelihood(degrees, alpha=2.0)
        self.assertTrue(l != float("inf") and l != float("-inf"))

    def test_eq10_rejects_degree_explosion(self):
        """给某节点加 degree=50 的扰动 → Λ = α·log(50.5) ≈ 7.85,远超 τ_Λ=2.0。"""
        deg_before = [1, 2, 1, 2, 3, 1, 1, 2, 1, 1]
        deg_after = deg_before + [50]
        pl = {"alpha": 2.0, "l": -50.0, "d_min": 1.0}
        lam = eq10_incremental_lambda(deg_before, deg_after, pl)
        # Λ = α · log(50.5) ≈ 7.85
        self.assertGreater(lam, 2.0, f"Λ={lam} 应该超 τ_Λ=2.0(degree=50)")

    def test_eq10_passes_modest_degree_change(self):
        """给某节点加 degree=2 的扰动 → Λ = α·log(2.5) ≈ 1.83,小于 τ_Λ=2.0。"""
        deg_before = [1, 2, 3, 2, 1, 2, 1, 1, 2, 1]
        deg_after = deg_before + [2]
        pl = {"alpha": 2.0, "l": -10.0, "d_min": 1.0}
        lam = eq10_incremental_lambda(deg_before, deg_after, pl)
        self.assertLess(lam, 2.0, f"Λ={lam} 应该 ≤ τ_Λ=2.0(modest degree=2)")

    def test_eq10_lambda_monotone_in_new_degree(self):
        """新加入的 degree 越大 → Λ 越大(monotone)。"""
        deg_before = [1, 2, 1, 2, 3]
        pl = {"alpha": 1.5, "l": -10.0, "d_min": 1.0}
        lams = []
        for d_new in [1, 5, 20, 100]:
            lams.append(eq10_incremental_lambda(deg_before, deg_before + [d_new], pl))
        for i in range(len(lams) - 1):
            self.assertGreater(lams[i + 1], lams[i],
                                f"Λ 不 monotone:{lams}")


class TestR3FilterIntegration(unittest.TestCase):

    def test_r3_filter_rejects_eq12_violation(self):
        """整体 r3_filter:Eq. 12 违反应 reject。"""
        g_before = CommandGraph()
        nid = g_before.add_node(raw_command="cat /etc/passwd",
                                 inputs={"/etc/passwd"})
        g_before.refresh_e_res()
        g_after = g_before.clone()
        # 扰动后该节点同时连了 netflow
        g_after.nodes[nid].inputs.add("127.0.0.1:80")
        g_after.refresh_e_res()

        benign = _build_benign_g()                       # G_benign 只 file,没共现 file+netflow
        c = precompute_co_occurrence(benign)
        pl = precompute_power_law(benign)
        passed, reason = r3_filter(g_before, g_after, [nid], c, pl)
        self.assertFalse(passed)
        self.assertIn("eq12", reason)


if __name__ == "__main__":
    unittest.main()
