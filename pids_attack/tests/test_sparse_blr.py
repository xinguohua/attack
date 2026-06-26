"""Unit tests for SparseBLR(p3_implementation_plan.md Step 3.3)。"""
import unittest

import numpy as np

from attack.safemimic_cmd.surrogate import SparseBLR


class TestSparseBLR(unittest.TestCase):

    def test_prior_posterior_no_data(self):
        """无数据时,posterior μ = 0,σ² > 0(取决于 prior λ)。"""
        blr = SparseBLR(D=5, sigma_n2=0.1)
        phi = np.array([1.0, 0.5, -0.5, 0.0, 1.0])
        mu, sigma = blr.posterior(phi)
        self.assertAlmostEqual(mu, 0.0, places=6)
        self.assertGreater(sigma, 0.0)

    def test_fit_recover_alpha_synthetic(self):
        """合成线性数据(已知 α_true)→ ARD 后验 mu_alpha 接近 α_true。"""
        rng = np.random.default_rng(seed=42)
        D = 10
        # 真正 alpha:稀疏,只有 3 维非零
        alpha_true = np.zeros(D)
        alpha_true[1] = 1.0
        alpha_true[4] = -0.5
        alpha_true[7] = 0.8
        # 生成 100 个数据点
        n = 100
        Phi = rng.normal(0, 1, size=(n, D))
        s = Phi @ alpha_true + rng.normal(0, 0.05, size=n)
        blr = SparseBLR(D=D, sigma_n2=0.05 ** 2, ard_max_iter=100)
        blr.fit(Phi, s)
        # 检查 mu_alpha 接近 alpha_true(允许容差)
        for i in (1, 4, 7):
            self.assertAlmostEqual(blr.mu_alpha[i], alpha_true[i], delta=0.2,
                                    msg=f"alpha[{i}] mismatch: pred={blr.mu_alpha[i]} true={alpha_true[i]}")
        # 应稀疏的维度(0/2/3/5/6/8/9)|μ| 应远小
        for i in (0, 2, 3, 5, 6, 8, 9):
            self.assertLess(abs(blr.mu_alpha[i]), 0.3,
                             msg=f"alpha[{i}] should be ~0,got {blr.mu_alpha[i]}")
        # ARD 稀疏性诊断
        self.assertLessEqual(blr.n_active_features, D)  # 不超总维度

    def test_update_incremental_matches_batch(self):
        """逐个 update 应跟 fit 整批等价(数值上)。"""
        rng = np.random.default_rng(seed=7)
        D = 6
        Phi = rng.normal(0, 1, size=(20, D))
        s = rng.normal(0, 1, size=20)

        blr_a = SparseBLR(D=D)
        blr_a.fit(Phi, s)

        blr_b = SparseBLR(D=D)
        for i in range(20):
            blr_b.update(Phi[i], s[i])

        # mu_alpha 应该几乎一样(ARD fixed-point 收敛到同一解)
        np.testing.assert_allclose(blr_a.mu_alpha, blr_b.mu_alpha, atol=1e-2)

    def test_batch_posterior_shape(self):
        """批量后验 shape 正确。"""
        blr = SparseBLR(D=8)
        rng = np.random.default_rng(seed=0)
        Phi = rng.normal(0, 1, size=(5, 8))
        s = rng.normal(0, 1, size=5)
        blr.fit(Phi, s)
        Phi_test = rng.normal(0, 1, size=(12, 8))
        mu, sigma = blr.batch_posterior(Phi_test)
        self.assertEqual(mu.shape, (12,))
        self.assertEqual(sigma.shape, (12,))
        self.assertTrue(np.all(sigma >= 0))

    def test_nll_held_out(self):
        """计算 NLL on held-out 数据,数值合理(不爆)。"""
        rng = np.random.default_rng(seed=3)
        D = 5
        alpha_true = np.array([1.0, 0.0, -0.5, 0.0, 0.3])
        Phi_train = rng.normal(0, 1, size=(50, D))
        s_train = Phi_train @ alpha_true + rng.normal(0, 0.1, size=50)
        blr = SparseBLR(D=D, sigma_n2=0.01)
        blr.fit(Phi_train, s_train)
        Phi_test = rng.normal(0, 1, size=(20, D))
        s_test = Phi_test @ alpha_true + rng.normal(0, 0.1, size=20)
        nll = blr.nll(Phi_test, s_test)
        self.assertTrue(np.isfinite(nll), f"NLL not finite: {nll}")
        self.assertLess(abs(nll), 100.0, f"NLL too large: {nll}")


if __name__ == "__main__":
    unittest.main()
