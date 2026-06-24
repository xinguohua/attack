"""Sparse Bayesian Linear Regression with ARD prior — p2_mcts_v3.md §5.2 Eq 6-8。

承 GRABNEL [Wan et al. NeurIPS'21] §2 Surrogate model 块 Eq 5-7。

Model:
    s | Φ, α, σ_n²  ~  N(α^⊤ Φ, σ_n² I)                           (Eq 6)
    α | λ          ~  N(0, diag(λ⁻¹))                              (Eq 7)
    λ_i            ~  Gamma(k, θ),  k = θ = 1e-4(默认)             (Eq 8)

ARD prior 让 α_i 在数据不支持的维度自动收缩到 0(每个 α_i 配独立 λ_i)。

Posterior(closed-form):
    Σ_α = (diag(λ) + (1/σ_n²) Φ^⊤ Φ)^{-1}
    μ_α = (1/σ_n²) Σ_α Φ^⊤ s

ARD λ update(fixed-point,Tipping JMLR'01):
    γ_i = 1 − λ_i Σ_{α,ii}
    λ_i ← γ_i / μ_{α,i}²

预测:
    μ(G') = μ_α^⊤ Φ(G')
    σ²(G') = Φ(G')^⊤ Σ_α Φ(G') + σ_n²
"""
from __future__ import annotations

from typing import Optional, Tuple

import numpy as np


# ============================================================
# SparseBLR
# ============================================================

class SparseBLR:
    """Closed-form Sparse Bayesian Linear Regression with ARD prior。

    Attributes:
        D:          feature 维度
        sigma_n2:   likelihood noise variance σ_n²
        lambdas:    ARD precision 向量 λ ∈ ℝ^D(每个 α_i 独立)
        mu_alpha:   后验均值 μ_α ∈ ℝ^D
        Sigma_alpha: 后验协方差 Σ_α ∈ ℝ^{D×D}
        Phi_hist:   累积训练 features (n_obs, D)
        s_hist:     累积训练 targets (n_obs,)
    """

    def __init__(
        self,
        D: int,
        k: float = 1e-4,
        theta: float = 1e-4,
        sigma_n2: float = 0.1,
        ard_max_iter: int = 50,
        ard_tol: float = 1e-4,
    ) -> None:
        self.D = int(D)
        self.ard_k = float(k)
        self.ard_theta = float(theta)
        self.sigma_n2 = float(sigma_n2)
        self.ard_max_iter = int(ard_max_iter)
        self.ard_tol = float(ard_tol)

        # prior:λ_i = k/θ 期望(Gamma 期望 = shape*scale)→ 初始 prior precision
        self.lambdas = np.full(self.D, self.ard_k / max(self.ard_theta, 1e-12), dtype=np.float64)
        self.mu_alpha = np.zeros(self.D, dtype=np.float64)
        self.Sigma_alpha = np.eye(self.D, dtype=np.float64) / np.maximum(self.lambdas, 1e-12)

        # 训练历史
        self.Phi_hist: np.ndarray = np.zeros((0, self.D), dtype=np.float64)
        self.s_hist: np.ndarray = np.zeros((0,), dtype=np.float64)

    # ─── update / fit ────────────────────────────────────

    def update(self, phi: np.ndarray, s: float) -> None:
        """加入一个新 (Φ, s) 训练点,refresh ARD posterior(整批 closed-form)。

        增量 rank-1 也可以,但 ARD λ update 必须用整批 Σ_α 才稳定;
        这里采取 "累积历史 + closed-form 全量后验" 路径,O(n D² + D³) per update。
        训练点 ≤ B_max=20 量级,D=200,n*D² ≈ 800K + D³ = 8M,毫秒级开销。
        """
        phi = np.asarray(phi, dtype=np.float64).reshape(-1)
        if phi.shape[0] != self.D:
            raise ValueError(f"phi dim={phi.shape[0]} ≠ D={self.D}")
        self.Phi_hist = np.vstack([self.Phi_hist, phi[np.newaxis, :]])
        self.s_hist = np.concatenate([self.s_hist, np.array([float(s)])])
        self._refit_closed_form()

    def fit(self, Phi: np.ndarray, s: np.ndarray) -> None:
        """整批重置 + fit。"""
        self.Phi_hist = np.asarray(Phi, dtype=np.float64)
        self.s_hist = np.asarray(s, dtype=np.float64).reshape(-1)
        self._refit_closed_form()

    def _refit_closed_form(self) -> None:
        """ARD fixed-point + closed-form posterior。"""
        n = self.Phi_hist.shape[0]
        if n == 0:
            # 后验 = prior
            self.mu_alpha = np.zeros(self.D, dtype=np.float64)
            self.Sigma_alpha = np.diag(1.0 / np.maximum(self.lambdas, 1e-12))
            return

        Phi = self.Phi_hist
        s = self.s_hist
        PhiT_Phi = Phi.T @ Phi
        PhiT_s = Phi.T @ s

        prev_mu = self.mu_alpha.copy()
        for it in range(self.ard_max_iter):
            # Posterior:Σ_α = (diag(λ) + (1/σ_n²) Φ^⊤Φ)^{-1}
            A = np.diag(self.lambdas) + (1.0 / max(self.sigma_n2, 1e-12)) * PhiT_Phi
            try:
                self.Sigma_alpha = np.linalg.inv(A + 1e-10 * np.eye(self.D))
            except np.linalg.LinAlgError:
                # singular fallback:对角加大
                self.Sigma_alpha = np.linalg.inv(A + 1e-4 * np.eye(self.D))
            self.mu_alpha = (1.0 / max(self.sigma_n2, 1e-12)) * (self.Sigma_alpha @ PhiT_s)

            # ARD λ update:γ_i = 1 - λ_i Σ_{α,ii},λ_i ← γ_i / μ_{α,i}²
            diag_sig = np.clip(np.diag(self.Sigma_alpha), 1e-12, None)
            gamma = np.clip(1.0 - self.lambdas * diag_sig, 0.0, 1.0)
            mu_sq = self.mu_alpha ** 2 + 1e-12
            new_lambdas = gamma / mu_sq
            # 防止数值爆 + 防止 0
            new_lambdas = np.clip(new_lambdas, 1e-12, 1e12)

            # 收敛判定:μ_α 变化
            delta_mu = float(np.linalg.norm(self.mu_alpha - prev_mu))
            self.lambdas = new_lambdas
            prev_mu = self.mu_alpha.copy()
            if it > 0 and delta_mu < self.ard_tol:
                break

    # ─── posterior prediction ────────────────────────────

    def posterior(self, phi: np.ndarray) -> Tuple[float, float]:
        """对单个 Φ(G') 返回后验 (μ, σ)。"""
        phi = np.asarray(phi, dtype=np.float64).reshape(-1)
        mu = float(self.mu_alpha @ phi)
        var = float(phi @ self.Sigma_alpha @ phi) + self.sigma_n2
        sigma = float(np.sqrt(max(var, 0.0)))
        return mu, sigma

    def batch_posterior(self, Phi: np.ndarray) -> Tuple[np.ndarray, np.ndarray]:
        """批量后验 (μ, σ)。"""
        Phi = np.asarray(Phi, dtype=np.float64)
        mu = Phi @ self.mu_alpha
        var = np.einsum("ij,jk,ik->i", Phi, self.Sigma_alpha, Phi) + self.sigma_n2
        sigma = np.sqrt(np.clip(var, 0.0, None))
        return mu, sigma

    # ─── 诊断 ────────────────────────────────────────────

    @property
    def n_active_features(self) -> int:
        """ARD 后,|α_i| > 1e-6 的维度数(自动稀疏指标)。"""
        return int((np.abs(self.mu_alpha) > 1e-6).sum())

    def nll(self, Phi: np.ndarray, s: np.ndarray) -> float:
        """negative log-likelihood on held-out (Φ, s)。"""
        Phi = np.asarray(Phi, dtype=np.float64)
        s = np.asarray(s, dtype=np.float64).reshape(-1)
        mu, sigma = self.batch_posterior(Phi)
        # log p(s | μ, σ) = -0.5 log(2πσ²) - (s-μ)² / (2σ²)
        var = sigma ** 2 + 1e-12
        ll = -0.5 * np.log(2 * np.pi * var) - (s - mu) ** 2 / (2 * var)
        return float(-ll.mean())
