"""
HE PoC：CKKS（TenSEAL）加密/運算可行性驗證（符合 APPAD 需求的最小集合）

本版本聚焦於 Week 1 的 PoC 目標：
1) 建立 CKKS context（真實 TenSEAL）
2) 將真實資料（Web_Auth_Anomaly_Detection）特徵向量加密/解密驗證
3) 同態加法（ct + ct）
4) 同態內積（dot product）：ct_x * w（明文權重）後 sum，驗證解密結果與明文一致性
5) 統計誤差與延遲（ms）

注意：
- 本版本不包含 sigmoid 近似、HE 下完整 LR 推論、APPAD workflow（避免 scope creep）
- 本版本強制使用 TenSEAL（不允許 simulation mode）

use "python -u .\HE.py --data_path ..\dataset\synthetic_web_auth_logs.csv --sample_ratio 0.3" to run
"""

import argparse
import time
import warnings
from dataclasses import dataclass
from typing import Dict, List, Tuple, Optional

import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, StandardScaler

warnings.filterwarnings("ignore")

# 強制使用 TenSEAL（PoC 才有意義）
try:
    import tenseal as ts
except ImportError as e:
    raise RuntimeError(
        "找不到 TenSEAL。此 PoC 必須使用真實 CKKS，請先安裝：pip install tenseal"
    ) from e


# ============================================================================
# CKKS 參數（可用 CLI 覆寫）
# ============================================================================
DEFAULT_POLY_MODULUS_DEGREE = 8192
DEFAULT_COEFF_MOD_BIT_SIZES = [60, 40, 40, 60]  # 足夠支援 dot + sum 這類 shallow 計算
DEFAULT_SCALE_BITS = 40


# ============================================================================
# 資料處理：Web_Auth_Anomaly_Detection（9 features）
# ============================================================================
class DataProcessor:
    """
    只做 PoC 需要的特徵抽取 + 基礎正規化（避免 HE 數值範圍過大）
    """

    def __init__(self, data_path: str, seed: int = 42):
        self.data_path = data_path
        self.seed = seed
        self.scaler = StandardScaler()

    def load(self, sample_ratio: float = 1.0) -> pd.DataFrame:
        df = pd.read_csv(self.data_path)
        if sample_ratio < 1.0:
            df = df.sample(frac=sample_ratio, random_state=self.seed).reset_index(drop=True)
        return df

    def extract_features(self, df: pd.DataFrame) -> Tuple[np.ndarray, np.ndarray]:
        """
        依你們程式原始邏輯（但更安全）抽出 9 個特徵：
        - Session Duration
        - Failed Attempts
        - Behavioral Score
        - Login Status (label-encoded)
        - Device Type (label-encoded)
        - Location (label-encoded)
        - IP last octet
        - Hour
        - DayOfWeek
        """
        # 基本欄位檢查（避免 KeyError）
        required_cols = [
            "Timestamp", "Login Status", "IP Address", "Device Type", "Location",
            "Session Duration", "Failed Attempts", "Behavioral Score", "Anomaly"
        ]
        for c in required_cols:
            if c not in df.columns:
                raise ValueError(f"資料缺少必要欄位：{c}，請確認 dataset 欄位名稱是否一致。")

        # 轉時間
        df = df.copy()
        df["Timestamp"] = pd.to_datetime(df["Timestamp"], errors="coerce")
        df["Hour"] = df["Timestamp"].dt.hour.fillna(0).astype(int)
        df["DayOfWeek"] = df["Timestamp"].dt.dayofweek.fillna(0).astype(int)

        # IP last octet
        def ip_last_octet(x: str) -> int:
            try:
                if pd.isna(x):
                    return 0
                return int(str(x).split(".")[-1])
            except Exception:
                return 0

        df["IP_last_octet"] = df["IP Address"].apply(ip_last_octet).astype(int)

        # 類別編碼
        le_status = LabelEncoder()
        le_device = LabelEncoder()
        le_location = LabelEncoder()

        df["Login_Status_enc"] = le_status.fit_transform(df["Login Status"].astype(str))
        df["Device_Type_enc"] = le_device.fit_transform(df["Device Type"].astype(str))
        df["Location_enc"] = le_location.fit_transform(df["Location"].astype(str))

        feature_cols = [
            "Session Duration",
            "Failed Attempts",
            "Behavioral Score",
            "Login_Status_enc",
            "Device_Type_enc",
            "Location_enc",
            "IP_last_octet",
            "Hour",
            "DayOfWeek",
        ]

        X = df[feature_cols].to_numpy(dtype=np.float64)
        y = df["Anomaly"].to_numpy(dtype=np.int32)

        # NaN / Inf 防護（PoC 需要穩定）
        X = np.nan_to_num(X, nan=0.0, posinf=0.0, neginf=0.0)
        return X, y

    def split_and_scale(
        self,
        X: np.ndarray,
        y: np.ndarray,
        test_size: float = 0.2,
        val_size: float = 0.2,
    ) -> Tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray, np.ndarray, np.ndarray]:
        """
        正規做法：先 split，再只用 train fit scaler，避免 data leakage。
        """
        X_train, X_temp, y_train, y_temp = train_test_split(
            X, y, test_size=(test_size + val_size), random_state=self.seed, stratify=y
        )
        # val_size 在 temp 中的比例
        val_ratio_in_temp = val_size / (test_size + val_size)
        X_val, X_test, y_val, y_test = train_test_split(
            X_temp, y_temp, test_size=(1 - val_ratio_in_temp),
            random_state=self.seed, stratify=y_temp
        )

        self.scaler.fit(X_train)
        X_train_s = self.scaler.transform(X_train)
        X_val_s = self.scaler.transform(X_val)
        X_test_s = self.scaler.transform(X_test)

        return X_train_s, y_train, X_val_s, y_val, X_test_s, y_test


# ============================================================================
# CKKS（TenSEAL）封裝
# ============================================================================
@dataclass
class CKKSConfig:
    poly_modulus_degree: int = DEFAULT_POLY_MODULUS_DEGREE
    coeff_mod_bit_sizes: Optional[List[int]] = None
    scale_bits: int = DEFAULT_SCALE_BITS

    def __post_init__(self):
        if self.coeff_mod_bit_sizes is None:
            self.coeff_mod_bit_sizes = DEFAULT_COEFF_MOD_BIT_SIZES


class CKKSEncryption:
    def __init__(self, cfg: CKKSConfig):
        self.cfg = cfg
        self.scale = 2 ** cfg.scale_bits

        self.context = ts.context(
            ts.SCHEME_TYPE.CKKS,
            poly_modulus_degree=cfg.poly_modulus_degree,
            coeff_mod_bit_sizes=cfg.coeff_mod_bit_sizes,
        )
        self.context.global_scale = self.scale

        # 向量操作常用
        self.context.generate_galois_keys()
        self.context.generate_relin_keys()

        print("\n" + "=" * 70)
        print("CKKS Context 已建立（TenSEAL / 真實模式）")
        print("=" * 70)
        print(f"  poly_modulus_degree: {cfg.poly_modulus_degree}")
        print(f"  coeff_mod_bit_sizes: {cfg.coeff_mod_bit_sizes}")
        print(f"  global_scale: 2^{cfg.scale_bits}")
        print("=" * 70)

    def encrypt_vec(self, x: np.ndarray) -> "ts.CKKSVector":
        return ts.ckks_vector(self.context, x.tolist())

    def decrypt_vec(self, ct: "ts.CKKSVector") -> np.ndarray:
        return np.array(ct.decrypt(), dtype=np.float64)


# ============================================================================
# PoC 測試（符合你們 Week 1 需求）
# ============================================================================
class HEPoCVerifier:
    def __init__(self, ckks: CKKSEncryption, seed: int = 42):
        self.ckks = ckks
        self.seed = seed
        self.results: Dict[str, Dict] = {}

    def _summary(self, name: str, result: Dict) -> None:
        self.results[name] = result
        status = "[PASSED]" if result.get("passed", False) else "[FAILED]"
        print(f"\n{name}: {status}")
        for k, v in result.items():
            if k == "passed":
                continue
            if isinstance(v, float):
                if "error" in k.lower():
                    print(f"  {k}: {v:.2e}")
                elif "time" in k.lower() or "latency" in k.lower():
                    print(f"  {k}: {v:.3f}")
                else:
                    print(f"  {k}: {v:.6f}")
            else:
                print(f"  {k}: {v}")

    def test_encrypt_decrypt(self, X: np.ndarray, n_samples: int = 10, tol: float = 1e-3) -> Dict:
        print("\n" + "=" * 70)
        print("PoC-1：加密/解密一致性（encrypt → decrypt）")
        print("=" * 70)

        n = min(n_samples, len(X))
        enc_times, dec_times = [], []
        max_errs = []
        mean_errs = []

        for i in range(n):
            x = X[i]
            t0 = time.time()
            ct = self.ckks.encrypt_vec(x)
            enc_times.append((time.time() - t0) * 1000)

            t1 = time.time()
            x_hat = self.ckks.decrypt_vec(ct)[: len(x)]
            dec_times.append((time.time() - t1) * 1000)

            err = np.abs(x - x_hat)
            max_errs.append(float(err.max()))
            mean_errs.append(float(err.mean()))

            if i < 3:
                print(f"\n樣本 {i+1}")
                print(f"  原始前5: {np.round(x[:5], 4)}")
                print(f"  解密前5: {np.round(x_hat[:5], 4)}")
                print(f"  max_err: {err.max():.2e}")

        result = {
            "max_error": float(np.max(max_errs)) if max_errs else 0.0,
            "mean_error": float(np.mean(mean_errs)) if mean_errs else 0.0,
            "avg_enc_time_ms": float(np.mean(enc_times)) if enc_times else 0.0,
            "avg_dec_time_ms": float(np.mean(dec_times)) if dec_times else 0.0,
        }
        result["passed"] = result["max_error"] < tol
        self._summary("PoC-1 encrypt/decrypt", result)
        return result

    def test_homomorphic_add(self, X: np.ndarray, n_pairs: int = 10, tol: float = 1e-3) -> Dict:
        print("\n" + "=" * 70)
        print("PoC-2：同態加法（ct_a + ct_b）")
        print("=" * 70)

        n_pairs = min(n_pairs, len(X) // 2)
        times = []
        max_errs = []
        mean_errs = []

        for i in range(n_pairs):
            a = X[2 * i]
            b = X[2 * i + 1]
            plain = a + b

            ct_a = self.ckks.encrypt_vec(a)
            ct_b = self.ckks.encrypt_vec(b)

            t0 = time.time()
            ct_sum = ct_a + ct_b
            times.append((time.time() - t0) * 1000)

            he = self.ckks.decrypt_vec(ct_sum)[: len(a)]
            err = np.abs(plain - he)
            max_errs.append(float(err.max()))
            mean_errs.append(float(err.mean()))

            if i < 2:
                print(f"\npair {i+1}")
                print(f"  plain前3: {np.round(plain[:3], 4)}")
                print(f"  he前3:    {np.round(he[:3], 4)}")
                print(f"  max_err: {err.max():.2e}")

        result = {
            "max_error": float(np.max(max_errs)) if max_errs else 0.0,
            "mean_error": float(np.mean(mean_errs)) if mean_errs else 0.0,
            "avg_add_time_ms": float(np.mean(times)) if times else 0.0,
        }
        result["passed"] = result["max_error"] < tol
        self._summary("PoC-2 homomorphic add", result)
        return result

    def test_homomorphic_dot(
        self,
        X: np.ndarray,
        n_samples: int = 10,
        tol: float = 1e-2,
        weight_mode: str = "random",
    ) -> Dict:
        """
        這是最關鍵的 PoC：驗證 LR 推論的核心運算 w·x + b 中的 w·x
        - 做法：ct_x * w（w 明文向量）後 sum()
        """
        print("\n" + "=" * 70)
        print("PoC-3：同態內積（dot product）= (ct_x * w).sum()")
        print("=" * 70)

        rng = np.random.default_rng(self.seed)
        d = X.shape[1]

        if weight_mode == "ones":
            w = np.ones(d, dtype=np.float64) / d
        else:
            # 隨機權重，但做尺度控制，避免數值過大
            w = rng.normal(0, 1, size=d).astype(np.float64)
            w = w / (np.linalg.norm(w) + 1e-12)

        print(f"  使用權重向量前5: {np.round(w[:5], 4)}")

        n = min(n_samples, len(X))
        times = []
        abs_errors = []
        rel_errors = []

        for i in range(n):
            x = X[i]
            plain = float(np.dot(x, w))

            ct_x = self.ckks.encrypt_vec(x)

            t0 = time.time()
            ct_prod = ct_x * w.tolist()     # element-wise multiply with plaintext
            ct_dot = ct_prod.sum()          # sum to scalar ciphertext
            times.append((time.time() - t0) * 1000)

            he = float(self.ckks.decrypt_vec(ct_dot)[0])
            abs_err = abs(plain - he)
            rel_err = abs_err / (abs(plain) + 1e-12)

            abs_errors.append(abs_err)
            rel_errors.append(rel_err)

            if i < 3:
                print(f"\n樣本 {i+1}")
                print(f"  plain dot: {plain:.6f}")
                print(f"  HE   dot:  {he:.6f}")
                print(f"  abs_err:   {abs_err:.2e}")

        result = {
            "abs_max_error": float(np.max(abs_errors)) if abs_errors else 0.0,
            "abs_mean_error": float(np.mean(abs_errors)) if abs_errors else 0.0,
            "rel_mean_error": float(np.mean(rel_errors)) if rel_errors else 0.0,
            "avg_dot_time_ms": float(np.mean(times)) if times else 0.0,
        }
        # dot 的容忍值通常比 encrypt/decrypt、加法略鬆（noise 累積）
        result["passed"] = result["abs_max_error"] < tol
        self._summary("PoC-3 homomorphic dot", result)
        return result

    def print_overall(self) -> bool:
        print("\n" + "=" * 70)
        print("HE PoC 總結")
        print("=" * 70)
        passed = True
        for name, r in self.results.items():
            ok = r.get("passed", False)
            print(f"  {name}: {'PASSED' if ok else 'FAILED'}")
            passed = passed and ok
        print("=" * 70)
        return passed


# ============================================================================
# CLI / Main
# ============================================================================
def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="HE PoC for APPAD (CKKS via TenSEAL)")
    p.add_argument("--data_path", type=str, required=True, help="Web_Auth_Anomaly_Detection CSV 路徑")
    p.add_argument("--sample_ratio", type=float, default=0.3, help="資料抽樣比例（PoC 可用 0.1~0.3）")
    p.add_argument("--seed", type=int, default=42)

    # CKKS
    p.add_argument("--poly_modulus_degree", type=int, default=DEFAULT_POLY_MODULUS_DEGREE)
    p.add_argument(
        "--coeff_mod_bit_sizes",
        type=str,
        default="60,40,40,60",
        help="例如：60,40,40,60（用逗號分隔）",
    )
    p.add_argument("--scale_bits", type=int, default=DEFAULT_SCALE_BITS)

    # tests
    p.add_argument("--n_samples", type=int, default=15, help="encrypt/decrypt 與 dot 測試樣本數")
    p.add_argument("--n_pairs", type=int, default=10, help="加法測試 pair 數")
    p.add_argument("--dot_tol", type=float, default=1e-2, help="dot product 的最大誤差容忍值")
    p.add_argument("--dot_weight_mode", choices=["random", "ones"], default="random")
    return p.parse_args()


def main() -> Dict[str, Dict]:
    args = parse_args()

    coeff_list = [int(x.strip()) for x in args.coeff_mod_bit_sizes.split(",") if x.strip()]
    cfg = CKKSConfig(
        poly_modulus_degree=args.poly_modulus_degree,
        coeff_mod_bit_sizes=coeff_list,
        scale_bits=args.scale_bits,
    )

    # 1) load data
    processor = DataProcessor(args.data_path, seed=args.seed)
    df = processor.load(sample_ratio=args.sample_ratio)
    X, y = processor.extract_features(df)
    X_train, y_train, X_val, y_val, X_test, y_test = processor.split_and_scale(X, y)

    print("\n" + "=" * 70)
    print("資料摘要（PoC 用）")
    print("=" * 70)
    print(f"  total: {len(X)}  train/val/test: {len(X_train)}/{len(X_val)}/{len(X_test)}")
    print(f"  feature_dim: {X_train.shape[1]}")
    print("=" * 70)

    # 2) init CKKS
    ckks = CKKSEncryption(cfg)

    # 3) run PoC tests (use X_train)
    verifier = HEPoCVerifier(ckks, seed=args.seed)
    verifier.test_encrypt_decrypt(X_train, n_samples=args.n_samples, tol=1e-3)
    verifier.test_homomorphic_add(X_train, n_pairs=args.n_pairs, tol=1e-3)
    verifier.test_homomorphic_dot(
        X_train,
        n_samples=args.n_samples,
        tol=args.dot_tol,
        weight_mode=args.dot_weight_mode,
    )

    verifier.print_overall()
    return verifier.results


if __name__ == "__main__":
    results = main()
