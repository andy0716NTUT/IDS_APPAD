# IDS_APPAD

APPAD（Adaptive Privacy-Preserving Anomaly Detection）實作專案：在異常偵測流程中，根據資料敏感度動態決定明文或加密處理。

## 專案目標
- 使用 Logistic Regression 進行異常偵測
- 以欄位/紀錄敏感度規則決定是否啟用保護
- 支援「明文 + 密文」混合資料流（Adaptive Protection）
- 將最終決策留在 Client 端模組

## 架構圖
![APPAD 系統架構圖](APPAD.drawio.png)

## 模組說明（目前主要使用）

### 1) `classifier`（敏感度判定）
- 主要功能：判斷資料欄位或事件是否屬於敏感資訊，提供加密決策依據。
- 核心內容：
  - `core/classifier.py`：敏感度分類器主流程。
  - `core/feature_sensitivity.py`：欄位級敏感度判定與索引提取（如 `sensitive_indices`）。
  - `core/rules.py`：敏感/非敏感規則、關鍵字與強制清單。
- 輸出：敏感欄位清單（供 `adaptive_module` 決定哪些欄位要加密）。

### 2) `adaptive_module`（自適應保護與流程協調）
- 主要功能：接收敏感欄位判定結果，對資料執行「敏感欄位加密、非敏感欄位明文」的混合保護。
- 核心內容：
  - `core/adaptive_module.py`：欄位級保護策略實作。
  - `core/mixed_protection.py`：明文/密文混合處理邏輯。
  - `core/core.py`：APPAD 核心協調流程（整合分類器、加密、模型推論）。
  - `demo/run_mixed_protection_demo.py`：端到端示範。
- 輸出：可供模型使用的受保護資料結構與示範結果。

### 3) `logistic_regression_model`（異常偵測模型）
- 主要功能：提供異常偵測模型的訓練與推論能力。
- 核心內容：
  - `core/logistic_regression_plain.py`：明文資料推論流程。
  - `core/logistic_regression_server.py`：伺服端 LR 推論封裝。
  - `training/train_logistic_regression.py`：模型訓練與儲存。
  - `inference/inference_tools.py`：可重用推論工具（載入模型、預測機率、預設資料/模型路徑）。
  - `inference/run_logistic_regression_inference.py`：CLI 推論腳本（呼叫 `inference_tools`）。
- 輸出：`output_lr/` 下的模型檔、指標報告與推論結果。

### 4) `ckks_homomorphic_encryption`（同態加密）
- 主要功能：封裝 CKKS 同態加密操作，供自適應保護流程使用。
- 核心內容：
  - `he_encryptor.py`：加密/解密或密文運算相關入口。
- 輸出：敏感欄位密文表示（供後續安全計算或傳輸）。

### 5) `traffic_generation`（隨機流量推論與效能評估）
- 主要功能：隨機抽樣資料集流量，分別執行明文推論與敏感資料保護後推論，輸出準確率與延遲統計。
- 核心內容：
  - `core/traffic_benchmark.py`：抽樣、保護流程、推論與評估主邏輯。
  - `scripts/run_traffic_benchmark.py`：可直接執行的 benchmark 腳本。
- 輸出：
  - `traffic_generation/output/traffic_benchmark_predictions.csv`（每筆樣本結果）
  - `traffic_generation/output/traffic_benchmark_metrics.json`（整體 accuracy/precision/recall/f1 與 latency）

## 可直接引用模組與方式

### 1) `classifier`
- 可引用：`SensitivityClassifier`、`FeatureSensitivityClassifier`、`need_he_flag_for_feature`
- 範例：
  - `from classifier import FeatureSensitivityClassifier`

### 2) `adaptive_module`
- 可引用：`AdaptiveModule`、`APPADCore`、`MixedProtectionPipeline`
- 範例：
  - `from adaptive_module import MixedProtectionPipeline`

### 3) `logistic_regression_model`
- 可引用（核心）：`LogisticRegressionPlain`、`ServerLR`
  - `from logistic_regression_model import ServerLR`
- 可引用（推論工具）：`load_trained_model`、`predict_probabilities`、`resolve_data_dir`、`resolve_model_path`
  - `from logistic_regression_model.inference import load_trained_model, predict_probabilities`

### 4) `ckks_homomorphic_encryption`
- 可引用：`CKKSEncryptor`
- 範例：
  - `from ckks_homomorphic_encryption import CKKSEncryptor`

### 5) `traffic_generation`
- 可引用：`run_traffic_benchmark`
- 範例：
  - `from traffic_generation import run_traffic_benchmark`

## `main.py` 執行方式

`main.py` 為專案整合入口，**預設會啟動前端網站流程**：
- 啟動 `frontend/backend_api.py`
- 啟動前端開發伺服器並開啟網站
- 之後由網站按鈕觸發分析執行

### 預設（建議）
- `python main.py`
  - 不會直接執行 pipeline
  - 不會先跑 privacy ratio sweep

### 需要 CLI 跑 pipeline 時
- `python main.py --pipeline [原本 pipeline 參數]`
- 範例：
  - `python main.py --pipeline --inference-mode mixed --skip-privacy-ratio-sweep`

### 指令參數
- `--dataset-path`：資料集 CSV 路徑（預設：`dataset/synthetic_web_auth_logs.csv`）
- `--sample-size`：抽樣筆數（預設：`500`）
- `--seed`：抽樣 random seed（預設：`42`）
- `--inference-mode`：推論模式，`plaintext` 或 `ckks`（預設：`plaintext`）
- `--output-dir`：輸出資料夾（預設：`output_results`）

### 輸出檔案
- `output_results/appad_main_predictions_<mode>.csv`
- `output_results/appad_main_metrics_<mode>.json`

## 專案檔案樹
```text
IDS_APPAD/
├─ adaptive_module/
│  ├─ core/
│  │  ├─ adaptive_module.py
│  │  ├─ core.py
│  │  └─ mixed_protection.py
│  └─ demo/
│     └─ run_mixed_protection_demo.py
├─ ckks_homomorphic_encryption/
│  └─ he_encryptor.py
├─ classifier/
│  ├─ core/
│  │  ├─ classifier.py
│  │  ├─ feature_sensitivity.py
│  │  └─ rules.py
│  ├─ scripts/
│  │  ├─ run_dataset.py
│  │  └─ run_generate_sensitive_feature_list.py
│  └─ data/
│     ├─ sample_data.py
│     └─ sensitive_feature_list.csv
├─ logistic_regression_model/
│  ├─ core/
│  │  ├─ logistic_regression_plain.py
│  │  └─ logistic_regression_server.py
│  ├─ training/
│  │  └─ train_logistic_regression.py
│  ├─ inference/
│  │  ├─ inference_tools.py
│  │  └─ run_logistic_regression_inference.py
│  └─ output_lr/
├─ traffic_generation/
│  ├─ core/
│  │  └─ traffic_benchmark.py
│  ├─ scripts/
│  │  └─ run_traffic_benchmark.py
│  └─ output/
├─ data_preprocessing/
│  └─ output/
├─ dataset/
│  └─ synthetic_web_auth_logs.csv
├─ APPAD.drawio.png
└─ README.md
```