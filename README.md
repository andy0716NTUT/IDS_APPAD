# IDS_APPAD

APPAD（Adaptive Privacy-Preserving Anomaly Detection）實作專案：在異常偵測流程中，根據資料敏感度動態決定明文或加密處理。

## 專案目標
- 使用 Logistic Regression 進行異常偵測
- 以欄位/紀錄敏感度規則決定是否啟用保護
- 支援「明文 + 密文」混合資料流（Adaptive Protection）
- 將最終決策留在 Client 端模組

## 架構圖
![APPAD 系統架構圖](APPAD.drawio.png)

## 模組說明

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
  - `inference/run_logistic_regression_inference.py`：載入模型並進行推論。
- 輸出：`output_lr/` 下的模型檔、指標報告與推論結果。

### 4) `data_preprocessing`（資料前處理）
- 主要功能：提供訓練/推論前的標準化與正規化能力。
- 核心內容：
  - `scripts/normalize.py`：Min-Max 正規化。
  - `scripts/standardize.py`：Standardization（Z-score）。
- 輸出：`output/normalize/`、`output/standard/` 的處理後資料與參數檔。

### 5) `ckks_homomorphic_encryption`（同態加密）
- 主要功能：封裝 CKKS 同態加密操作，供自適應保護流程使用。
- 核心內容：
  - `he_encryptor.py`：加密/解密或密文運算相關入口。
- 輸出：敏感欄位密文表示（供後續安全計算或傳輸）。

### 6) `decision_module`（客戶端決策）
- 主要功能：在客戶端整合模型輸出與規則結果，產生最終判定。
- 核心內容：
  - `client_decision.py`：Client 端最終決策邏輯。
- 輸出：異常/正常與保護策略相關的最終決策結果。

## 快速執行
- 產生敏感欄位清單
  - `python -m classifier.scripts.run_generate_sensitive_feature_list`
- LR 訓練
  - `python -m logistic_regression_model.training.train_logistic_regression`
- LR 推論
  - `python -m logistic_regression_model.inference.run_logistic_regression_inference`
- 混合保護 Demo
  - `python -m adaptive_module.demo.run_mixed_protection_demo`

## Week4 結果摘要（敏感特徵分類）
- 分類統計：10 個特徵中，4 個需 HE 加密（40%），6 個可明文處理（60%）
- 需加密欄位：`user_id`、`ip_address`、`location`、`timestamp`
- 不需加密欄位：`anomaly`、`behavioral_score`、`device_type`、`failed_attempts`、`login_status`、`session_duration`
- 規則設計：
  - 強制敏感清單與強制非敏感清單
  - 關鍵字規則（例如 `id/user/account`、`ip/device`、`location/address`、`time/timestamp`）
- Pipeline 整合結果：`FeatureSensitivityClassifier.sensitive_indices(record)` 能正確驅動 `AdaptiveModule.protect()` 將敏感欄位進入加密流程
- 隱私/效能平衡：關鍵識別資訊覆蓋率 100%，同時保留 60% 欄位明文處理以降低運算成本

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
├─ data_preprocessing/
│  ├─ scripts/
│  │  ├─ normalize.py
│  │  └─ standardize.py
│  └─ output/
│     ├─ normalize/
│     └─ standard/
├─ decision_module/
│  └─ client_decision.py
├─ logistic_regression_model/
│  ├─ core/
│  │  ├─ logistic_regression_plain.py
│  │  └─ logistic_regression_server.py
│  ├─ training/
│  │  └─ train_logistic_regression.py
│  ├─ inference/
│  │  └─ run_logistic_regression_inference.py
│  └─ output_lr/
├─ dataset/
│  └─ synthetic_web_auth_logs.csv
├─ output_results/
│  └─ mixed_protection_visualization_week6.png
├─ APPAD.drawio.png
├─ conftest.py
└─ README.md
```

## 備註
- 原 `classifier/RESULTS_SUMMARY_week4.md` 內容已整併至本文件。

