## Week5 - Final Feature Sensitivity Classifier (Reuse & Integration)

本週目標：
- **沿用並整理 Week4 的欄位層級敏感度 classifier，作為之後實驗的「最終版規則」**
- **確認此 classifier 可以方便地被 APPAD / HE 流程呼叫與整合**

Week5 不再重新設計新規則，而是把 Week4 已經驗證過的邏輯直接「封裝／定稿」，讓後續所有實驗都可以穩定使用同一份欄位敏感度判斷。

### 檔案說明

- `feature_sensitivity.py`
  - 延續 Week4 的設計，提供欄位層級的敏感度判斷：
  - `need_he_flag_for_feature(feature_name) -> int`  
    - 根據欄位名稱（例如 `user_id`, `ip_address`, `session_duration`），回傳 **0 或 1**：
      - `1`：建議對此欄位做 HE / 加密
      - `0`：視為非敏感技術特徵
  - `FeatureSensitivityClassifier`
    - `flag_feature(feature_name)`：單一欄位 → `0/1`
    - `classify_features(feature_names)`：批次產生清單（含 reason）
    - `sensitive_indices(record)`：給一個 `dict` record，回傳其中需要 HE 的欄位名稱清單，可直接丟給 `AdaptiveModule.protect(..., sensitive_idx=...)` 使用。

- `__init__.py`
  - 方便以 `Week5` 這個 package 名稱對外匯入（例如 `from Week5 import FeatureSensitivityClassifier`）。

> 若你需要產生新的敏感欄位清單（CSV），可以直接複製 Week4 的 `run_generate_sensitive_feature_list.py` 到 Week5，並將匯入路徑改成 `from Week5.feature_sensitivity import FeatureSensitivityClassifier`；輸出路徑也可以改成 `Week5/sensitive_feature_list.csv` 作為 Week5 版本。

### Week5 與 Week4 的差異／延伸

- **Week4：**
  - 主要工作是「設計規則」與「產生 `Week4/sensitive_feature_list.csv`」，並透過簡單測試證明：
    - 欄位層級的 flag 可以正確標示需要 HE 的欄位
    - 可以與 `AdaptiveModule` 串接，控制 `encrypted` / `plain` 欄位

- **Week5：**
  - 不再調整規則，而是：
    - **沿用 Week4 的 `feature_sensitivity.py` 邏輯，整理成一個穩定可重用的模組**
    - **作為「最終版欄位敏感度 classifier」供後續 APPAD / HE 實驗直接匯入**
    - 若需要針對其他資料集／場景重跑敏感欄位清單，只要呼叫同一份規則即可，確保實驗結果一貫。

### 使用方式（在 Week5 中）

1. 在其他模組匯入 Week5 的 classifier：

   ```python
   from Week5 import FeatureSensitivityClassifier, need_he_flag_for_feature

   clf = FeatureSensitivityClassifier()
   print(clf.flag_feature("user_id"))        # 1
   print(clf.sensitive_indices(record_dict)) # 回傳需要 HE 的欄位名稱 list
   ```

2. 若已經有 APPAD / HE 的流程（例如 Week3 的 `AdaptiveModule`）：
   - 使用 `FeatureSensitivityClassifier.sensitive_indices(record)` 取得需要 HE 的欄位名稱
   - 將結果當作 `sensitive_idx` 傳給 `AdaptiveModule.protect(...)`
   - 如此即可保證 Week5 之後所有實驗都使用相同的敏感度規則。

