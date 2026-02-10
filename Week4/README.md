## Week4 - Sensitive Feature List & HE Flag Classifier

本週目標：
- **製作 sensitive feature 清單**
- **設計欄位層級的 classifier 規則，決定哪些欄位需要同態加密 (HE)（flag ∈ {0,1}）**

### 檔案說明

- `feature_sensitivity.py`
  - `need_he_flag_for_feature(feature_name) -> int`  
    - 根據欄位名稱（例如 `user_id`, `ip_address`, `session_duration`），回傳 **0 或 1**：
      - `1`：建議對此欄位做 HE / 加密
      - `0`：視為非敏感技術特徵
  - `FeatureSensitivityClassifier`
    - `flag_feature(feature_name)`：單一欄位 → `0/1`
    - `classify_features(feature_names)`：批次產生清單（含 reason）
    - `sensitive_indices(record)`：給一個 `dict` record，回傳其中需要 HE 的欄位名稱清單，可直接丟給 `AdaptiveModule.protect(..., sensitive_idx=...)` 使用。

- `run_generate_sensitive_feature_list.py`
  - 讀取專案根目錄下的 `dataset/synthetic_web_auth_logs.csv`
  - 使用與 Week2 相同的欄位映射：
    - `User ID` → `user_id`
    - `Login Status` → `login_status`
    - `IP Address` → `ip_address`
    - `Location` → `location`
    - `Session Duration` → `session_duration`
    - `Failed Attempts` → `failed_attempts`
    - `Behavioral Score` → `behavioral_score`
    - `Timestamp` → `timestamp`
    - `Device Type` → `device_type`
    - `Anomaly` → `anomaly`
  - 對這些 **內部欄位名** 做敏感度分類，輸出：
    - `Week4/sensitive_feature_list.csv`
    - 欄位：
      - `feature_name`
      - `source_columns`（對應的 CSV 欄位）
      - `need_HE_flag`（0/1）
      - `reason`（文字說明）

### 規則設計（重點）

- **強制敏感 (`FORCE_SENSITIVE_FEATURES`)：**  
  - `user_id`, `ip_address`, `location`, `timestamp`  
  → 直接或間接識別使用者／裝置／行為軌跡，flag = 1

- **明確非敏感 (`FORCE_NON_SENSITIVE_FEATURES`)：**
  - `session_duration`, `failed_attempts`, `behavioral_score`, `anomaly`, `device_type`  
  → 偏技術或統計特徵，本作業中視為 non-sensitive，flag = 0

- **關鍵字規則 (`SENSITIVE_KEYWORDS`)：**
  - 若欄位名稱含有 `id`, `user`, `account`, `email`, `phone`, `ip`, `addr`, `location`, `time`, `timestamp` 等字串  
  → 視為可能暴露身分/位置/行為資訊，flag = 1

- **其他未命中的欄位：**
  - 預設 `flag = 0`

### 使用方式

1. 在專案根目錄執行：

   ```bash
   python -m Week4.run_generate_sensitive_feature_list
   ```

2. 檢查輸出的 `Week4/sensitive_feature_list.csv`，確定每個欄位的 `need_HE_flag` 是否符合你對隱私風險的期待，必要時可手動調整：
   - `FORCE_SENSITIVE_FEATURES`
   - `FORCE_NON_SENSITIVE_FEATURES`
   - `SENSITIVE_KEYWORDS`

3. 若要在 APPAD pipeline 中實際使用（例如接到 `AdaptiveModule`）：
   - 使用 `FeatureSensitivityClassifier.sensitive_indices(record)` 取得需要 HE 的欄位名稱
   - 將結果當作 `sensitive_idx` 傳給 `AdaptiveModule.protect(...)`

### 實驗與測試結果總結

- **敏感欄位清單結果**（`Week4/sensitive_feature_list.csv`）：
  - `need_HE_flag = 1`：`user_id`, `ip_address`, `location`, `timestamp`
  - `need_HE_flag = 0`：`login_status`, `session_duration`, `failed_attempts`, `behavioral_score`, `device_type`, `anomaly`
  - 解釋：前四個欄位會直接或間接識別使用者／裝置／行為時間軸，因此建議以 HE 保護；其餘為技術或統計特徵，本作業中視為非敏感。

- **與 AdaptiveModule 的串接測試**：
  - 以 `dataset/synthetic_web_auth_logs.csv` 的第一筆紀錄作為輸入 `record`。
  - `FeatureSensitivityClassifier.sensitive_indices(record)` 得到：`['user_id', 'ip_address', 'location', 'timestamp']`。
  - 將上述清單作為 `sensitive_idx` 傳入 `AdaptiveModule.protect(record, flag=True, sensitive_idx=...)` 後：
    - `encrypted` 區包含：`user_id`, `ip_address`, `location`, `timestamp`
    - `plain` 區包含：`login_status`, `session_duration`, `failed_attempts`, `behavioral_score`, `device_type`, `anomaly`
  - 證明：欄位層級的敏感度 classifier 所產生的 flag 可以正確控制哪些欄位需要 HE，並可直接整合進 APPAD 的保護流程。