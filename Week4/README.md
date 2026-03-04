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

### 延伸實驗：Week7_8 多目標自適應路由（隱私收益 vs 延遲成本）

為了把「欄位敏感度」進一步連結到實際部署時的路由決策，我在 `Week7_8/adaptive_router.py` 中加入了 **多目標自適應路由策略**，讓系統在 **隱私保護** 與 **推論延遲** 之間做更精細的權衡：

- **RoutingConfig 新增多目標參數**
  - `enable_multi_objective: bool = True`  
    - 開啟後，對於 **MEDIUM 敏感度** 的請求，不再只用「有沒有超過 latency budget」的二元規則，而是用效用函數比較 HE 與 plaintext。
  - `privacy_weight: float = 1.0`  
    - 控制「隱私收益」在效用中的權重，數值越大，越偏向選擇 HE。
  - `latency_weight: float = 0.01`  
    - 控制「延遲成本」在效用中的權重（乘在毫秒上，因此設為較小的數），數值越大，越偏向選擇延遲較低的 plaintext。
  - 仍保留 `latency_budget_ms` 作為 **延遲護欄**，避免在極端情況下選到非常慢的 HE 路由。

- **隱私收益模型 `_privacy_gain_for_he(...)`**
  - 依據敏感度輸出（例如 `sensitivity_level` 與 `risk_score`）給每一筆記錄計算一個簡單的 **隱私收益分數**：
    - LOW：≈ 0（幾乎不會走 HE）
    - MEDIUM：`1.0 + risk_score`，`risk_score ∈ [0, 1]`，風險越高，選 HE 的「收益」越大。
    - HIGH：更高的 base 分數，但 HIGH 本來就被強制走 HE。
  - 這個函數讓 MEDIUM 級別不再是「一刀切」，而是可以隨著紀錄的風險分數改變是否走 HE。

- **多目標效用函數與路由決策**
  - 對於 MEDIUM 級別，路由器會先估計兩條路徑的總延遲：
    - `plain_est = _estimate_total_latency_ms("server_plain")`
    - `he_est = _estimate_total_latency_ms("server_mixed_he")`
  - 然後計算兩條路的 **效用**：
    - plaintext 路由（隱私收益近似 0）：
      - $U_{plain} = - \\text{latency\\_weight} \\cdot plain\\_est$
    - HE 路由：
      - $U_{he} = \\text{privacy\\_weight} \\cdot privacy\\_gain\\_he - \\text{latency\\_weight} \\cdot he\\_est$
  - 決策規則：
    - 若 `U_he >= U_plain`，則走 `server_mixed_he`（加密路徑）
    - 否則走 `server_plain`（明文路徑）
    - 若 `he_est` 超過 `latency_budget_ms` 且 `U_he < U_plain`，則強制回退到 plaintext，以避免延遲失控。

- **如何透過參數實現不同策略**
  - **偏隱私（盡量多走 HE）**：
    - 提高 `privacy_weight`（例如 1.5–2.0）
    - 降低 `latency_weight`（例如 0.005）
    - 放寬 `latency_budget_ms`（例如 150–200 ms）
  - **偏性能（只在風險偏高時走 HE）**：
    - 提高 `latency_weight`（例如 0.02）
    - 緊縮 `latency_budget_ms`（例如 80–100 ms）
    - 保持或略微降低 `privacy_weight`

總結來說，Week4 先完成了**欄位層級敏感度判斷與 HE flag 設計**，而在 Week7_8 進一步把這些「敏感度訊號」轉化為 **路由層級的多目標決策**：  
系統不再只用硬編碼規則決定是否加密，而是透過可調的效用函數在「隱私收益」與「延遲成本」之間做權衡，能更貼近實際部署場景中的 SLO / 隱私政策需求。