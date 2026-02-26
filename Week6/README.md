## Week6 - Mixed Plaintext / Ciphertext Processing (明文 / 密文並存)

本週目標：
- **根據欄位敏感度 classifier 產生的 flag，動態決定每個欄位要走明文或加密處理**
- **實作一個簡單 pipeline，示範同一筆 record 中「明文 / 假加密(未來可換成 HE) 並存」的資料流程**

Week6 不再改變敏感度規則本身，而是把 Week5 的欄位層級 classifier 與 Week3 的 `AdaptiveModule` 串起來，讓系統可以自動：
1. 看欄位名稱 → 判斷是否需要 HE（flag 0/1）
2. 將需要 HE 的欄位放進 `encrypted` 區，其餘留在 `plain` 區
3. 透過一個參數 `enable_he` 決定是否真正啟用這個「混合保護」邏輯

### 檔案說明

- `mixed_protection.py`
  - `MixedProtectionPipeline`
    - 建構式：
      - 內部會建立：
        - `FeatureSensitivityClassifier`（來自 Week5）
        - `AdaptiveModule`（來自 Week3，負責把欄位分到 `plain` / `encrypted`）
    - `get_sensitive_fields(record) -> list[str]`
      - 使用欄位敏感度 classifier，對這筆 `record` 的 key 做判斷，回傳需要 HE 的欄位名稱清單。
    - `protect_record(record, enable_he: bool = True) -> dict`
      - 先用 `get_sensitive_fields` 找出 sensitive 欄位，再呼叫 `AdaptiveModule.protect(...)`：
        - 若 `enable_he=True`：
          - `record` 中屬於 sensitive 的欄位會出現在回傳 dict 的 `encrypted` 區。
          - 其餘欄位會出現在 `plain` 區。
        - 若 `enable_he=False`：
          - 等同於關閉 HE，所有欄位都會留在 `plain`，`encrypted` 會是空 dict。
      - 回傳格式：
        - `{"plain": {...}, "encrypted": {...}}`

- `run_mixed_protection_demo.py`
  - 示範如何用真實資料集跑一次「明文 / 密文並存」流程：
    - 讀取專案根目錄下的 `dataset/synthetic_web_auth_logs.csv` 第一筆資料。
    - 使用與 Week2 / Week4 相同的欄位映射，把 CSV 欄位轉成內部欄位名稱：
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
    - 把這筆轉換後的 `record` 丟給 `MixedProtectionPipeline`：
      1. `enable_he = True`：查看哪些欄位被分到 `encrypted`，哪些留在 `plain`。
      2. `enable_he = False`：比較全部都在 `plain` 的情況。

### 使用方式

1. 在專案根目錄執行 demo：

   ```bash
   python -m Week6.run_mixed_protection_demo
   ```

2. 觀察輸出：
   - `enable_he = True` 區塊：
     - `plain` 中只會剩下被視為非敏感的技術特徵（例如 `session_duration`, `failed_attempts`, ...）。
     - `encrypted` 中會包含：`user_id`, `ip_address`, `location`, `timestamp` 等敏感欄位（內容目前為 stub，例如 `enc(123)`，未來可換成真正的 CKKS）。
   - `enable_he = False` 區塊：
     - 所有欄位都在 `plain`，`encrypted` 為空，對照方便理解「啟用 / 關閉 HE」對資料結構的影響。

### 與前幾週的關係

- **Week2**：對「事件/紀錄」做敏感度與風險評估（SensitivityClassifier）。
- **Week3**：實作 APPAD 核心與 `AdaptiveModule`，支援將欄位分流到 `plain` / `encrypted`。
- **Week4 / Week5**：設計並定稿「欄位層級」敏感度 classifier（決定欄位是否需要 HE）。
- **Week6（本週）**：
  - 把欄位級 classifier 的 flag 轉成實際的處理決策：
    - 哪些欄位進 `encrypted`
    - 哪些欄位留在 `plain`
  - 實際示範「明文 / 假加密並存」的 data flow，作為之後真正接上 HE（例如 CKKS）的基礎。

