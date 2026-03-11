## 自適應路由模組簡要報告

### 一、目標

本週將前幾週的成果（事件敏感度判斷、欄位級保護與混合同態加密、APPAD 架構）整合成一個**可實際運行的自適應路由模組**。  
系統依據每筆事件的敏感度與延遲預估，在兩條路徑間自動選擇：

- **`server_plain`**：純明文路徑，偏重效能（低敏感度事件）
- **`server_mixed_he`**：混合同態加密路徑，偏重隱私（中高敏感度事件）

並提供統一入口 `IDSSystem.process_event`，對外隱藏細節。

---

### 二、架構與模組

- **專案結構**
  - `adaptive_router.py`：路由決策與端到端流程
  - `feature_encoder.py`：將原始事件轉成數值特徵，支援 HE
  - `interfaces.py`：定義 `Encryptor`、`RecordEncoder`、`SensitivityClassifierLike`、`ModelServerLike` 介面
  - `system.py`：統一入口 `IDSSystem`
  - `run_adaptive_routing_demo.py`：完整 demo

- **特徵編碼（`SimpleRecordEncoder`）**
  - 保留欄位名稱（例如 `ip_address`, `location`, `timestamp`）。
  - 所有欄位轉為穩定的數值表示：
    - 數值欄位直接轉型並加上預設值保護。
    - 類別與字串欄位（含 `user_id`, `location` 等）使用 **SHA-256 穩定 hash + 取模**，確保跨機器可重現。
    - `timestamp` 取小時、`ip_address` 取最後一段 octet。

---

### 三、自適應路由邏輯（`AdaptiveRouter`）

- **RoutingConfig**：集中管理路由策略參數（延遲預算、網路 RTT、預設延遲估計、多目標權重等）。
- **決策原則**
  - **HIGH**：若 `encryption_required=True`，強制走 `server_mixed_he`。
  - **LOW**：若 `is_sensitive=False`，走 `server_plain`，不加密以追求最低延遲。
  - **MEDIUM**：
    - 估計 plaintext 與 HE 的處理時間（滑動平均或預設值）。
    - 計算使用 HE 的隱私收益，與延遲成本一起帶入效用函數。
    - 在延遲預算內盡量選擇隱私較好的路徑，否則退回 plaintext。

- **端到端流程**
  1. 事件敏感度分類（LOW / MEDIUM / HIGH + risk score）。
  2. 依設定與延遲預估選擇明文或混合 HE 路徑。
  3. 使用 `SimpleRecordEncoder` + `MixedProtectionPipeline` 組出 `{"plain":..., "encrypted":...}` payload。
  4. 伺服端模型推論（明文或 Paillier ciphertext），HE 結果由客戶端解密。
  5. 以 sigmoid 機率 + threshold 判斷是否異常，並回傳路由結果、加密欄位、延遲與決策。

---

### 四、IDSSystem 與 Demo

- **`IDSSystem`**
  - 透過 `IDSSystemConfig` 設定路由參數與異常判斷門檻。
  - 建構時注入 `Encryptor`，默認組合 `SimpleRecordEncoder`、`MixedProtectionPipeline` 與 `AdaptiveRouter`。
  - 對外只暴露 `process_event(raw_record)`，方便之後掛到 REST/gRPC 等服務。

- **Demo（`run_adaptive_routing_demo.py`）**
  - 從 `synthetic_web_auth_logs.csv` 讀取資料並做欄位對應。
  - 建立 `PaillierEncryptor` 與 `IDSSystem`，對每筆記錄跑自適應路由。
  - 在終端輸出每筆事件的路徑、敏感度、延遲、加密欄位與異常判斷。
  - 同步寫入 `adaptive_routing/demo_output.json`，方便後續分析。

---

### 五、測試與結論

- **測試**
  - 驗證特徵編碼對固定輸入的數值是否穩定（與 SHA-256 + 取模結果一致）。
  - 檢查 HIGH / LOW / MEDIUM 三種敏感度下的路由是否符合策略設計。
  - 測試 HE 路徑下，伺服端只在 ciphertext 上運算，最終由客戶端成功解密並完成異常判斷。

- **結論**
  - 完成一個可運行的 **自適應路由系統**，能在隱私與延遲之間動態取捨。
  - 透過穩定的特徵編碼與 `IDSSystem` 抽象，為未來接入真實模型、線上調參與更多隱私機制（多層 HE、差分隱私等）打下基礎。
raw_record
    │
    ▼
IDSSystem.process_event
    │
    ▼
敏感度分類 (LOW / MEDIUM / HIGH)
    │
    ▼
AdaptiveRouter 決策
    ├── 明文路徑 (低敏感 / 低延遲)
    │       │
    │       ▼
    │   特徵編碼 (plain)
    │       │
    │       ▼
    │   伺服端模型推論 (明文)
    │
    └── 混合同態路徑 (高敏感 / 強隱私)
            │
            ▼
        特徵編碼 + HE 加密 (encrypted)
            │
            ▼
        伺服端模型推論 (密文)
            │
            ▼
        客戶端解密 + 異常判斷

最終輸出: { route, enable_he, prob, is_anomaly, ... }
