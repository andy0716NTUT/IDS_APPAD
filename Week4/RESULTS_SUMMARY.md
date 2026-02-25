# Week4 結果總結報告
## 特徵敏感度分類與同態加密(HE)標記

---

## 📊 分類結果統計

| 類別 | 數量 | 百分比 |
|------|------|--------|
| **需要HE加密** (flag=1) | 4 | 40% |
| **不需要HE加密** (flag=0) | 6 | 60% |
| **總特徵數** | 10 | 100% |

---

## 🔐 需要同態加密的敏感特徵 (HE Flag = 1)

| # | 特徵名稱 | 原始欄位 | 分類原因 |
|---|----------|----------|----------|
| 1 | `user_id` | User ID | 直接或強識別資訊 - 可唯一識別使用者身分 |
| 2 | `ip_address` | IP Address | 直接或強識別資訊 - 可追蹤裝置與網路位置 |
| 3 | `location` | Location | 直接或強識別資訊 - 地理位置敏感資訊 |
| 4 | `timestamp` | Timestamp | 直接或強識別資訊 - 行為時間軌跡資訊 |

### 風險說明
這四個欄位組合起來可以：
- 🔍 識別特定使用者的完整行為軌跡
- 📍 追蹤使用者的地理位置變化
- ⏰ 建立時間序列的行為模式
- 🎯 進行跨資料集的身分識別（re-identification）

---

## ✅ 不需要加密的技術特徵 (HE Flag = 0)

| # | 特徵名稱 | 原始欄位 | 分類原因 |
|---|----------|----------|----------|
| 1 | `anomaly` | Anomaly | 技術特徵，較難識別個人 - 僅為異常標記 |
| 2 | `behavioral_score` | Behavioral Score | 技術特徵，較難識別個人 - 統計數值 |
| 3 | `device_type` | Device Type | 技術特徵，較難識別個人 - 裝置類型太廣泛 |
| 4 | `failed_attempts` | Failed Attempts | 技術特徵，較難識別個人 - 失敗次數統計 |
| 5 | `login_status` | Login Status | 技術或統計性欄位 - 登入狀態 |
| 6 | `session_duration` | Session Duration | 技術特徵，較難識別個人 - 會話時長 |

### 非敏感理由
這些欄位：
- 📈 主要用於統計分析與模型訓練
- 🔢 單獨存在時難以識別特定個人
- ⚙️ 屬於技術性或行為統計特徵
- 🛡️ 即使洩露也不會直接暴露使用者身分

---

## 📋 分類規則設計

### 1️⃣ 強制敏感特徵清單
```python
FORCE_SENSITIVE_FEATURES = {
    "user_id",      # 使用者ID
    "ip_address",   # IP位址
    "location",     # 地理位置
    "timestamp",    # 時間戳記
}
```

### 2️⃣ 強制非敏感特徵清單
```python
FORCE_NON_SENSITIVE_FEATURES = {
    "session_duration",   # 會話時長
    "failed_attempts",    # 失敗嘗試次數
    "behavioral_score",   # 行為分數
    "anomaly",           # 異常標記
    "device_type",       # 裝置類型
}
```

### 3️⃣ 關鍵字規則
若欄位名稱包含以下關鍵字，則標記為敏感：
- **身分/帳號**: `id`, `user`, `account`, `uid`
- **聯絡資訊**: `email`, `phone`, `mail`, `tel`
- **位置/地址**: `address`, `location`, `city`, `region`
- **裝置/網路**: `ip`, `mac`, `device`, `imei`, `imsi`
- **金融資訊**: `card`, `bank`, `salary`
- **時間資訊**: `time`, `timestamp`

---

## 🔬 與 APPAD Pipeline 的整合測試

### 測試方法
使用 `FeatureSensitivityClassifier.sensitive_indices(record)` 取得需要HE的欄位清單，並傳入 `AdaptiveModule.protect()`

### 測試結果
```python
# 輸入: dataset/synthetic_web_auth_logs.csv 第一筆記錄
record = {
    "user_id": "U001",
    "login_status": "Success",
    "ip_address": "192.168.1.100",
    "location": "New York",
    "session_duration": 1200,
    "failed_attempts": 0,
    "behavioral_score": 85.5,
    "timestamp": "2024-01-01 10:00:00",
    "device_type": "Desktop",
    "anomaly": 0
}

# 分類器輸出
sensitive_indices = ['user_id', 'ip_address', 'location', 'timestamp']

# AdaptiveModule 處理結果
protected_data = {
    "encrypted": {  # 使用HE加密
        "user_id": <encrypted>,
        "ip_address": <encrypted>,
        "location": <encrypted>,
        "timestamp": <encrypted>
    },
    "plain": {  # 明文保留
        "login_status": "Success",
        "session_duration": 1200,
        "failed_attempts": 0,
        "behavioral_score": 85.5,
        "device_type": "Desktop",
        "anomaly": 0
    }
}
```

✅ **驗證成功**: 欄位層級的敏感度分類器可以正確控制APPAD的加密策略

---

## 📁 輸出檔案

- **CSV清單**: [`sensitive_feature_list.csv`](sensitive_feature_list.csv)
- **Python模組**: [`feature_sensitivity.py`](feature_sensitivity.py)
- **執行腳本**: [`run_generate_sensitive_feature_list.py`](run_generate_sensitive_feature_list.py)

---

## 🚀 使用方式

### 1. 生成敏感特徵清單
```bash
python -m Week4.run_generate_sensitive_feature_list
```

### 2. 在程式碼中使用
```python
from Week4.feature_sensitivity import FeatureSensitivityClassifier

# 初始化分類器
clf = FeatureSensitivityClassifier()

# 方法1: 單一特徵判斷
flag = clf.flag_feature("user_id")  # 回傳 1 (需要HE)

# 方法2: 批次分類
results = clf.classify_features(["user_id", "session_duration"])

# 方法3: 從record中自動提取敏感欄位
record = {"user_id": "U001", "session_duration": 1200, ...}
sensitive_fields = clf.sensitive_indices(record)
# 回傳: ['user_id']
```

### 3. 整合至 APPAD Pipeline
```python
from Week3.appad_core import AdaptiveModule
from Week4.feature_sensitivity import FeatureSensitivityClassifier

clf = FeatureSensitivityClassifier()
adaptive_module = AdaptiveModule()

# 自動識別敏感欄位並保護
sensitive_idx = clf.sensitive_indices(record)
protected = adaptive_module.protect(
    record=record,
    flag=True,
    sensitive_idx=sensitive_idx
)
```

---

## 📊 隱私保護效果評估

| 指標 | 說明 | 結果 |
|------|------|------|
| **敏感資訊覆蓋率** | 關鍵識別欄位是否被保護 | ✅ 100% (user_id, ip_address, location, timestamp 全數加密) |
| **計算效率** | 非必要欄位是否避免加密 | ✅ 良好 (60%欄位可明文處理，節省運算成本) |
| **準確性** | 分類規則是否合理 | ✅ 符合GDPR個資定義與實務經驗 |
| **可擴展性** | 新欄位是否能正確分類 | ✅ 支援關鍵字規則與手動調整 |

---

## 🎯 結論

Week4 成功建立了一套**欄位層級的敏感度分類系統**，具有以下特點：

1. ✅ **明確規則**: 基於GDPR與隱私實務，定義了強制敏感/非敏感特徵清單
2. ✅ **自動分類**: 透過關鍵字規則，可自動判斷新欄位的敏感性
3. ✅ **靈活調整**: 規則可透過修改 `FORCE_*_FEATURES` 和 `SENSITIVE_KEYWORDS` 輕鬆調整
4. ✅ **無縫整合**: 可直接與 Week3 的 AdaptiveModule 串接使用
5. ✅ **平衡效能**: 40%敏感欄位加密，60%明文處理，兼顧隱私與效能

這套系統為 APPAD (Adaptive Privacy Protection for Anomaly Detection) 提供了自動化的隱私保護決策能力。

---

*報告生成時間: 2026-02-12*
*資料來源: Week4/sensitive_feature_list.csv*
