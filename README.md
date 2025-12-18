# IDS_APPAD - 自適應隱私保護異常檢測系統

> 基於論文 "Adaptive Privacy-Preserving Framework for Network Traffic Anomaly Detection" 的實作

## 🎯 這個系統在做什麼？

簡單來說：**檢測網路攻擊，同時保護用戶隱私**

- 📊 分析網路流量，找出異常行為（可能是攻擊）
- 🔒 敏感資料（如密碼）用加密方式處理
- ⚡ 一般資料用快速方式處理
- 🎚️ 自動切換，平衡隱私和速度

---

## 🧩 怎麼分工？三個獨立項目

把整個系統拆成三塊，像拼圖一樣各自完成再組合：

```
用戶流量 
   ↓
┌──────────────────────────────────────┐
│  項目 1: 看看這是不是敏感資料？       │  ← 貼標籤
│  "這封包有密碼" → 標記為【敏感】      │
└──────────────────────────────────────┘
   ↓
┌──────────────────────────────────────┐
│  項目 3: 決定要用哪種方式檢測         │  ← 交通指揮
│  看標籤決定走哪條路                   │
└──────────────────────────────────────┘
   ↓                    ↓
【敏感】              【不敏感】
   ↓                    ↓
┌─────────────┐    ┌─────────────┐
│  項目 2:    │    │  明文檢測   │
│  加密檢測   │    │  (快速)     │
│  (安全)     │    │             │
└─────────────┘    └─────────────┘
   ↓                    ↓
   └──────────┬─────────┘
              ↓
         輸出結果
```

---

## 📦 項目 1：隱私分類器

**做什麼**：判斷這筆流量有沒有隱私資料

**輸入**：網路封包  
**輸出**：一個標籤 + 8 個特徵數字

### 實作步驟

**階段一：規則引擎版本（Week 1）**
```python
def classify_traffic(packet):
    # 簡單規則檢測
    sensitive_keywords = ['password', 'credit_card', 'ssn', 'login']
    
    if any(keyword in packet.payload for keyword in sensitive_keywords):
        return {"is_sensitive": True}
    return {"is_sensitive": False}
```

**階段二：機器學習版本（Week 2-3）**
1. 收集訓練數據（可用模擬數據）
2. 訓練分類模型（例如：決策樹、隨機森林）
3. 提取流量特徵（8 個數字）
4. 輸出標準格式 JSON

### 要檢測的敏感資訊類型
- 🔑 登入憑證（帳號/密碼）
- 💳 支付資訊（信用卡、銀行帳號）
- 🆔 個人識別資訊（身份證、護照）
- 🏥 健康醫療資訊
- 📧 私人通訊內容

### 技術棧建議
- **流量解析**：Scapy / PyShark
- **特徵提取**：pandas / NumPy
- **分類模型**：Scikit-learn
- **正則表達式**：re 模組

**不會卡住的原因**：
- ✅ 其他人可以先用假標籤開發（隨機標記為敏感/不敏感）
- ✅ 初期用簡單規則（有"password"就是敏感），之後再升級為 ML 模型
- ✅ 提供 Mock API 讓其他項目測試

---

## 🔐 項目 2：加密檢測

**做什麼**：用加密方式檢測異常（處理敏感資料）

**比喻**：保險箱檢測，不打開箱子就知道裡面有沒有問題

**輸入**：加密後的流量特徵（8 個數字）  
**輸出**：異常分數（0-1，越高越可疑）

### 實作步驟

**階段一：明文模型訓練（Week 1）**
```python
from sklearn.linear_model import LogisticRegression

# 訓練明文模型
model = LogisticRegression()
model.fit(X_train, y_train)  # X_train: 8維特徵

# 測試推論
score = model.predict_proba(features)[0][1]  # 異常分數
```

**階段二：同態加密實作（Week 2-3）**
```python
import tenseal as ts

# 1. 建立加密環境
context = ts.context(ts.SCHEME_TYPE.CKKS, 8192)

# 2. 加密特徵
encrypted_features = ts.ckks_vector(context, features)

# 3. 加密狀態下計算（同態運算）
encrypted_score = homomorphic_inference(encrypted_features, model_weights)

# 4. 客戶端解密
score = encrypted_score.decrypt()
```

### 測試資料來源

#### 方案 A：UNSW-NB15 數據集（推薦）

**下載方式 1：Kaggle（推薦）**
```bash
# 需要先安裝 kaggle API
pip install kaggle

# 下載數據集
kaggle datasets download -d mrwellsdavid/unsw-nb15
unzip unsw-nb15.zip
```

**下載方式 2：官方網站**
- 訪問：https://www.unsw.adfa.edu.au/unsw-canberra-cyber/cybersecurity/ADFA-NB15-Datasets/
- 手動下載 CSV 檔案

**下載方式 3：GitHub 鏡像**
```bash
# 使用 GitHub 上的數據集副本
wget https://github.com/topics/unsw-nb15-dataset
# 或從其他可用鏡像源下載
```

**使用方式：**
```python
import pandas as pd

# 讀取下載的 CSV 檔案
df = pd.read_csv('UNSW-NB15_1.csv')

# 選取 8 個特徵
features = ['dur', 'spkts', 'dpkts', 'sbytes', 'dbytes', 'sload', 'dload', 'ct_srv_dst']
X = df[features].values
y = df['label'].values  # 0=正常, 1=異常
```

#### 方案 B：使用其他公開數據集

**KDD Cup 99**（最容易獲取）
```python
from sklearn.datasets import fetch_kddcup99

# 直接從 sklearn 下載
data = fetch_kddcup99(subset='SA', percent10=True)
X_raw, y = data.data, data.target

# 選取 8 個數值特徵
from sklearn.preprocessing import MinMaxScaler
X = X_raw[:, :8].astype(float)  # 取前 8 個特徵
scaler = MinMaxScaler()
X = scaler.fit_transform(X)
```

**NSL-KDD**（改良版）
```bash
# GitHub 下載
wget https://raw.githubusercontent.com/defcom17/NSL_KDD/master/KDDTrain%2B.txt
wget https://raw.githubusercontent.com/defcom17/NSL_KDD/master/KDDTest%2B.txt
```

#### 方案 C：自己生成測試數據
```python
from sklearn.datasets import make_classification

# 生成符合格式的數據
X, y = make_classification(
    n_samples=10000,
    n_features=8,
    n_classes=2,
    weights=[0.85, 0.15],  # 85%正常, 15%異常
    random_state=42
)
```

### 同態加密方案選擇

| 方案 | 優點 | 缺點 | 推薦度 |
|------|------|------|--------|
| **CKKS** | 支援浮點運算 | 精度損失 | ⭐⭐⭐⭐⭐ |
| BFV | 精確整數運算 | 不支援小數 | ⭐⭐⭐ |

### 技術棧
- **同態加密**：TenSEAL / Microsoft SEAL
- **機器學習**：Scikit-learn
- **數值計算**：NumPy

### 性能指標
- **明文推論延遲**：~5ms
- **加密推論延遲**：~200ms（論文結果）
- **準確度損失**：<2%

**不會卡住的原因**：
- ✅ 有公開數據集可以直接用（不用等其他項目）
- ✅ 可以先做明文版本訓練和測試
- ✅ 加密部分可以獨立開發，最後整合
- ✅ 提供 Mock 接口模擬加密延遲（200ms）

---

## 🚦 項目 3：系統核心

**做什麼**：整合一切，決定走哪條路

**比喻**：物流中心，看包裹標籤決定用快遞還是專車

### 核心路由邏輯

```python
class APPADCore:
    def __init__(self):
        self.classifier = PrivacyClassifier()      # 項目 1
        self.he_detector = HomomorphicDetector()   # 項目 2
        self.plain_detector = PlaintextDetector()  # 明文檢測
    
    def process_traffic(self, raw_traffic):
        # Step 1: 分類流量
        result = self.classifier.classify(raw_traffic)
        
        # Step 2: 路由決策
        if result["is_sensitive"]:
            # 敏感流量 → 走加密路徑
            score = self.he_detector.detect_encrypted(
                result["feature_vector"]
            )
            method = "encrypted"
        else:
            # 一般流量 → 走明文路徑（快速）
            score = self.plain_detector.detect(
                result["feature_vector"]
            )
            method = "plaintext"
        
        # Step 3: 返回結果
        return {
            "is_anomaly": score > 0.5,
            "score": score,
            "method": method
        }
```

### API 端點設計

```python
from fastapi import FastAPI

app = FastAPI()

@app.post("/detect")
async def detect_anomaly(traffic_data: dict):
    """異常檢測主接口"""
    result = appad_core.process_traffic(traffic_data)
    return result

@app.get("/health")
async def health_check():
    return {"status": "ok"}

@app.get("/metrics")
async def get_metrics():
    return {
        "total_requests": counter,
        "avg_latency_ms": avg_latency,
        "sensitive_ratio": sensitive_count / total
    }
```

### 實作步驟

**階段一：基礎框架（Week 1）**
1. 建立 REST API（FastAPI）
2. 實作明文異常檢測
3. 加入 Mock 接口（項目 1 和 2）

**階段二：部分整合（Week 2-3）**
1. 整合項目 1 的真實分類器
2. 測試路由邏輯
3. 加入性能監控

**階段三：完整整合（Week 4）**
1. 整合項目 2 的加密檢測
2. 完整端到端測試
3. 性能優化

### 技術棧
- **Web 框架**：FastAPI / Flask
- **異常檢測**：Scikit-learn
- **監控**：Prometheus + Grafana
- **容器化**：Docker

### 性能監控指標
- ⏱️ **延遲**：平均處理時間
- 🎯 **準確度**：異常檢測準確率
- 🔒 **隱私保護率**：敏感流量使用加密比例
- 📊 **吞吐量**：每秒處理請求數

**不會卡住的原因**：
- ✅ 可以先只做明文檢測部分
- ✅ 項目1和項目2還沒好，就用假的替代
- ✅ Web API 和路由邏輯可獨立開發
- ✅ 使用 Mock 數據進行完整測試

---

## 📝 統一格式（重點！）

三個項目之間傳遞的資料格式要一致：

### 項目 1 → 項目 3：分類結果

```json
{
  "traffic_id": "uuid-abc123",
  "timestamp": "2025-12-18T10:30:00Z",
  "source_ip": "192.168.1.100",
  "destination_ip": "203.0.113.50",
  "is_sensitive": true,
  "confidence": 0.92,
  "detected_patterns": ["login_credentials"],
  "feature_vector": [0.2, 0.8, 0.4, 0.9, 0.1, 0.7, 0.3, 0.5]
}
```

### 項目 3 → 項目 2：加密檢測請求

```json
{
  "traffic_id": "uuid-abc123",
  "feature_vector": [0.2, 0.8, 0.4, 0.9, 0.1, 0.7, 0.3, 0.5],
  "encryption_required": true
}
```

### 項目 2 → 項目 3：檢測結果

```json
{
  "traffic_id": "uuid-abc123",
  "anomaly_score": 0.87,
  "is_anomaly": true,
  "processing_time_ms": 245.6,
  "method": "encrypted"
}
```

### 最終系統輸出

```json
{
  "traffic_id": "uuid-abc123",
  "timestamp": "2025-12-18T10:30:00Z",
  "is_anomaly": true,
  "anomaly_score": 0.87,
  "is_sensitive": true,
  "detection_method": "encrypted",
  "latency_ms": 256.3,
  "privacy_protected": true
}
```

### 關鍵欄位說明

| 欄位 | 類型 | 說明 | 範例 |
|------|------|------|------|
| `traffic_id` | string | 唯一識別碼 | "uuid-abc123" |
| `is_sensitive` | boolean | 是否敏感 | true / false |
| `feature_vector` | array[8] | 特徵向量 | [0.2, 0.8, ...] |
| `anomaly_score` | float | 異常分數 | 0.87 (0-1) |
| `is_anomaly` | boolean | 是否異常 | true / false |

### 8 個特徵數字代表什麼

1. **連線持續時間**：流量持續多久
2. **來源封包數**：客戶端傳送封包數量
3. **目的地封包數**：伺服器回傳封包數量
4. **來源位元組數**：上傳數據大小
5. **目的地位元組數**：下載數據大小
6. **來源傳輸率**：上傳速度
7. **目的地傳輸率**：下載速度
8. **相同服務連線數**：同類型連線數量

**重點**：
- 🔢 特徵向量固定 **8 個數字**（0-1 之間）
- 🆔 所有請求都有唯一 `traffic_id` 可追蹤
- ⏰ 時間戳使用 ISO 8601 格式
- 📊 異常分數範圍：0（正常）到 1（異常）

---

## ⚙️ 實際怎麼並行開發？

### 第 1-2 週（各做各的）
- **項目 1**：用規則引擎（看到"password"就標記）
- **項目 2**：用公開數據集訓練模型
- **項目 3**：先做明文檢測，加密部分用假的

### 第 3-4 週（兩兩整合）
- 項目 1 + 項目 3：真實分類 + 明文檢測
- 項目 2：繼續優化加密性能

### 第 5-6 週（全部整合）
- 三個項目接在一起
- 完整測試

---

## 🎁 開發用工具包

每個項目都有**假數據生成器**，不用等別人：

### 項目 1 假數據（給項目 3 用）
```python
# 隨機生成標記好的流量
fake_data = {
    "是敏感資料": random.choice([True, False]),
    "特徵數字": [random.random() for _ in range(8)]
}
```

### 項目 2 假數據
```python
# 方式 1：使用 sklearn 內建數據集（最簡單）
from sklearn.datasets import fetch_kddcup99
data = fetch_kddcup99(subset='SA', percent10=True)
X = data.data[:, :8].astype(float)

# 方式 2：生成隨機數據
import numpy as np
fake_features = np.random.rand(1000, 8)  # 1000 筆，每筆 8 個數字
```

### 項目 3 假接口
```python
# 假的加密檢測（等項目 2 完成再替換）
def fake_encrypted_detect(features):
    time.sleep(0.2)  # 模擬加密的延遲
    return random.random()  # 假的異常分數
```

---

## ✅ 為什麼不會卡住？總結

| 問題 | 解決方案 |
|------|---------|
| 項目 1 還沒完成 | 用假標籤（隨機或固定） |
| 項目 2 還沒完成 | 用明文檢測 + 模擬延遲 |
| 沒有真實資料 | 用公開數據集或生成假資料 |
| 格式不一致 | 提前定義好格式（8 個數字） |
| 不知道對方進度 | 每個項目都有 Mock API |

---

## 🚀 快速開始

```bash
# 項目 1：隱私分類器
cd project1_classifier
python classifier.py --mode mock  # 用假數據測試

# 項目 2：加密檢測
cd project2_encryption
python download_dataset.py      # 下載 UNSW-NB15
python train_model.py           # 訓練模型

# 項目 3：系統核心
cd project3_core
python app.py --mock-mode       # 用假接口啟動
```

---

## 📚 需要更多細節？

如果需要看完整的代碼和技術細節，可以參考：
- API 接口文檔（在下方）
- 數據格式規範（在下方）
- 性能評估指標（見論文）

---

## 📖 附錄：技術細節

<details>
<summary><b>點擊展開：完整 API 規範</b></summary>

### 項目 1 API
```python
class PrivacyClassifier:
    def classify(self, raw_traffic: bytes) -> dict:
        """
        輸出格式：
        {
            "traffic_id": "uuid",
            "is_sensitive": true/false,
            "feature_vector": [8個數字]
        }
        """
        pass
```

### 項目 2 API
```python
class HomomorphicDetector:
    def detect_encrypted(self, features: list) -> float:
        """
        輸入：8 個數字
        輸出：異常分數 (0-1)
        """
        pass
```

### 項目 3 API
```python
class APPADCore:
    def process(self, traffic: bytes) -> dict:
        """
        完整流程：分類 → 路由 → 檢測
        輸出：{"is_anomaly": true/false, "score": 0.87}
        """
        pass
```

</details>

<details>
<summary><b>點擊展開：數據格式詳細說明</b></summary>

### 標準輸入格式
```json
{
  "traffic_id": "唯一編號",
  "is_sensitive": true,
  "feature_vector": [0.2, 0.8, 0.4, 0.9, 0.1, 0.7, 0.3, 0.5]
}
```

### 8 個特徵數字代表什麼
1. 連線持續時間
2. 來源封包數
3. 目的地封包數
4. 來源位元組數
5. 目的地位元組數
6. 來源傳輸率
7. 目的地傳輸率
8. 相同服務連線數

</details>

<details>
<summary><b>點擊展開：性能指標</b></summary>

根據論文結果：

| 模型 | 準確度 | 延遲 | 隱私保護 |
|------|--------|------|----------|
| APPAD（我們的） | ⭐⭐⭐⭐ | ⭐⭐⭐⭐ | ⭐⭐⭐⭐ |
| 全部加密 | ⭐⭐⭐ | ⭐⭐ | ⭐⭐⭐⭐⭐ |
| 全部明文 | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐ | ⭐ |

</details>

---

## 🤝 聯絡與支援

- 📧 Email: cseyrj@gmail.com
- 📄 論文：2025_mobisec.pdf
- 🔗 會議：MobiSec 2025

---

**最後更新**: 2025/12/18
