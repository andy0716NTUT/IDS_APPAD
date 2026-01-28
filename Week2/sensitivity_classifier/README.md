# Sensitivity Classifier（敏感性分類）

此資料夾提供一個規則式的敏感性分類器，用來評估登入/驗證事件是否具高風險（敏感）。

## 功能概述
- 針對單筆登入紀錄進行風險計分
- 依照門檻輸出敏感等級（LOW / MEDIUM / HIGH）
- 回傳觸發的規則原因（reasons）
- 可批次掃描資料集並輸出統計摘要

## 檔案說明
- `classifier.py`：核心分類器 `SensitivityClassifier`
- `rules.py`：規則權重與門檻設定
- `run_dataset.py`：讀取 CSV 資料集並批次評估
- `sample_data.py`：範例資料格式（單筆事件）

## 規則與門檻
- 外部 IP（非內網 192.168.x.x / 10.x.x.x）會增加風險
- 失敗次數越多風險越高
- 登入失敗（`login_status=fail`）會增加風險
- 可疑地點（例如 `Mars`）會增加風險
- 工作階段過長會增加風險
- 行為分數越低風險越高

門檻設定在 `rules.py`：
- `HIGH`：0.7
- `MEDIUM`：0.4

## 使用方式

### 1. 單筆分類

```python
from classifier import SensitivityClassifier

record = {
    "ip_address": "203.0.113.5",
    "login_status": "fail",
    "location": "Mars",
    "session_duration": 900,
    "failed_attempts": 3,
    "behavioral_score": 35
}

clf = SensitivityClassifier()
result = clf.classify(record)
print(result)
```

回傳格式範例：

```python
{
    "is_sensitive": True,
    "risk_score": 0.95,
    "sensitivity_level": "HIGH",
    "encryption_required": True,
    "reasons": [
        "external_ip",
        "some_failed_attempts",
        "failed_login",
        "suspicious_location",
        "long_session",
        "abnormal_behavior"
    ]
}
```

### 2. 批次掃描資料集

`run_dataset.py` 會讀取專案的 `dataset/synthetic_web_auth_logs.csv`，逐筆輸出結果並在最後列出統計摘要。

```bash
python run_dataset.py
```

> 需要先安裝 pandas：
> `pip install pandas`

## 輸入欄位
分類器使用的欄位如下（`rules.py` 的 `MODEL_FEATURES`）：
- `ip_address`
- `login_status`
- `location`
- `session_duration`
- `failed_attempts`
- `behavioral_score`

`run_dataset.py` 會把 CSV 欄位映射為內部欄位：
- `User ID` → `user_id`
- `Login Status` → `login_status`
- `IP Address` → `ip_address`
- `Location` → `location`
- `Session Duration` → `session_duration`
- `Failed Attempts` → `failed_attempts`
- `Behavioral Score` → `behavioral_score`

## 可調整項目
如需調整規則權重或門檻，請修改 `rules.py`：
- `HIGH_RISK_RULES`
- `THRESHOLDS`

## 容易導致 HIGH 的特徵（清單）
以下是會推高分數、較容易組合達到 HIGH 的特徵與條件：
- 外部 IP（`external_ip`）
- 失敗嘗試很多（`failed_attempts >= 5` → `many_failed_attempts`）
- 失敗嘗試偏多（`failed_attempts >= 3` → `some_failed_attempts`）
- 登入失敗（`login_status` 為 `fail/failed`）
- 可疑地點（`location` 在 `SUSPICIOUS_LOCATIONS`，預設含 `Mars`）
- 工作階段過長（`session_duration >= 600`）
- 行為分數過低（`behavioral_score < 40`）
- 行為分數偏低（`behavioral_score < 60`）

若要降低 HIGH 的比例，可以調低上述規則權重或提高門檻（`THRESHOLDS`）。

---

如需新增規則或擴充欄位，請同步更新 `classifier.py` 與 `rules.py`。