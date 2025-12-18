# 項目 3: 系統核心

整合隱私分類器和加密檢測,提供REST API

## 功能

- REST API 接口
- 自動路由決策(敏感流量→加密檢測,一般流量→明文檢測)
- 性能監控和統計
- Mock模式支援(無需訓練模型即可測試)

## 安裝

```bash
pip install -r requirements.txt
```

## 使用方式

### 啟動服務(正常模式)

```bash
python app.py
```

### 啟動服務(Mock模式)

```bash
python app.py --mock-mode
```

### 自定義主機和端口

```bash
python app.py --host 0.0.0.0 --port 8080
```

## API 端點

### 1. 異常檢測

```bash
POST http://localhost:8000/detect

{
  "payload": "POST /login HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"username\":\"admin\",\"password\":\"secret\"}",
  "source_ip": "192.168.1.100",
  "destination_ip": "203.0.113.50"
}
```

**回應:**
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

### 2. 健康檢查

```bash
GET http://localhost:8000/health
```

### 3. 系統統計

```bash
GET http://localhost:8000/metrics
```

**回應:**
```json
{
  "total_requests": 1000,
  "sensitive_count": 300,
  "anomaly_count": 150,
  "avg_latency_ms": 125.5,
  "sensitive_ratio": 0.3,
  "anomaly_ratio": 0.15
}
```

### 4. Mock測試

```bash
POST http://localhost:8000/test/mock
```

## 互動式API文檔

啟動服務後訪問:
- Swagger UI: http://localhost:8000/docs
- ReDoc: http://localhost:8000/redoc

## 路由決策邏輯

```
流量輸入
   ↓
隱私分類器 (項目1)
   ↓
是否敏感?
   ↓
┌─────┴─────┐
是         否
↓           ↓
加密檢測   明文檢測
(項目2)    (項目2)
~200ms     ~5ms
↓           ↓
└─────┬─────┘
      ↓
   返回結果
```

## 測試範例

### 使用 curl

```bash
# 測試敏感流量
curl -X POST http://localhost:8000/detect \
  -H "Content-Type: application/json" \
  -d '{
    "payload": "username=admin&password=secret",
    "source_ip": "192.168.1.100",
    "destination_ip": "203.0.113.50"
  }'

# 查看統計
curl http://localhost:8000/metrics
```

### 使用 Python

```python
import requests

# 檢測異常
response = requests.post('http://localhost:8000/detect', json={
    'payload': 'POST /login HTTP/1.1\r\n{"password":"secret"}',
    'source_ip': '192.168.1.100',
    'destination_ip': '203.0.113.50'
})

print(response.json())
```
