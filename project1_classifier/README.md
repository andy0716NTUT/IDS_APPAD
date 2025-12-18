# 項目 1: 隱私分類器

判斷網路流量是否包含敏感資訊

## 功能

- 基於規則引擎檢測敏感關鍵字
- 支援正則表達式模式匹配
- 提取8個流量特徵向量
- 輸出標準化JSON格式

## 安裝

```bash
pip install -r requirements.txt
```

## 使用方式

```bash
python classifier.py
```

## API

```python
from classifier import PrivacyClassifier, generate_mock_traffic

# 建立分類器
classifier = PrivacyClassifier()

# 分類流量
traffic_data = {
    'payload': b'...',
    'source_ip': '192.168.1.100',
    'destination_ip': '203.0.113.50'
}
result = classifier.classify(traffic_data)

# 生成測試數據
mock_traffic = generate_mock_traffic(is_sensitive=True)
```

## 輸出格式

```json
{
  "traffic_id": "uuid",
  "timestamp": "2025-12-18T10:30:00Z",
  "source_ip": "192.168.1.100",
  "destination_ip": "203.0.113.50",
  "is_sensitive": true,
  "confidence": 0.92,
  "detected_patterns": ["login_credentials"],
  "feature_vector": [0.2, 0.8, 0.4, 0.9, 0.1, 0.7, 0.3, 0.5]
}
```
