# 項目 2: 加密檢測系統

使用加密方式檢測異常(處理敏感資料)

## 功能

- 明文異常檢測模型訓練
- 支援 Logistic Regression 和 Random Forest
- 模擬同態加密檢測(含延遲)
- 支援真實數據集 (KDD Cup 99) 和合成數據

## 安裝

```bash
pip install -r requirements.txt
```

## 使用方式

### 訓練和測試

```bash
python detector.py
```

### API 使用

```python
from detector import PlaintextDetector, HomomorphicDetector, generate_synthetic_data

# 準備數據
X, y = generate_synthetic_data(n_samples=10000)

# 訓練明文檢測器
detector = PlaintextDetector()
detector.train(X, y, model_type='logistic')

# 明文檢測 (快速)
result = detector.detect([0.2, 0.8, 0.4, 0.9, 0.1, 0.7, 0.3, 0.5])
print(result)  # ~5ms

# 加密檢測 (安全但較慢)
he_detector = HomomorphicDetector(plaintext_model=detector)
result = he_detector.detect_encrypted([0.2, 0.8, 0.4, 0.9, 0.1, 0.7, 0.3, 0.5])
print(result)  # ~200ms
```

## 輸出格式

```json
{
  "anomaly_score": 0.87,
  "is_anomaly": true,
  "processing_time_ms": 5.2,
  "method": "plaintext"
}
```

## 性能指標

| 方法 | 延遲 | 隱私保護 |
|------|------|----------|
| 明文檢測 | ~5ms | 無 |
| 加密檢測 | ~200ms | 完整 |

## 未來改進

- [ ] 整合 TenSEAL 實現真實同態加密
- [ ] 支援更多數據集 (UNSW-NB15, NSL-KDD)
- [ ] 優化加密運算性能
