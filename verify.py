"""
快速驗證腳本
確認三個項目都能正常運作
"""

import sys
import os

print("=" * 60)
print("IDS_APPAD 系統驗證")
print("=" * 60)

# 測試項目1
print("\n[1/3] 測試項目1: 隱私分類器...")
try:
    from project1_classifier.classifier import PrivacyClassifier

    classifier = PrivacyClassifier()
    test_data = {
        'payload': b'password=secret',
        'source_ip': '192.168.1.100',
        'destination_ip': '203.0.113.50'
    }
    result = classifier.classify(test_data)

    assert 'is_sensitive' in result
    assert 'feature_vector' in result
    assert len(result['feature_vector']) == 8

    print(f"   OK - 敏感流量檢測: {result['is_sensitive']}")
    print(f"   OK - 特徵向量長度: {len(result['feature_vector'])}")

except Exception as e:
    print(f"   FAIL - {str(e)}")
    sys.exit(1)

# 測試項目2
print("\n[2/3] 測試項目2: 加密檢測...")
try:
    from project2_encryption.detector import PlaintextDetector, generate_synthetic_data

    # 生成測試數據並訓練
    X, y = generate_synthetic_data(n_samples=1000)
    detector = PlaintextDetector()
    detector.train(X[:800], y[:800], model_type='logistic')

    # 測試檢測
    test_feature = X[900]
    result = detector.detect(test_feature)

    assert 'anomaly_score' in result
    assert 'is_anomaly' in result
    assert 0 <= result['anomaly_score'] <= 1

    print(f"   OK - 模型訓練完成")
    print(f"   OK - 異常分數: {result['anomaly_score']:.4f}")
    print(f"   OK - 處理延遲: {result['processing_time_ms']:.2f} ms")

except Exception as e:
    print(f"   FAIL - {str(e)}")
    sys.exit(1)

# 測試項目3
print("\n[3/3] 測試項目3: 系統核心...")
try:
    from project3_core.app import APPADCore

    core = APPADCore(mock_mode=True)  # 使用Mock模式快速測試

    test_traffic = {
        'payload': b'username=admin&password=secret',
        'source_ip': '192.168.1.100',
        'destination_ip': '203.0.113.50'
    }

    result = core.process_traffic(test_traffic)

    assert 'is_anomaly' in result
    assert 'is_sensitive' in result
    assert 'detection_method' in result

    print(f"   OK - 路由決策正常")
    print(f"   OK - 敏感流量: {result['is_sensitive']}")
    print(f"   OK - 檢測方法: {result['detection_method']}")
    print(f"   OK - 總延遲: {result['latency_ms']:.2f} ms")

except Exception as e:
    print(f"   FAIL - {str(e)}")
    import traceback
    traceback.print_exc()
    sys.exit(1)

# 檢查文件結構
print("\n[文件結構檢查]")
required_files = [
    'README.md',
    '使用說明.md',
    'requirements.txt',
    'run.py',
    'project1_classifier/classifier.py',
    'project2_encryption/detector.py',
    'project3_core/app.py',
    'tests/test_integration.py',
    'examples/client.py'
]

all_exist = True
for file in required_files:
    exists = os.path.exists(file)
    status = "OK" if exists else "MISSING"
    if not exists:
        all_exist = False
    print(f"   [{status}] {file}")

if not all_exist:
    print("\n   WARNING - 某些檔案缺失")

# 總結
print("\n" + "=" * 60)
print("驗證結果")
print("=" * 60)
print("[OK] 項目1: 隱私分類器 - 正常")
print("[OK] 項目2: 加密檢測 - 正常")
print("[OK] 項目3: 系統核心 - 正常")
print("\n所有核心功能測試通過!")
print("=" * 60)

print("\n下一步:")
print("1. 啟動系統: python run.py")
print("2. 查看文檔: 使用說明.md")
print("3. 執行完整測試: python tests/test_integration.py")
print("4. API文檔: http://localhost:8000/docs (啟動後訪問)")
print("=" * 60)
