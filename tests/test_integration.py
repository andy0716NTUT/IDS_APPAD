"""
端到端整合測試
測試三個項目的整合運作
"""

import sys
import os
import time
import numpy as np

# 添加專案路徑
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from project1_classifier.classifier import PrivacyClassifier, generate_mock_traffic
from project2_encryption.detector import PlaintextDetector, HomomorphicDetector, generate_synthetic_data
from project3_core.app import APPADCore


def test_project1_classifier():
    """測試項目1: 隱私分類器"""
    print("\n" + "=" * 60)
    print("測試項目 1: 隱私分類器")
    print("=" * 60)

    classifier = PrivacyClassifier()

    # 測試敏感流量
    sensitive_traffic = {
        'payload': b'POST /login HTTP/1.1\r\n{"username":"admin","password":"secret123"}',
        'source_ip': '192.168.1.100',
        'destination_ip': '203.0.113.50'
    }

    result = classifier.classify(sensitive_traffic)

    assert result['is_sensitive'] == True, "應該檢測為敏感流量"
    assert len(result['feature_vector']) == 8, "特徵向量應為8維"
    assert len(result['detected_patterns']) > 0, "應該檢測到敏感模式"

    print(f"✓ 檢測到敏感流量")
    print(f"  信心度: {result['confidence']:.2f}")
    print(f"  檢測到的模式: {result['detected_patterns']}")
    print(f"  特徵向量: {[f'{x:.2f}' for x in result['feature_vector']]}")

    # 測試正常流量
    normal_traffic = {
        'payload': b'GET /index.html HTTP/1.1\r\nHost: example.com',
        'source_ip': '192.168.1.101',
        'destination_ip': '203.0.113.51'
    }

    result = classifier.classify(normal_traffic)

    assert result['is_sensitive'] == False, "應該檢測為正常流量"

    print(f"✓ 檢測到正常流量")
    print(f"  敏感: {result['is_sensitive']}")

    return True


def test_project2_detector():
    """測試項目2: 加密檢測"""
    print("\n" + "=" * 60)
    print("測試項目 2: 加密檢測")
    print("=" * 60)

    # 生成測試數據
    X, y = generate_synthetic_data(n_samples=1000)
    X_train, X_test = X[:800], X[800:]
    y_train, y_test = y[:800], y[800:]

    # 訓練明文檢測器
    detector = PlaintextDetector()
    detector.train(X_train, y_train, model_type='logistic')

    # 測試明文檢測
    test_feature = X_test[0]
    result = detector.detect(test_feature)

    assert 'anomaly_score' in result, "應該包含異常分數"
    assert 0 <= result['anomaly_score'] <= 1, "異常分數應在0-1之間"
    assert result['processing_time_ms'] < 50, "明文檢測延遲應小於50ms"

    print(f"✓ 明文檢測正常")
    print(f"  異常分數: {result['anomaly_score']:.4f}")
    print(f"  延遲: {result['processing_time_ms']:.2f} ms")

    # 測試加密檢測
    he_detector = HomomorphicDetector(plaintext_model=detector)
    result_encrypted = he_detector.detect_encrypted(test_feature)

    assert result_encrypted['method'] == 'encrypted', "應該使用加密方法"
    assert result_encrypted['processing_time_ms'] > 100, "加密檢測延遲應大於100ms"

    print(f"✓ 加密檢測正常")
    print(f"  異常分數: {result_encrypted['anomaly_score']:.4f}")
    print(f"  延遲: {result_encrypted['processing_time_ms']:.2f} ms")

    return True


def test_project3_core():
    """測試項目3: 系統核心"""
    print("\n" + "=" * 60)
    print("測試項目 3: 系統核心")
    print("=" * 60)

    # 初始化系統核心
    core = APPADCore(mock_mode=False)

    # 測試敏感流量 (應該使用加密檢測)
    sensitive_traffic = {
        'payload': b'{"username":"admin","password":"secret"}',
        'source_ip': '192.168.1.100',
        'destination_ip': '203.0.113.50'
    }

    result = core.process_traffic(sensitive_traffic)

    assert result['is_sensitive'] == True, "應該檢測為敏感流量"
    assert result['detection_method'] == 'encrypted', "應該使用加密檢測"
    assert result['privacy_protected'] == True, "應該有隱私保護"

    print(f"✓ 敏感流量處理正常")
    print(f"  檢測方法: {result['detection_method']}")
    print(f"  隱私保護: {result['privacy_protected']}")
    print(f"  異常分數: {result['anomaly_score']:.4f}")
    print(f"  總延遲: {result['latency_ms']:.2f} ms")

    # 測試正常流量 (應該使用明文檢測)
    normal_traffic = {
        'payload': b'GET /index.html HTTP/1.1',
        'source_ip': '192.168.1.101',
        'destination_ip': '203.0.113.51'
    }

    result = core.process_traffic(normal_traffic)

    assert result['is_sensitive'] == False, "應該檢測為正常流量"
    assert result['detection_method'] == 'plaintext', "應該使用明文檢測"
    assert result['privacy_protected'] == False, "不需要隱私保護"

    print(f"✓ 正常流量處理正常")
    print(f"  檢測方法: {result['detection_method']}")
    print(f"  隱私保護: {result['privacy_protected']}")
    print(f"  異常分數: {result['anomaly_score']:.4f}")
    print(f"  總延遲: {result['latency_ms']:.2f} ms")

    return True


def test_performance():
    """性能測試"""
    print("\n" + "=" * 60)
    print("性能測試")
    print("=" * 60)

    core = APPADCore(mock_mode=False)

    # 測試100筆流量
    n_tests = 100
    latencies_sensitive = []
    latencies_normal = []

    print(f"處理 {n_tests} 筆流量...")

    for i in range(n_tests):
        # 隨機生成敏感或正常流量
        is_sensitive = np.random.choice([True, False], p=[0.3, 0.7])
        mock_traffic = generate_mock_traffic(is_sensitive=is_sensitive)

        result = core.process_traffic(mock_traffic)

        if result['is_sensitive']:
            latencies_sensitive.append(result['latency_ms'])
        else:
            latencies_normal.append(result['latency_ms'])

    # 統計結果
    metrics = core.get_metrics()

    print(f"\n統計結果:")
    print(f"  總請求數: {metrics['total_requests']}")
    print(f"  敏感流量: {metrics['sensitive_count']} ({metrics['sensitive_ratio']*100:.1f}%)")
    print(f"  檢測到異常: {metrics['anomaly_count']} ({metrics['anomaly_ratio']*100:.1f}%)")
    print(f"  平均延遲: {metrics['avg_latency_ms']:.2f} ms")

    if latencies_sensitive:
        print(f"\n敏感流量延遲:")
        print(f"  平均: {np.mean(latencies_sensitive):.2f} ms")
        print(f"  中位數: {np.median(latencies_sensitive):.2f} ms")
        print(f"  最大: {np.max(latencies_sensitive):.2f} ms")

    if latencies_normal:
        print(f"\n正常流量延遲:")
        print(f"  平均: {np.mean(latencies_normal):.2f} ms")
        print(f"  中位數: {np.median(latencies_normal):.2f} ms")
        print(f"  最大: {np.max(latencies_normal):.2f} ms")

    # 驗證性能要求
    assert metrics['avg_latency_ms'] < 500, "平均延遲應小於500ms"
    print(f"\n✓ 性能測試通過")

    return True


def main():
    """執行所有測試"""
    print("\n" + "=" * 60)
    print("IDS_APPAD 整合測試")
    print("=" * 60)

    tests = [
        ("項目1: 隱私分類器", test_project1_classifier),
        ("項目2: 加密檢測", test_project2_detector),
        ("項目3: 系統核心", test_project3_core),
        ("性能測試", test_performance)
    ]

    passed = 0
    failed = 0

    for test_name, test_func in tests:
        try:
            result = test_func()
            if result:
                passed += 1
                print(f"\n✓ {test_name} 通過")
        except Exception as e:
            failed += 1
            print(f"\n✗ {test_name} 失敗: {str(e)}")

    print("\n" + "=" * 60)
    print("測試結果")
    print("=" * 60)
    print(f"通過: {passed}/{len(tests)}")
    print(f"失敗: {failed}/{len(tests)}")

    if failed == 0:
        print("\n✓ 所有測試通過!")
    else:
        print(f"\n✗ {failed} 個測試失敗")

    print("=" * 60)


if __name__ == "__main__":
    main()
