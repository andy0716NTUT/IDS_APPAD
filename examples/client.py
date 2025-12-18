"""
範例客戶端
示範如何調用 APPAD API
"""

import requests
import json
import time


class APPADClient:
    """APPAD API 客戶端"""

    def __init__(self, base_url: str = "http://localhost:8000"):
        self.base_url = base_url

    def detect(self, payload: str, source_ip: str = "192.168.1.100",
               destination_ip: str = "203.0.113.50") -> dict:
        """
        檢測流量異常

        參數:
            payload: 流量內容
            source_ip: 來源IP
            destination_ip: 目的地IP

        返回:
            檢測結果
        """
        url = f"{self.base_url}/detect"

        data = {
            "payload": payload,
            "source_ip": source_ip,
            "destination_ip": destination_ip
        }

        response = requests.post(url, json=data)
        response.raise_for_status()

        return response.json()

    def test_mock(self) -> dict:
        """使用Mock數據測試"""
        url = f"{self.base_url}/test/mock"
        response = requests.post(url)
        response.raise_for_status()
        return response.json()

    def get_metrics(self) -> dict:
        """獲取系統統計"""
        url = f"{self.base_url}/metrics"
        response = requests.get(url)
        response.raise_for_status()
        return response.json()

    def health_check(self) -> dict:
        """健康檢查"""
        url = f"{self.base_url}/health"
        response = requests.get(url)
        response.raise_for_status()
        return response.json()


def print_result(result: dict, title: str = "檢測結果"):
    """美化輸出結果"""
    print("\n" + "=" * 60)
    print(title)
    print("=" * 60)

    # 基本資訊
    print(f"流量ID: {result.get('traffic_id', 'N/A')}")
    print(f"時間戳: {result.get('timestamp', 'N/A')}")

    # 檢測結果
    is_anomaly = result.get('is_anomaly', False)
    anomaly_icon = "🚨" if is_anomaly else "✓"
    print(f"{anomaly_icon} 是否異常: {is_anomaly}")
    print(f"   異常分數: {result.get('anomaly_score', 0):.4f}")

    # 隱私保護
    is_sensitive = result.get('is_sensitive', False)
    sensitive_icon = "🔒" if is_sensitive else "🔓"
    print(f"{sensitive_icon} 是否敏感: {is_sensitive}")
    print(f"   檢測方法: {result.get('detection_method', 'N/A')}")
    print(f"   隱私保護: {result.get('privacy_protected', False)}")

    # 性能
    print(f"⏱️  處理延遲: {result.get('latency_ms', 0):.2f} ms")

    print("=" * 60)


def main():
    """示範各種使用場景"""
    print("\n" + "=" * 60)
    print("APPAD API 客戶端示範")
    print("=" * 60)

    # 初始化客戶端
    client = APPADClient(base_url="http://localhost:8000")

    # 1. 健康檢查
    print("\n[1] 健康檢查")
    try:
        health = client.health_check()
        print(f"✓ 系統狀態: {health['status']}")
    except Exception as e:
        print(f"✗ 連接失敗: {e}")
        print("\n請確保服務已啟動:")
        print("  python run.py")
        return

    # 2. 測試敏感流量
    print("\n[2] 測試敏感流量 (包含密碼)")
    payload_sensitive = 'POST /login HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{"username":"admin","password":"secret123"}'

    try:
        result = client.detect(payload_sensitive)
        print_result(result, "敏感流量檢測結果")
    except Exception as e:
        print(f"✗ 檢測失敗: {e}")

    # 3. 測試正常流量
    print("\n[3] 測試正常流量")
    payload_normal = 'GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n'

    try:
        result = client.detect(payload_normal)
        print_result(result, "正常流量檢測結果")
    except Exception as e:
        print(f"✗ 檢測失敗: {e}")

    # 4. 測試信用卡資訊
    print("\n[4] 測試信用卡資訊")
    payload_payment = '{"card_number":"4532-1234-5678-9010","cvv":"123","holder":"John Doe"}'

    try:
        result = client.detect(payload_payment)
        print_result(result, "信用卡資訊檢測結果")
    except Exception as e:
        print(f"✗ 檢測失敗: {e}")

    # 5. 批次測試
    print("\n[5] 批次測試 (10筆Mock數據)")
    print("-" * 60)

    for i in range(10):
        try:
            result = client.test_mock()
            status = "🚨 異常" if result['is_anomaly'] else "✓ 正常"
            sensitive = "🔒 敏感" if result['is_sensitive'] else "🔓 一般"
            print(f"[{i+1:2d}] {status} | {sensitive} | "
                  f"分數: {result['anomaly_score']:.3f} | "
                  f"延遲: {result['latency_ms']:6.2f} ms")
            time.sleep(0.1)  # 避免過快
        except Exception as e:
            print(f"[{i+1:2d}] ✗ 失敗: {e}")

    # 6. 查看統計
    print("\n[6] 系統統計")
    print("-" * 60)

    try:
        metrics = client.get_metrics()
        print(f"總請求數: {metrics['total_requests']}")
        print(f"敏感流量: {metrics['sensitive_count']} ({metrics['sensitive_ratio']*100:.1f}%)")
        print(f"檢測到異常: {metrics['anomaly_count']} ({metrics['anomaly_ratio']*100:.1f}%)")
        print(f"平均延遲: {metrics['avg_latency_ms']:.2f} ms")
    except Exception as e:
        print(f"✗ 獲取統計失敗: {e}")

    print("\n" + "=" * 60)
    print("示範完成!")
    print("=" * 60)
    print("\n提示:")
    print("- 訪問 http://localhost:8000/docs 查看完整API文檔")
    print("- 使用 --mock-mode 快速測試無需訓練模型")
    print("=" * 60)


if __name__ == "__main__":
    main()
