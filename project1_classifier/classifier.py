"""
項目 1: 隱私分類器
判斷網路流量是否包含敏感資料

階段一: 規則引擎版本
"""

import re
import uuid
import json
import numpy as np
from datetime import datetime
from typing import Dict, List, Union


class PrivacyClassifier:
    """隱私分類器 - 判斷流量是否包含敏感資訊"""

    def __init__(self):
        # 敏感資訊關鍵字
        self.sensitive_keywords = {
            'login_credentials': [
                b'password', b'passwd', b'pwd', b'login', b'username',
                b'user', b'auth', b'credential', b'token'
            ],
            'payment_info': [
                b'credit_card', b'creditcard', b'card_number', b'cvv', b'cvc',
                b'bank_account', b'payment', b'billing'
            ],
            'personal_id': [
                b'ssn', b'social_security', b'passport', b'id_card',
                b'identity', b'national_id', b'driver_license'
            ],
            'health_info': [
                b'medical', b'health', b'patient', b'diagnosis',
                b'prescription', b'hospital'
            ],
            'private_communication': [
                b'private', b'confidential', b'secret', b'personal_message'
            ]
        }

        # 敏感資訊的正則表達式模式
        self.sensitive_patterns = {
            'email': rb'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
            'credit_card': rb'\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b',
            'ssn': rb'\b\d{3}-\d{2}-\d{4}\b',
            'phone': rb'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b'
        }

    def classify(self, raw_traffic: Union[bytes, dict]) -> Dict:
        """
        分類流量是否包含敏感資訊

        參數:
            raw_traffic: 原始流量數據(bytes)或模擬的流量字典

        返回:
            {
                "traffic_id": "uuid",
                "timestamp": "ISO 8601 時間",
                "source_ip": "來源IP",
                "destination_ip": "目的地IP",
                "is_sensitive": True/False,
                "confidence": 0.0-1.0,
                "detected_patterns": ["類型1", "類型2"],
                "feature_vector": [8個數字]
            }
        """
        traffic_id = str(uuid.uuid4())
        timestamp = datetime.utcnow().isoformat() + 'Z'

        # 處理不同格式的輸入
        if isinstance(raw_traffic, dict):
            payload = raw_traffic.get('payload', b'')
            if isinstance(payload, str):
                payload = payload.encode('utf-8')
            source_ip = raw_traffic.get('source_ip', '0.0.0.0')
            destination_ip = raw_traffic.get('destination_ip', '0.0.0.0')
        else:
            payload = raw_traffic if isinstance(raw_traffic, bytes) else str(raw_traffic).encode('utf-8')
            source_ip = '0.0.0.0'
            destination_ip = '0.0.0.0'

        # 檢測敏感資訊
        detected_patterns = []
        keyword_matches = 0

        # 檢查關鍵字
        for category, keywords in self.sensitive_keywords.items():
            for keyword in keywords:
                if keyword.lower() in payload.lower():
                    if category not in detected_patterns:
                        detected_patterns.append(category)
                    keyword_matches += 1

        # 檢查正則表達式模式
        for pattern_name, pattern in self.sensitive_patterns.items():
            if re.search(pattern, payload, re.IGNORECASE):
                if pattern_name not in detected_patterns:
                    detected_patterns.append(pattern_name)

        # 判斷是否敏感
        is_sensitive = len(detected_patterns) > 0
        confidence = min(0.5 + (len(detected_patterns) * 0.15), 1.0)

        # 提取流量特徵(8個數字)
        feature_vector = self._extract_features(payload, is_sensitive)

        return {
            "traffic_id": traffic_id,
            "timestamp": timestamp,
            "source_ip": source_ip,
            "destination_ip": destination_ip,
            "is_sensitive": is_sensitive,
            "confidence": confidence,
            "detected_patterns": detected_patterns,
            "feature_vector": feature_vector
        }

    def _extract_features(self, payload: bytes, is_sensitive: bool) -> List[float]:
        """
        提取8個流量特徵

        特徵定義:
        1. 連線持續時間 (模擬)
        2. 來源封包數 (基於payload長度)
        3. 目的地封包數 (模擬)
        4. 來源位元組數 (payload大小)
        5. 目的地位元組數 (模擬)
        6. 來源傳輸率 (基於封包數)
        7. 目的地傳輸率 (模擬)
        8. 相同服務連線數 (模擬)
        """
        payload_size = len(payload)

        # 基於實際數據計算特徵
        features = [
            # 1. 連線持續時間 (歸一化到0-1)
            min(payload_size / 10000, 1.0),

            # 2. 來源封包數 (基於payload大小估算)
            min(payload_size / 1500, 1.0),  # 1500 是典型MTU

            # 3. 目的地封包數 (假設回應較少)
            min(payload_size / 3000, 1.0),

            # 4. 來源位元組數
            min(payload_size / 10000, 1.0),

            # 5. 目的地位元組數 (假設回應較少)
            min(payload_size / 20000, 1.0),

            # 6. 來源傳輸率 (基於封包密度)
            min(payload_size / 5000, 1.0),

            # 7. 目的地傳輸率
            min(payload_size / 8000, 1.0),

            # 8. 相同服務連線數 (如果是敏感流量,假設連線較少)
            0.3 if is_sensitive else 0.7
        ]

        # 確保所有特徵在0-1範圍內
        features = [max(0.0, min(1.0, f)) for f in features]

        # 四捨五入到小數點後4位
        features = [round(f, 4) for f in features]

        return features


def generate_mock_traffic(is_sensitive: bool = None) -> dict:
    """
    生成模擬流量數據 - 供其他項目測試使用

    參數:
        is_sensitive: 指定是否生成敏感流量, None則隨機
    """
    if is_sensitive is None:
        is_sensitive = np.random.choice([True, False], p=[0.3, 0.7])

    # 生成模擬payload
    if is_sensitive:
        sensitive_samples = [
            b'POST /login HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{"username":"user123","password":"secret123"}',
            b'{"credit_card":"4532-1234-5678-9010","cvv":"123","expiry":"12/25"}',
            b'GET /api/user/profile?ssn=123-45-6789 HTTP/1.1',
            b'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...',
        ]
        payload = np.random.choice(sensitive_samples)
    else:
        normal_samples = [
            b'GET /index.html HTTP/1.1\r\nHost: example.com',
            b'POST /api/data HTTP/1.1\r\n\r\n{"temperature":25.5,"humidity":60}',
            b'{"message":"Hello World","timestamp":1234567890}',
            b'GET /static/image.jpg HTTP/1.1',
        ]
        payload = np.random.choice(normal_samples)

    return {
        'payload': payload,
        'source_ip': f'192.168.1.{np.random.randint(1, 255)}',
        'destination_ip': f'203.0.113.{np.random.randint(1, 255)}'
    }


def main():
    """測試分類器"""
    print("=" * 60)
    print("項目 1: 隱私分類器測試")
    print("=" * 60)

    classifier = PrivacyClassifier()

    # 測試案例1: 敏感流量(包含登入資訊)
    print("\n測試 1: 敏感流量(登入資訊)")
    print("-" * 60)
    sensitive_traffic = {
        'payload': b'POST /login HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{"username":"admin","password":"secret123"}',
        'source_ip': '192.168.1.100',
        'destination_ip': '203.0.113.50'
    }
    result = classifier.classify(sensitive_traffic)
    print(json.dumps(result, indent=2, ensure_ascii=False))

    # 測試案例2: 正常流量
    print("\n\n測試 2: 正常流量")
    print("-" * 60)
    normal_traffic = {
        'payload': b'GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n',
        'source_ip': '192.168.1.101',
        'destination_ip': '203.0.113.51'
    }
    result = classifier.classify(normal_traffic)
    print(json.dumps(result, indent=2, ensure_ascii=False))

    # 測試案例3: 包含信用卡資訊
    print("\n\n測試 3: 敏感流量(信用卡資訊)")
    print("-" * 60)
    payment_traffic = {
        'payload': b'{"card_number":"4532-1234-5678-9010","cvv":"123","holder":"John Doe"}',
        'source_ip': '192.168.1.102',
        'destination_ip': '203.0.113.52'
    }
    result = classifier.classify(payment_traffic)
    print(json.dumps(result, indent=2, ensure_ascii=False))

    # 測試案例4: 使用Mock數據
    print("\n\n測試 4: 隨機生成的Mock數據(10筆)")
    print("-" * 60)
    for i in range(10):
        mock_traffic = generate_mock_traffic()
        result = classifier.classify(mock_traffic)
        print(f"[{i+1}] 敏感: {result['is_sensitive']}, "
              f"信心度: {result['confidence']:.2f}, "
              f"檢測到: {result['detected_patterns']}")

    print("\n" + "=" * 60)
    print("測試完成!")
    print("=" * 60)


if __name__ == "__main__":
    main()
