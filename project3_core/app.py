"""
項目 3: 系統核心
整合隱私分類器和加密檢測,提供REST API

功能:
- 接收流量數據
- 判斷是否敏感
- 路由到適當的檢測器
- 返回檢測結果
"""

import sys
import os
import time
from datetime import datetime
from typing import Dict, Optional

# 添加專案路徑
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import List

# 導入項目1和項目2
from project1_classifier.classifier import PrivacyClassifier, generate_mock_traffic
from project2_encryption.detector import PlaintextDetector, HomomorphicDetector, generate_synthetic_data


# ==================== 數據模型 ====================

class TrafficData(BaseModel):
    """流量數據輸入格式"""
    payload: str = ""  # 可選: 流量內容 (base64或字符串)
    source_ip: str = "0.0.0.0"
    destination_ip: str = "0.0.0.0"
    feature_vector: Optional[List[float]] = None  # 可選: 直接提供8維特徵向量


class DetectionResponse(BaseModel):
    """檢測結果輸出格式"""
    traffic_id: str
    timestamp: str
    is_anomaly: bool
    anomaly_score: float
    is_sensitive: bool
    detection_method: str
    latency_ms: float
    privacy_protected: bool


# ==================== 系統核心 ====================

class APPADCore:
    """APPAD 系統核心 - 自適應隱私保護異常檢測"""

    def __init__(self, mock_mode: bool = False):
        """
        初始化系統核心

        參數:
            mock_mode: 是否使用Mock模式(不需要訓練好的模型)
        """
        self.mock_mode = mock_mode

        # 統計數據
        self.total_requests = 0
        self.sensitive_count = 0
        self.anomaly_count = 0
        self.total_latency = 0

        # 初始化組件
        print("初始化 APPAD 系統核心...")

        # 項目1: 隱私分類器
        self.classifier = PrivacyClassifier()
        print("[OK] 隱私分類器已載入")

        # 項目2: 檢測器
        if not mock_mode:
            # 嘗試載入已訓練的模型
            model_path = 'project2_encryption/trained_model.pkl'
            if os.path.exists(model_path):
                self.plain_detector = PlaintextDetector(model_path=model_path)
                print("[OK] 已載入訓練好的檢測模型")
            else:
                # 快速訓練一個模型
                print("未找到訓練好的模型,正在訓練...")
                self.plain_detector = PlaintextDetector()
                X, y = generate_synthetic_data(n_samples=5000)
                self.plain_detector.train(X, y, model_type='logistic')
                print("[OK] 檢測模型訓練完成")
        else:
            self.plain_detector = None
            print("[OK] Mock模式: 使用模擬檢測器")

        # 加密檢測器
        self.he_detector = HomomorphicDetector(plaintext_model=self.plain_detector)
        print("[OK] 加密檢測器已初始化")

        print("=" * 60)
        print("APPAD 系統核心已啟動")
        print("=" * 60)

    def process_traffic(self, traffic_data: dict) -> Dict:
        """
        處理流量數據 - 核心路由邏輯

        流程:
        1. 使用項目1分類流量
        2. 根據是否敏感決定使用哪種檢測方式
        3. 返回檢測結果
        """
        start_time = time.time()

        # Step 1: 分類流量 (項目1)
        classification_result = self.classifier.classify(traffic_data)

        traffic_id = classification_result['traffic_id']
        timestamp = classification_result['timestamp']
        is_sensitive = classification_result['is_sensitive']
        feature_vector = classification_result['feature_vector']

        # Step 2: 路由決策 - 選擇檢測方式
        if is_sensitive:
            # 敏感流量 → 使用加密檢測 (項目2 - 加密模式)
            detection_result = self.he_detector.detect_encrypted(feature_vector)
            method = "encrypted"
            privacy_protected = True
        else:
            # 一般流量 → 使用明文檢測 (項目2 - 明文模式)
            if self.mock_mode or not self.plain_detector:
                # Mock模式: 返回隨機結果
                import random
                detection_result = {
                    "anomaly_score": random.random(),
                    "is_anomaly": random.choice([True, False]),
                    "processing_time_ms": random.uniform(3, 8),
                    "method": "plaintext_mock"
                }
            else:
                detection_result = self.plain_detector.detect(feature_vector)

            method = "plaintext"
            privacy_protected = False

        # Step 3: 組合最終結果
        total_latency = (time.time() - start_time) * 1000  # 毫秒

        # 更新統計
        self.total_requests += 1
        if is_sensitive:
            self.sensitive_count += 1
        if detection_result['is_anomaly']:
            self.anomaly_count += 1
        self.total_latency += total_latency

        return {
            "traffic_id": traffic_id,
            "timestamp": timestamp,
            "is_anomaly": detection_result['is_anomaly'],
            "anomaly_score": detection_result['anomaly_score'],
            "is_sensitive": is_sensitive,
            "detection_method": method,
            "latency_ms": round(total_latency, 2),
            "privacy_protected": privacy_protected
        }

    def get_metrics(self) -> Dict:
        """獲取系統統計指標"""
        avg_latency = (self.total_latency / self.total_requests
                       if self.total_requests > 0 else 0)

        sensitive_ratio = (self.sensitive_count / self.total_requests
                          if self.total_requests > 0 else 0)

        anomaly_ratio = (self.anomaly_count / self.total_requests
                        if self.total_requests > 0 else 0)

        return {
            "total_requests": self.total_requests,
            "sensitive_count": self.sensitive_count,
            "anomaly_count": self.anomaly_count,
            "avg_latency_ms": round(avg_latency, 2),
            "sensitive_ratio": round(sensitive_ratio, 3),
            "anomaly_ratio": round(anomaly_ratio, 3)
        }


# ==================== FastAPI 應用 ====================

app = FastAPI(
    title="APPAD API",
    description="自適應隱私保護異常檢測系統",
    version="1.0.0"
)

# 全局變量: APPAD核心實例
appad_core: Optional[APPADCore] = None


@app.on_event("startup")
async def startup_event():
    """應用啟動時初始化"""
    global appad_core

    # 檢查是否使用Mock模式
    import sys
    mock_mode = '--mock-mode' in sys.argv

    appad_core = APPADCore(mock_mode=mock_mode)


@app.get("/")
async def root():
    """根路徑"""
    return {
        "service": "APPAD - Adaptive Privacy-Preserving Anomaly Detection",
        "version": "1.0.0",
        "status": "running",
        "endpoints": {
            "detect": "POST /detect - 檢測流量異常",
            "health": "GET /health - 健康檢查",
            "metrics": "GET /metrics - 系統統計"
        }
    }


@app.post("/detect", response_model=DetectionResponse)
async def detect_anomaly(traffic_data: TrafficData):
    """
    異常檢測主接口

    接收流量數據,返回檢測結果
    """
    if appad_core is None:
        raise HTTPException(status_code=503, detail="系統尚未初始化")

    try:
        # 轉換為字典格式
        traffic_dict = {
            'payload': traffic_data.payload.encode('utf-8') if traffic_data.payload else b'',
            'source_ip': traffic_data.source_ip,
            'destination_ip': traffic_data.destination_ip
        }

        # 處理流量
        result = appad_core.process_traffic(traffic_dict)

        return result

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"檢測失敗: {str(e)}")


@app.get("/health")
async def health_check():
    """健康檢查"""
    return {
        "status": "ok",
        "timestamp": datetime.utcnow().isoformat() + 'Z',
        "system_initialized": appad_core is not None
    }


@app.get("/metrics")
async def get_metrics():
    """獲取系統統計指標"""
    if appad_core is None:
        raise HTTPException(status_code=503, detail="系統尚未初始化")

    return appad_core.get_metrics()


@app.post("/test/mock")
async def test_with_mock_data():
    """使用Mock數據進行測試"""
    if appad_core is None:
        raise HTTPException(status_code=503, detail="系統尚未初始化")

    # 生成Mock流量
    mock_traffic = generate_mock_traffic()

    # 處理
    result = appad_core.process_traffic(mock_traffic)

    return result


# ==================== 命令行運行 ====================

def main():
    """命令行啟動"""
    import uvicorn
    import argparse

    parser = argparse.ArgumentParser(description='APPAD 系統核心')
    parser.add_argument('--mock-mode', action='store_true',
                       help='使用Mock模式(不需要訓練好的模型)')
    parser.add_argument('--host', default='127.0.0.1',
                       help='綁定主機 (預設: 127.0.0.1)')
    parser.add_argument('--port', type=int, default=8000,
                       help='綁定端口 (預設: 8000)')

    args = parser.parse_args()

    print("\n" + "=" * 60)
    print("啟動 APPAD 系統")
    print("=" * 60)
    print(f"模式: {'Mock模式' if args.mock_mode else '正常模式'}")
    print(f"地址: http://{args.host}:{args.port}")
    print(f"文檔: http://{args.host}:{args.port}/docs")
    print("=" * 60 + "\n")

    # 啟動服務
    uvicorn.run(
        "app:app",
        host=args.host,
        port=args.port,
        reload=False
    )


if __name__ == "__main__":
    main()
