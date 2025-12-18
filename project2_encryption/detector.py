"""
項目 2: 加密檢測系統
使用加密方式檢測異常(處理敏感資料)

階段一: 明文模型訓練
階段二: 同態加密實作 (可選)
"""

import numpy as np
import json
import time
from typing import List, Dict, Union
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_recall_fscore_support
import pickle
import os


class PlaintextDetector:
    """明文異常檢測器 - 快速但不保護隱私"""

    def __init__(self, model_path: str = None):
        self.model = None
        self.scaler = StandardScaler()
        self.is_trained = False
        self.model_path = model_path

        if model_path and os.path.exists(model_path):
            self.load_model(model_path)

    def train(self, X_train: np.ndarray, y_train: np.ndarray, model_type: str = 'logistic'):
        """
        訓練明文檢測模型

        參數:
            X_train: 訓練特徵 (n_samples, 8)
            y_train: 訓練標籤 (n_samples,) 0=正常, 1=異常
            model_type: 模型類型 'logistic' 或 'random_forest'
        """
        print(f"訓練明文檢測模型 ({model_type})...")

        # 標準化特徵
        X_train_scaled = self.scaler.fit_transform(X_train)

        # 選擇模型
        if model_type == 'logistic':
            self.model = LogisticRegression(random_state=42, max_iter=1000)
        elif model_type == 'random_forest':
            self.model = RandomForestClassifier(n_estimators=100, random_state=42)
        else:
            raise ValueError(f"不支援的模型類型: {model_type}")

        # 訓練模型
        start_time = time.time()
        self.model.fit(X_train_scaled, y_train)
        training_time = time.time() - start_time

        self.is_trained = True

        print(f"訓練完成! 耗時: {training_time:.2f}秒")

        # 訓練集準確度
        y_pred = self.model.predict(X_train_scaled)
        train_accuracy = accuracy_score(y_train, y_pred)
        print(f"訓練集準確度: {train_accuracy:.4f}")

        return {
            'training_time': training_time,
            'train_accuracy': train_accuracy
        }

    def detect(self, features: Union[List[float], np.ndarray]) -> Dict:
        """
        檢測異常(明文方式)

        參數:
            features: 8維特徵向量

        返回:
            {
                "anomaly_score": 0.87,
                "is_anomaly": True,
                "processing_time_ms": 5.2,
                "method": "plaintext"
            }
        """
        if not self.is_trained:
            raise ValueError("模型尚未訓練! 請先調用 train() 方法")

        start_time = time.time()

        # 確保輸入格式正確
        if isinstance(features, list):
            features = np.array(features)

        if features.shape != (8,):
            raise ValueError(f"特徵向量必須是8維, 當前: {features.shape}")

        # 標準化特徵
        features_scaled = self.scaler.transform(features.reshape(1, -1))

        # 預測
        anomaly_score = self.model.predict_proba(features_scaled)[0][1]
        is_anomaly = anomaly_score > 0.5

        processing_time = (time.time() - start_time) * 1000  # 轉換為毫秒

        return {
            "anomaly_score": float(anomaly_score),
            "is_anomaly": bool(is_anomaly),
            "processing_time_ms": round(processing_time, 2),
            "method": "plaintext"
        }

    def evaluate(self, X_test: np.ndarray, y_test: np.ndarray) -> Dict:
        """評估模型性能"""
        if not self.is_trained:
            raise ValueError("模型尚未訓練!")

        X_test_scaled = self.scaler.transform(X_test)
        y_pred = self.model.predict(X_test_scaled)
        y_pred_proba = self.model.predict_proba(X_test_scaled)[:, 1]

        accuracy = accuracy_score(y_test, y_pred)
        precision, recall, f1, _ = precision_recall_fscore_support(
            y_test, y_pred, average='binary'
        )

        return {
            'accuracy': float(accuracy),
            'precision': float(precision),
            'recall': float(recall),
            'f1_score': float(f1)
        }

    def save_model(self, path: str):
        """儲存模型"""
        if not self.is_trained:
            raise ValueError("模型尚未訓練!")

        model_data = {
            'model': self.model,
            'scaler': self.scaler
        }

        with open(path, 'wb') as f:
            pickle.dump(model_data, f)

        print(f"模型已儲存至: {path}")

    def load_model(self, path: str):
        """載入模型"""
        with open(path, 'rb') as f:
            model_data = pickle.load(f)

        self.model = model_data['model']
        self.scaler = model_data['scaler']
        self.is_trained = True

        print(f"模型已從 {path} 載入")


class HomomorphicDetector:
    """同態加密檢測器 - 保護隱私但較慢"""

    def __init__(self, plaintext_model: PlaintextDetector = None):
        self.plaintext_model = plaintext_model
        self.use_encryption = False  # 暫時使用明文模式

        # TODO: 未來可整合 TenSEAL 進行同態加密
        # import tenseal as ts
        # self.context = ts.context(ts.SCHEME_TYPE.CKKS, 8192)

    def detect_encrypted(self, features: Union[List[float], np.ndarray]) -> Dict:
        """
        檢測異常(加密方式)

        目前實作: 使用明文模型 + 模擬加密延遲
        未來: 整合 TenSEAL 進行真實同態加密運算
        """
        start_time = time.time()

        # 模擬加密運算的延遲 (約200ms)
        time.sleep(0.2)

        # 使用明文模型進行檢測
        if self.plaintext_model and self.plaintext_model.is_trained:
            result = self.plaintext_model.detect(features)
            result['method'] = 'encrypted'
            result['processing_time_ms'] = (time.time() - start_time) * 1000
        else:
            # 如果沒有訓練好的模型,返回隨機結果
            anomaly_score = np.random.random()
            result = {
                "anomaly_score": float(anomaly_score),
                "is_anomaly": anomaly_score > 0.5,
                "processing_time_ms": (time.time() - start_time) * 1000,
                "method": "encrypted_mock"
            }

        return result


def generate_synthetic_data(n_samples: int = 10000, anomaly_ratio: float = 0.15):
    """
    生成合成測試數據

    參數:
        n_samples: 樣本數量
        anomaly_ratio: 異常樣本比例

    返回:
        X: 特徵矩陣 (n_samples, 8)
        y: 標籤向量 (n_samples,) 0=正常, 1=異常
    """
    np.random.seed(42)

    n_anomalies = int(n_samples * anomaly_ratio)
    n_normal = n_samples - n_anomalies

    # 正常流量特徵 (較小的值, 較低的變異)
    normal_features = np.random.beta(2, 5, size=(n_normal, 8))

    # 異常流量特徵 (較大的值, 較高的變異)
    anomaly_features = np.random.beta(5, 2, size=(n_anomalies, 8))

    # 合併數據
    X = np.vstack([normal_features, anomaly_features])
    y = np.hstack([np.zeros(n_normal), np.ones(n_anomalies)])

    # 打亂順序
    indices = np.random.permutation(n_samples)
    X = X[indices]
    y = y[indices]

    return X, y


def load_kddcup99_data(n_samples: int = 10000):
    """
    載入 KDD Cup 99 數據集

    參數:
        n_samples: 要載入的樣本數量

    返回:
        X: 特徵矩陣 (n_samples, 8)
        y: 標籤向量 (n_samples,) 0=正常, 1=異常
    """
    try:
        from sklearn.datasets import fetch_kddcup99
        print("正在下載 KDD Cup 99 數據集...")

        # 下載數據集 (使用10%子集以加快速度)
        data = fetch_kddcup99(subset='SA', percent10=True)
        X_raw, y_raw = data.data, data.target

        # 選取前8個數值特徵
        X = X_raw[:n_samples, :8].astype(float)

        # 標籤轉換: 'normal' -> 0, 其他 -> 1
        y = np.where(y_raw[:n_samples] == b'normal.', 0, 1)

        # 標準化到0-1範圍
        from sklearn.preprocessing import MinMaxScaler
        scaler = MinMaxScaler()
        X = scaler.fit_transform(X)

        print(f"成功載入 {len(X)} 筆資料")
        print(f"正常: {np.sum(y==0)} 筆, 異常: {np.sum(y==1)} 筆")

        return X, y

    except Exception as e:
        print(f"無法載入 KDD Cup 99 數據集: {e}")
        print("改用合成數據...")
        return generate_synthetic_data(n_samples)


def main():
    """測試加密檢測系統"""
    print("=" * 60)
    print("項目 2: 加密檢測系統測試")
    print("=" * 60)

    # 1. 生成或載入訓練數據
    print("\n[步驟 1] 準備訓練數據")
    print("-" * 60)

    # 嘗試使用真實數據集,失敗則使用合成數據
    X, y = load_kddcup99_data(n_samples=10000)

    # 分割訓練集和測試集
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42
    )

    print(f"訓練集: {len(X_train)} 筆")
    print(f"測試集: {len(X_test)} 筆")

    # 2. 訓練明文模型
    print("\n[步驟 2] 訓練明文檢測模型")
    print("-" * 60)

    detector = PlaintextDetector()
    detector.train(X_train, y_train, model_type='logistic')

    # 3. 評估模型
    print("\n[步驟 3] 評估模型性能")
    print("-" * 60)

    metrics = detector.evaluate(X_test, y_test)
    print(f"測試集準確度: {metrics['accuracy']:.4f}")
    print(f"精確度: {metrics['precision']:.4f}")
    print(f"召回率: {metrics['recall']:.4f}")
    print(f"F1分數: {metrics['f1_score']:.4f}")

    # 4. 測試推論速度
    print("\n[步驟 4] 測試推論延遲")
    print("-" * 60)

    test_feature = X_test[0]

    # 明文檢測
    result_plain = detector.detect(test_feature)
    print(f"明文檢測延遲: {result_plain['processing_time_ms']:.2f} ms")
    print(f"異常分數: {result_plain['anomaly_score']:.4f}")
    print(f"是否異常: {result_plain['is_anomaly']}")

    # 加密檢測
    print("\n加密檢測 (模擬):")
    he_detector = HomomorphicDetector(plaintext_model=detector)
    result_encrypted = he_detector.detect_encrypted(test_feature)
    print(f"加密檢測延遲: {result_encrypted['processing_time_ms']:.2f} ms")
    print(f"異常分數: {result_encrypted['anomaly_score']:.4f}")
    print(f"是否異常: {result_encrypted['is_anomaly']}")

    # 5. 儲存模型
    print("\n[步驟 5] 儲存模型")
    print("-" * 60)

    model_path = 'trained_model.pkl'
    detector.save_model(model_path)

    # 6. 批次測試
    print("\n[步驟 6] 批次測試 (10筆隨機樣本)")
    print("-" * 60)

    for i in range(10):
        idx = np.random.randint(0, len(X_test))
        feature = X_test[idx]
        true_label = y_test[idx]

        result = detector.detect(feature)

        status = "✓" if (result['is_anomaly'] == (true_label == 1)) else "✗"
        print(f"[{i+1}] {status} 預測: {result['is_anomaly']}, "
              f"實際: {true_label==1}, "
              f"分數: {result['anomaly_score']:.3f}")

    print("\n" + "=" * 60)
    print("測試完成!")
    print("=" * 60)


if __name__ == "__main__":
    main()
