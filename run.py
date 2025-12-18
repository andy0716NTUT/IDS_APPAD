"""
快速啟動腳本
"""

import subprocess
import sys
import os
import argparse


def check_model_exists():
    """檢查模型是否已訓練"""
    model_path = 'project2_encryption/trained_model.pkl'
    return os.path.exists(model_path)


def train_model():
    """訓練模型"""
    print("=" * 60)
    print("首次執行,正在訓練檢測模型...")
    print("=" * 60)
    subprocess.check_call([sys.executable, 'project2_encryption/detector.py'])
    print("\n✓ 模型訓練完成!")


def start_server(host='127.0.0.1', port=8000, mock_mode=False):
    """啟動服務"""
    print("\n" + "=" * 60)
    print("啟動 APPAD 系統")
    print("=" * 60)

    args = [sys.executable, 'project3_core/app.py']

    if mock_mode:
        args.append('--mock-mode')

    args.extend(['--host', host, '--port', str(port)])

    print(f"模式: {'Mock模式' if mock_mode else '正常模式'}")
    print(f"地址: http://{host}:{port}")
    print(f"文檔: http://{host}:{port}/docs")
    print("=" * 60 + "\n")

    subprocess.check_call(args)


def main():
    parser = argparse.ArgumentParser(description='IDS_APPAD 快速啟動')
    parser.add_argument('--host', default='127.0.0.1',
                       help='綁定主機 (預設: 127.0.0.1)')
    parser.add_argument('--port', type=int, default=8000,
                       help='綁定端口 (預設: 8000)')
    parser.add_argument('--mock-mode', action='store_true',
                       help='使用Mock模式(不需要訓練模型)')
    parser.add_argument('--force-train', action='store_true',
                       help='強制重新訓練模型')

    args = parser.parse_args()

    try:
        # 檢查模型
        if not args.mock_mode:
            if args.force_train or not check_model_exists():
                train_model()
            else:
                print("✓ 檢測到已訓練的模型")

        # 啟動服務
        start_server(
            host=args.host,
            port=args.port,
            mock_mode=args.mock_mode
        )

    except KeyboardInterrupt:
        print("\n\n服務已停止")
    except Exception as e:
        print(f"\n✗ 啟動失敗: {str(e)}")
        sys.exit(1)


if __name__ == "__main__":
    main()
