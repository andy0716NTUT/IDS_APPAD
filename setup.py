"""
IDS_APPAD 安裝腳本
"""

import subprocess
import sys
import os


def install_dependencies():
    """安裝所有依賴套件"""
    print("=" * 60)
    print("安裝 IDS_APPAD 依賴套件")
    print("=" * 60)

    # 安裝根目錄的requirements.txt
    print("\n安裝主要依賴...")
    subprocess.check_call([sys.executable, '-m', 'pip', 'install', '-r', 'requirements.txt'])

    print("\n✓ 所有依賴安裝完成!")


def train_initial_model():
    """訓練初始模型"""
    print("\n" + "=" * 60)
    print("訓練初始檢測模型")
    print("=" * 60)

    # 執行項目2的訓練
    print("\n訓練異常檢測模型...")
    subprocess.check_call([sys.executable, 'project2_encryption/detector.py'])

    print("\n✓ 初始模型訓練完成!")


def run_tests():
    """執行測試"""
    print("\n" + "=" * 60)
    print("執行整合測試")
    print("=" * 60)

    subprocess.check_call([sys.executable, 'tests/test_integration.py'])


def main():
    """主安裝流程"""
    import argparse

    parser = argparse.ArgumentParser(description='IDS_APPAD 安裝腳本')
    parser.add_argument('--skip-train', action='store_true',
                       help='跳過模型訓練')
    parser.add_argument('--skip-test', action='store_true',
                       help='跳過測試')

    args = parser.parse_args()

    try:
        # 1. 安裝依賴
        install_dependencies()

        # 2. 訓練模型
        if not args.skip_train:
            train_initial_model()
        else:
            print("\n跳過模型訓練")

        # 3. 執行測試
        if not args.skip_test:
            run_tests()
        else:
            print("\n跳過測試")

        print("\n" + "=" * 60)
        print("✓ 安裝完成!")
        print("=" * 60)
        print("\n快速啟動:")
        print("  python run.py")
        print("\n或者:")
        print("  cd project3_core")
        print("  python app.py")
        print("=" * 60)

    except Exception as e:
        print(f"\n✗ 安裝失敗: {str(e)}")
        sys.exit(1)


if __name__ == "__main__":
    main()
