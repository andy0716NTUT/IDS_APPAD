#!/usr/bin/env bash
# IDS Inference Server — 啟動腳本
#
# 用法:
#   ./start_server.sh              # 預設 port 5001
#   ./start_server.sh --port 8080  # 自訂 port
#   ./start_server.sh --host 0.0.0.0 --port 5001  # 允許外部連入

set -euo pipefail
cd "$(dirname "$0")"

# 建立虛擬環境（首次執行時）
if [ ! -d ".venv" ]; then
    echo "Creating virtual environment..."
    python3 -m venv .venv
    .venv/bin/pip install --upgrade pip
    .venv/bin/pip install -r requirements.txt
    echo "Dependencies installed."
fi

# 啟動 Server
echo "Starting IDS inference server..."
exec .venv/bin/python -m server_module.server_app "$@"
