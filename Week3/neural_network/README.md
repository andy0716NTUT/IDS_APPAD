# 神經網路異常偵測模型

本專案使用 PyTorch 建立前饋神經網路，用於偵測網路驗證日誌中的異常行為。

## 目錄結構

```
Week3/neural_network/
├── train.py                # 訓練腳本
├── README.md               # 說明文件
└── output/                 # 輸出目錄
    ├── best_model.pt              # 最佳模型權重
    ├── training_results.json      # 訓練結果與指標
    └── precision_recall_curve.png # PR 曲線圖表
```

## 資料來源

使用 Week2 預處理後的 MinMax 正規化資料：
- 訓練集：`Week2/data_Pre-processing/output/normalize/train_normalized.csv`
- 驗證集：`Week2/data_Pre-processing/output/normalize/val_normalized.csv`

## 特徵欄位

| 欄位名稱 | 說明 |
|----------|------|
| User ID | 使用者編號（正規化後） |
| Session Duration | 連線時長（正規化後） |
| Failed Attempts | 失敗嘗試次數（正規化後） |
| Behavioral Score | 行為評分（正規化後） |

目標欄位：`Anomaly`（0 = 正常，1 = 異常）

## 模型架構

```
輸入層 (4 個特徵)
    ↓
隱藏層 1 (預設 32 神經元) + ReLU + Dropout(0.2)
    ↓
隱藏層 2 (預設 16 神經元) + ReLU + Dropout(0.2)
    ↓
輸出層 (1 神經元) + Sigmoid
```

## 使用方式

### 基本訓練

```bash
cd Week3/neural_network
python train.py
```

### 參數說明

| 參數 | 預設值 | 說明 |
|------|--------|------|
| `--epochs` | 50 | 訓練輪數 |
| `--batch-size` | 32 | 批次大小 |
| `--lr` | 0.001 | 學習率 |
| `--hidden-dims` | "32,16" | 隱藏層維度（逗號分隔） |
| `--threshold` | 0.5 | 分類門檻（降低可提高 Recall） |
| `--use-class-weight` | False | 使用類別權重處理不平衡資料 |
| `--data-dir` | 自動偵測 | 資料目錄路徑 |
| `--output-dir` | ./output | 輸出目錄路徑 |

### 進階範例

提高 Recall（適合重視偵測率的場景）：

```bash
python train.py --use-class-weight --threshold 0.4 --epochs 100
```

使用更大的網路：

```bash
python train.py --hidden-dims "64,32,16" --epochs 150
```

完整參數範例：

```bash
python train.py \
    --epochs 100 \
    --batch-size 64 \
    --lr 0.001 \
    --hidden-dims "64,32,16" \
    --threshold 0.4 \
    --use-class-weight
```

## 輸出說明

### training_results.json

包含以下內容：
- `config`：訓練配置參數
- `final_metrics`：最終評估指標（accuracy、precision、recall、f1、confusion_matrix）
- `history`：訓練歷史（每個 epoch 的 loss 與指標）
- `precision_recall_analysis`：PR 曲線分析結果

### precision_recall_curve.png

包含兩張圖表：
1. Precision-Recall 曲線：展示不同 recall 下的 precision
2. Metrics vs Threshold：展示不同門檻下的 precision、recall、F1 變化

此圖表可協助選擇最佳分類門檻。

## 類別不平衡處理

資料集中異常樣本約佔 17.9%，屬於不平衡資料。使用 `--use-class-weight` 參數可啟用加權損失函數：

- 計算正樣本權重：`pos_weight = (1 - 異常比例) / 異常比例`
- 對漏報異常施加較高懲罰，提升 Recall

## 門檻調整建議

| 場景 | 建議門檻 | 特性 |
|------|----------|------|
| 高精確度（減少誤報） | 0.5 - 0.6 | Precision 高，Recall 低 |
| 平衡 | 0.4 | Precision 與 Recall 較平衡 |
| 高召回率（減少漏報） | 0.3 - 0.35 | Recall 高，Precision 降低 |

建議執行訓練後參考 `precision_recall_curve.png` 圖表，根據實際需求選擇最佳門檻。

## 評估指標說明

| 指標 | 說明 |
|------|------|
| Accuracy | 整體正確率 |
| Precision | 預測為異常中實際為異常的比例（減少誤報） |
| Recall | 實際異常中被正確偵測的比例（減少漏報） |
| F1 Score | Precision 與 Recall 的調和平均數 |

### 混淆矩陣

```
              預測
              正常    異常
實際 正常     TN      FP（誤報）
實際 異常     FN（漏報）TP
```

## 依賴套件

- torch
- numpy
- pandas
- scikit-learn
- matplotlib

安裝指令：

```bash
pip install torch numpy pandas scikit-learn matplotlib
```

## 注意事項

1. 首次執行需確保 Week2 的正規化資料已產生
2. 訓練時會自動保存最佳 F1 分數的模型
3. 若使用 GPU，程式會自動偵測並使用 CUDA