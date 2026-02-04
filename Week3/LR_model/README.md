# LR 模型（明文）

本資料夾提供 Logistic Regression 的訓練與推論腳本，以及對應的輸出說明。

## 輸出檔案說明

### 訓練輸出（train_lr.py）
- `output_lr/lr_model.joblib`：訓練完成的 LR 模型。
- `output_lr/training_results_lr.json`：訓練/驗證/測試指標與設定。
- `output_lr/training_metrics_lr.png`：Train/Val/Test 的 Accuracy、Precision、Recall、F1 指標比較圖。
- `output_lr/precision_recall_curve_lr.png`：驗證集 PR 曲線。
- `output_lr/val_confusion_matrix_lr.png`：驗證集混淆矩陣。
- `output_lr/test_confusion_matrix_lr.png`：測試集混淆矩陣。

`training_results_lr.json` 欄位：
- `config`：訓練參數（`max_iter`、`threshold`、`use_class_weight`）。
- `train_metrics` / `val_metrics` / `test_metrics`：
  - `accuracy`：整體正確率
  - `precision`：預測異常中實際為異常的比例
  - `recall`：實際異常被偵測的比例
  - `f1`：Precision 與 Recall 的調和平均
  - `confusion_matrix`：[[TN, FP], [FN, TP]]

### 推論輸出（infer_lr.py）
- `output_lr/lr_inference_predictions.csv`：推論結果，包含原始欄位 + `anomaly_prob` + `anomaly_pred`。
- `output_lr/lr_inference_metrics.json`：若資料含 `Anomaly` 欄位，會輸出推論指標。
- `output_lr/lr_inference_prob_hist.png`：推論機率分佈直方圖。
- `output_lr/lr_inference_confusion_matrix.png`：若有標籤，輸出推論混淆矩陣。

## 注意
- 圖形會在執行對應腳本後自動產生於 `output_lr/`。
- 若未提供標籤欄位（`Anomaly`），推論僅輸出預測結果與機率分佈圖。
