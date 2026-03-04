## Week7-8 - 自適應路由模組實作（Adaptive Routing）

這週的重點是把前面幾週做好的模組串起來，真正落地「自適應路由」：

- **Week2**：對整筆事件做敏感度/風險判斷（LOW / MEDIUM / HIGH）
- **Week5/Week6**：對欄位做敏感度判斷，並組裝 `{"plain":..., "encrypted":...}` payload
- **Week3**：APPAD 的角色分工（Client 決策/解密、Server 推論）

### 為什麼新增 `Week7_8/`？

本 repo 的作業資料夾叫 `Week7-8/`（含 `-`），Python 無法把它當作 package import。
因此本週的可執行/可 import 程式碼放在 **`Week7_8/`**：

- `Week7_8/adaptive_router.py`：路由決策 + 端到端流程（plaintext vs mixed-HE）
- `Week7_8/feature_encoder.py`：把原始 record 編碼為數值，確保 HE 可運作
- `Week7_8/run_adaptive_routing_demo.py`：demo（讀 dataset 前幾筆，跑路由與結果）

### 运行方式

在专案根目录执行：

```bash
python -m Week7_8.run_adaptive_routing_demo
```

> 若已安裝 `phe`（Paillier encryptor 用）：`pip install phe`，demo 會使用真正的 Paillier HE。
> 若未安裝，會**自動 fallback** 到 `FakeEncryptor(simulated HE)`，仍可端到端展示 routing + mixed payload + client-side decrypt 的流程（PoC 用途）。

