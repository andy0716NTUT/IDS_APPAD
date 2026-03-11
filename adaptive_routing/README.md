## 自適應路由模組實作（Adaptive Routing）

把前面幾週做好的模組串起來，真正落地「自適應路由」：

- **classifier**：對整筆事件做敏感度/風險判斷（LOW / MEDIUM / HIGH）
- **ckks_homomorphic_encryption**：對欄位做敏感度判斷，並組裝 `{"plain":..., "encrypted":...}` payload
- **adaptive_module**：APPAD 的角色分工（Client 決策/解密、Server 推論）

### 模組結構

- `adaptive_routing/adaptive_router.py`：路由決策 + 端到端流程（plaintext vs mixed-HE）
- `adaptive_routing/feature_encoder.py`：把原始 record 編碼為數值，確保 HE 可運作
- `adaptive_routing/run_adaptive_routing_demo.py`：demo（讀 dataset 前幾筆，跑路由與結果）

### 运行方式

在专案根目录执行：

```bash
python -m adaptive_routing.run_adaptive_routing_demo
```

> 若已安裝 `phe`（Paillier encryptor 用）：`pip install phe`，demo 會使用真正的 Paillier HE。
> 若未安裝，會**自動 fallback** 到 `FakeEncryptor(simulated HE)`，仍可端到端展示 routing + mixed payload + client-side decrypt 的流程（PoC 用途）。

