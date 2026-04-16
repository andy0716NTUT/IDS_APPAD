import { useEffect, useState } from 'react';
import { MetricCard } from './components/MetricCard';
import { Play, History } from 'lucide-react';
import { Tabs, TabsContent, TabsList, TabsTrigger } from './components/ui/tabs';

interface ChartPoint {
  ratio: number;
  value: number;
}

interface MetricData {
  accuracy: number;
  latencySec: number;
  detectionEfficiency: number;
  infoLeakage: number;
}

interface ChartSeries {
  accuracy: ChartPoint[];
  latency: ChartPoint[];
  detectionEfficiency: ChartPoint[];
  infoLeakage: ChartPoint[];
}

interface ExecutionRecord {
  id: number;
  timestamp: string;
  metrics: MetricData;
  chartSeries: ChartSeries;
  sampledRecordsPreview: SampleRecord[];
  artifacts: ArtifactsData;
}

interface SampleRecord {
  sample_idx: number;
  pre_sensitive_label: string;
  anomaly: number;
  user_id?: string;
  login_status?: string;
  location?: string;
}

interface CiphertextFileInfo {
  name: string;
  path: string;
  bytes: number;
}

interface ArtifactsData {
  datasetPath: string;
  sampledPlainDataPath: string;
  encryptedPayloadIndexPath: string;
  encryptedCiphertextDir: string;
  encryptedCiphertextFiles: CiphertextFileInfo[];
  encryptedCiphertextFileCount: number;
}

interface ApiPayload {
  metrics?: {
    metrics?: {
      accuracy?: number;
      information_leakage?: number;
      detection_efficiency?: number;
    };
    latency_sec?: {
      avg?: number;
    };
  };
  chartSeries?: {
    accuracy?: ChartPoint[];
    latency?: ChartPoint[];
    informationLeakage?: ChartPoint[];
    detectionEfficiency?: ChartPoint[];
  };
  artifacts?: Partial<ArtifactsData>;
  sampledRecordsPreview?: SampleRecord[];
  stdout?: string;
  stderr?: string;
  errorSummary?: string;
  returncode?: number;
  error?: string;
}

interface HexViewPayload {
  path: string;
  totalBytes: number;
  offset: number;
  length: number;
  requestedLength: number;
  nextOffset: number;
  prevOffset: number;
  hasPrev: boolean;
  hasNext: boolean;
  hexDump: string;
}

const defaultMetrics: MetricData = {
  accuracy: 0,
  latencySec: 0,
  detectionEfficiency: 0,
  infoLeakage: 0,
};

const defaultChartSeries: ChartSeries = {
  accuracy: [],
  latency: [],
  detectionEfficiency: [],
  infoLeakage: [],
};

const defaultArtifacts: ArtifactsData = {
  datasetPath: '',
  sampledPlainDataPath: '',
  encryptedPayloadIndexPath: '',
  encryptedCiphertextDir: '',
  encryptedCiphertextFiles: [],
  encryptedCiphertextFileCount: 0,
};

function toMetricData(payload: ApiPayload): MetricData {
  const m = payload.metrics?.metrics;
  const latency = payload.metrics?.latency_sec?.avg;
  return {
    accuracy: Number(m?.accuracy ?? 0),
    latencySec: Number(latency ?? 0),
    detectionEfficiency: Number(m?.detection_efficiency ?? 0),
    infoLeakage: Number(m?.information_leakage ?? 0),
  };
}

function toChartSeries(payload: ApiPayload): ChartSeries {
  const c = payload.chartSeries;
  return {
    accuracy: c?.accuracy ?? [],
    latency: c?.latency ?? [],
    detectionEfficiency: c?.detectionEfficiency ?? [],
    infoLeakage: c?.informationLeakage ?? [],
  };
}

function toArtifacts(payload: ApiPayload): ArtifactsData {
  const a = payload.artifacts;
  return {
    datasetPath: a?.datasetPath ?? '',
    sampledPlainDataPath: a?.sampledPlainDataPath ?? '',
    encryptedPayloadIndexPath: a?.encryptedPayloadIndexPath ?? '',
    encryptedCiphertextDir: a?.encryptedCiphertextDir ?? '',
    encryptedCiphertextFiles: a?.encryptedCiphertextFiles ?? [],
    encryptedCiphertextFileCount: Number(a?.encryptedCiphertextFileCount ?? 0),
  };
}

function getStatus(metric: string, value: number): '正常' | '警告' | '危險' {
  if (metric === 'accuracy') {
    if (value >= 0.9) {
      return '正常';
    }
    if (value >= 0.8) {
      return '警告';
    }
    return '危險';
  }
  if (metric === 'latencySec') {
    if (value <= 0.5) {
      return '正常';
    }
    if (value <= 1.5) {
      return '警告';
    }
    return '危險';
  }
  if (metric === 'detectionEfficiency') {
    if (value >= 0.5) {
      return '正常';
    }
    if (value >= 0.1) {
      return '警告';
    }
    return '危險';
  }
  if (metric === 'infoLeakage') {
    if (value <= 300) {
      return '正常';
    }
    if (value <= 500) {
      return '警告';
    }
    return '危險';
  }
  return '正常';
}

export default function App() {
  const [metrics, setMetrics] = useState<MetricData>(defaultMetrics);
  const [lastUpdated, setLastUpdated] = useState<string>(new Date().toLocaleString('zh-TW'));
  const [logs, setLogs] = useState<string[]>([
    '[2024-03-25 10:00:00] 系統已初始化',
    '[2024-03-25 10:00:05] IDS 監控已啟動',
    '[2024-03-25 10:00:10] 基準線已建立',
  ]);
  const [chartSeries, setChartSeries] = useState<ChartSeries>(defaultChartSeries);
  const [artifacts, setArtifacts] = useState<ArtifactsData>(defaultArtifacts);
  const [sampledRecordsPreview, setSampledRecordsPreview] = useState<SampleRecord[]>([]);
  const [isRunning, setIsRunning] = useState(false);
  const [sampleSize, setSampleSize] = useState<number>(500);
  const [seed, setSeed] = useState<number>(42);
  const [randomSeedEachRun, setRandomSeedEachRun] = useState<boolean>(false);
  const [selectedCipherPath, setSelectedCipherPath] = useState<string>('');
  const [hexView, setHexView] = useState<HexViewPayload | null>(null);
  const [hexPageBytes, setHexPageBytes] = useState<number>(512);
  const [hexLoading, setHexLoading] = useState<boolean>(false);
  const [executionHistory, setExecutionHistory] = useState<ExecutionRecord[]>([]);
  const [recordIdCounter, setRecordIdCounter] = useState(1);

  const appendLog = (line: string) => {
    setLogs((prev: string[]) => [...prev.slice(-9), line]);
  };

  const loadLatestResults = async () => {
    const res = await fetch('/api/results?mode=mixed');
    if (!res.ok) {
      return;
    }
    const payload: ApiPayload = await res.json();
    setMetrics(toMetricData(payload));
    setChartSeries(toChartSeries(payload));
    setArtifacts(toArtifacts(payload));
    setSampledRecordsPreview(payload.sampledRecordsPreview ?? []);
    setLastUpdated(new Date().toLocaleString('zh-TW'));
  };

  useEffect(() => {
    void loadLatestResults();
  }, []);

  useEffect(() => {
    if (!artifacts.encryptedCiphertextFiles.length) {
      setSelectedCipherPath('');
      setHexView(null);
      return;
    }
    const exists = artifacts.encryptedCiphertextFiles.some((f) => f.path === selectedCipherPath);
    if (!exists) {
      setSelectedCipherPath(artifacts.encryptedCiphertextFiles[0].path);
    }
  }, [artifacts.encryptedCiphertextFiles, selectedCipherPath]);

  const loadHexPage = async (offset = 0) => {
    if (!selectedCipherPath) {
      setHexView(null);
      return;
    }
    setHexLoading(true);
    try {
      const params = new URLSearchParams({
        path: selectedCipherPath,
        offset: String(Math.max(0, offset)),
        length: String(Math.max(64, Math.min(4096, hexPageBytes))),
      });
      const res = await fetch(`/api/ciphertext/hex?${params.toString()}`);
      const payload = (await res.json()) as HexViewPayload & { error?: string };
      if (!res.ok) {
        throw new Error(payload.error ?? '載入密文 Hex 失敗');
      }
      setHexView(payload);
    } catch (err) {
      const message = err instanceof Error ? err.message : '未知錯誤';
      appendLog(`[Hex Viewer] ${message}`);
      setHexView(null);
    } finally {
      setHexLoading(false);
    }
  };

  useEffect(() => {
    if (!selectedCipherPath) {
      return;
    }
    void loadHexPage(0);
  }, [selectedCipherPath, hexPageBytes]);

  const handleRunBackendAnalysis = async () => {
    setIsRunning(true);

    const timestamp = new Date().toLocaleString('zh-TW', {
      year: 'numeric',
      month: '2-digit',
      day: '2-digit',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
      hour12: false,
    });

    appendLog(`[${timestamp}] 開始執行後端分析...`);

    try {
      const effectiveSeed = randomSeedEachRun ? Math.floor(Math.random() * 1_000_000_000) : seed;
      const res = await fetch('/api/run', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          inferenceMode: 'mixed',
          seed: effectiveSeed,
          runPrivacySweep: true,
          sampleSize,
        }),
      });

      const payload: ApiPayload = await res.json();
      if (!res.ok) {
        const summary = payload.errorSummary ?? '後端執行失敗';
        const detail = payload.error ?? '';
        const errText = [summary, detail].filter((v, i, arr) => v && arr.indexOf(v) === i).join(': ');
        throw new Error(errText || '後端執行失敗');
      }

      const newMetrics = toMetricData(payload);
      const newChartSeries = toChartSeries(payload);
      const newArtifacts = toArtifacts(payload);
      const newSampledRecordsPreview = payload.sampledRecordsPreview ?? [];
      setMetrics(newMetrics);
      setChartSeries(newChartSeries);
      setArtifacts(newArtifacts);
      setSampledRecordsPreview(newSampledRecordsPreview);
      setLastUpdated(new Date().toLocaleString('zh-TW'));

      const newRecord: ExecutionRecord = {
        id: recordIdCounter,
        timestamp: new Date().toLocaleString('zh-TW'),
        metrics: newMetrics,
        chartSeries: newChartSeries,
        sampledRecordsPreview: newSampledRecordsPreview,
        artifacts: newArtifacts,
      };
      setExecutionHistory((prev: ExecutionRecord[]) => [newRecord, ...prev]);
      setRecordIdCounter((prev: number) => prev + 1);

      appendLog(`[${timestamp}] 後端分析完成`);
      appendLog(`[${timestamp}] 已重跑完整流程並重新生成隱私比例圖表`);
      appendLog(`[${timestamp}] sample_size=${sampleSize}`);
      appendLog(`[${timestamp}] seed=${effectiveSeed}${randomSeedEachRun ? ' (random)' : ''}`);
      appendLog(
        `[${timestamp}] 圖表已更新 - Accuracy: ${(newMetrics.accuracy * 100).toFixed(2)}%, Latency: ${newMetrics.latencySec.toFixed(4)}s`
      );

      if (payload.stdout) {
        payload.stdout
          .split(/\r?\n/)
          .map((line) => line.trim())
          .filter((line) => line.length > 0)
          .forEach((line) => appendLog(`[main] ${line}`));
      }
    } catch (err) {
      const message = err instanceof Error ? err.message : '未知錯誤';
      appendLog(`[${timestamp}] 後端執行失敗: ${message}`);

      try {
        const res = await fetch('/api/health');
        const health = (await res.json()) as { build?: string };
        if (!health.build) {
          appendLog(`[${timestamp}] 偵測到舊版後端，請重啟 backend_api.py 以載入最新修正`);
        }
      } catch {
        appendLog(`[${timestamp}] 無法取得後端版本資訊，請確認服務是否正常`);
      }
    } finally {
      setIsRunning(false);
    }
  };

  return (
    <div className="min-h-screen bg-gray-50">
      <header className="bg-white border-b border-gray-200">
        <div className="max-w-7xl mx-auto px-6 py-4">
          <div className="flex items-center justify-between">
            <h1 className="text-2xl font-semibold text-gray-900">IDS 監控儀表板</h1>
            <div className="flex gap-3">
              <div className="flex items-center gap-2">
                <label htmlFor="sample-size" className="text-sm text-gray-600">Sample Size</label>
                <input
                  id="sample-size"
                  type="number"
                  min={1}
                  step={1}
                  value={sampleSize}
                  onChange={(e) => setSampleSize(Math.max(1, Number(e.target.value || 1)))}
                  className="w-28 rounded border border-gray-300 px-2 py-1 text-sm"
                />
              </div>
              <div className="flex items-center gap-2">
                <label htmlFor="seed" className="text-sm text-gray-600">Seed</label>
                <input
                  id="seed"
                  type="number"
                  step={1}
                  value={seed}
                  onChange={(e) => setSeed(Number(e.target.value || 0))}
                  disabled={randomSeedEachRun}
                  className="w-28 rounded border border-gray-300 px-2 py-1 text-sm disabled:bg-gray-100"
                />
              </div>
              <label className="flex items-center gap-2 text-sm text-gray-600">
                <input
                  type="checkbox"
                  checked={randomSeedEachRun}
                  onChange={(e) => setRandomSeedEachRun(e.target.checked)}
                />
                每次隨機 Seed
              </label>
              <button
                onClick={handleRunBackendAnalysis}
                disabled={isRunning}
                className="px-4 py-2 bg-green-600 text-white rounded hover:bg-green-700 transition-colors disabled:bg-gray-400 disabled:cursor-not-allowed inline-flex items-center gap-2"
              >
                <Play className="w-4 h-4" />
                {isRunning ? '執行中...' : '執行後端分析'}
              </button>
            </div>
          </div>
          <div className="mt-2 text-sm text-gray-600">最後更新時間: {lastUpdated}</div>
        </div>
      </header>

      <main className="max-w-7xl mx-auto px-6 py-6">
        <Tabs defaultValue="dashboard" className="w-full">
          <TabsList className="mb-4">
            <TabsTrigger value="dashboard">儀表板</TabsTrigger>
            <TabsTrigger value="history">
              <History className="w-4 h-4 mr-2" />
              執行紀錄
            </TabsTrigger>
            <TabsTrigger value="artifacts">抽樣與密文資料</TabsTrigger>
            <TabsTrigger value="ciphertext">密文 Hex Viewer</TabsTrigger>
          </TabsList>

          <TabsContent value="dashboard">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-6">
              <MetricCard
                title="準確率 (Accuracy)"
                value={(metrics.accuracy * 100).toFixed(2)}
                unit="%"
                tooltipUnit="%"
                status={getStatus('accuracy', metrics.accuracy)}
                chartData={chartSeries.accuracy}
              />

              <MetricCard
                title="延遲 (Latency)"
                value={metrics.latencySec.toFixed(4)}
                unit=" sec"
                tooltipUnit=" sec"
                status={getStatus('latencySec', metrics.latencySec)}
                chartData={chartSeries.latency}
              />

              <MetricCard
                title="偵測效率 (Detection Efficiency)"
                value={metrics.detectionEfficiency.toExponential(3)}
                status={getStatus('detectionEfficiency', metrics.detectionEfficiency)}
                chartData={chartSeries.detectionEfficiency}
              />

              <MetricCard
                title="資訊洩漏 (Information Leakage, kb)"
                value={metrics.infoLeakage.toFixed(3)}
                unit=" kb"
                tooltipUnit=" kb"
                status={getStatus('infoLeakage', metrics.infoLeakage)}
                chartData={chartSeries.infoLeakage}
              />
            </div>

            <div className="bg-white border border-gray-200 rounded p-4">
              <h2 className="text-base font-medium text-gray-900 mb-3">系統日誌</h2>
              <div className="bg-gray-50 border border-gray-200 rounded p-3 h-40 overflow-y-auto">
                <div className="font-mono text-xs text-gray-700 space-y-1">
                  {logs.map((log, index) => (
                    <div key={index}>{log}</div>
                  ))}
                </div>
              </div>
            </div>

          </TabsContent>

          <TabsContent value="artifacts">
            <div className="bg-white border border-gray-200 rounded p-4 mt-1">
              <h2 className="text-base font-medium text-gray-900 mb-3">當次抽樣資料與密文檔</h2>
              <div className="text-sm text-gray-700 space-y-1 mb-4">
                <div>抽樣明文資料: {artifacts.sampledPlainDataPath || '尚未產生'}</div>
                <div>密文索引檔: {artifacts.encryptedPayloadIndexPath || '尚未產生'}</div>
                <div>密文資料夾: {artifacts.encryptedCiphertextDir || '尚未產生'}</div>
                <div>密文檔總數: {artifacts.encryptedCiphertextFileCount}</div>
                <div className="text-gray-500">註: 此密文檔數量為「本次主流程推論」產物，非 10%-90% 掃描各比例總和。</div>
                <div>資料來源: {artifacts.datasetPath || '未知'}</div>
              </div>

              <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                <div>
                  <h3 className="font-medium text-gray-800 mb-2">抽樣明文預覽（含預先敏感標記）</h3>
                  <div className="max-h-64 overflow-auto border border-gray-200 rounded">
                    <table className="w-full text-xs">
                      <thead className="bg-gray-50 sticky top-0">
                        <tr>
                          <th className="text-left px-2 py-1">idx</th>
                          <th className="text-left px-2 py-1">預先標記</th>
                          <th className="text-left px-2 py-1">anomaly</th>
                          <th className="text-left px-2 py-1">user_id</th>
                        </tr>
                      </thead>
                      <tbody>
                        {sampledRecordsPreview.map((r) => (
                          <tr key={r.sample_idx} className="border-t border-gray-100">
                            <td className="px-2 py-1">{r.sample_idx}</td>
                            <td className={`px-2 py-1 ${r.pre_sensitive_label === '敏感' ? 'text-red-700 font-medium' : 'text-green-700'}`}>
                              {r.pre_sensitive_label}
                            </td>
                            <td className="px-2 py-1">{r.anomaly}</td>
                            <td className="px-2 py-1">{r.user_id ?? '-'}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>

                <div>
                  <h3 className="font-medium text-gray-800 mb-2">密文檔清單（前200筆）</h3>
                  <div className="max-h-64 overflow-auto border border-gray-200 rounded p-2 text-xs font-mono text-gray-700 space-y-1">
                    {artifacts.encryptedCiphertextFiles.map((f) => (
                      <div key={f.path}>{f.name} ({f.bytes} bytes)</div>
                    ))}
                    {artifacts.encryptedCiphertextFiles.length === 0 && <div>尚無密文檔資料</div>}
                  </div>
                </div>
              </div>
            </div>
          </TabsContent>

          <TabsContent value="ciphertext">
            <div className="bg-white border border-gray-200 rounded p-4 space-y-4">
              <h2 className="text-base font-medium text-gray-900">密文 16 進位分頁檢視</h2>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="space-y-2">
                  <label className="text-sm text-gray-700">密文檔案</label>
                  <select
                    value={selectedCipherPath}
                    onChange={(e) => setSelectedCipherPath(e.target.value)}
                    className="w-full rounded border border-gray-300 px-2 py-1 text-sm"
                  >
                    {artifacts.encryptedCiphertextFiles.length === 0 && <option value="">尚無密文檔</option>}
                    {artifacts.encryptedCiphertextFiles.map((f) => (
                      <option key={f.path} value={f.path}>
                        {f.name} ({f.bytes} bytes)
                      </option>
                    ))}
                  </select>
                </div>

                <div className="space-y-2">
                  <label className="text-sm text-gray-700">每頁位元組數</label>
                  <input
                    type="number"
                    min={64}
                    max={4096}
                    step={64}
                    value={hexPageBytes}
                    onChange={(e) => setHexPageBytes(Math.max(64, Math.min(4096, Number(e.target.value || 512))))}
                    className="w-full rounded border border-gray-300 px-2 py-1 text-sm"
                  />
                </div>
              </div>

              <div className="flex items-center gap-2">
                <button
                  type="button"
                  className="px-3 py-1 rounded border border-gray-300 text-sm disabled:bg-gray-100"
                  disabled={!hexView?.hasPrev || hexLoading}
                  onClick={() => void loadHexPage(hexView?.prevOffset ?? 0)}
                >
                  上一頁
                </button>
                <button
                  type="button"
                  className="px-3 py-1 rounded border border-gray-300 text-sm disabled:bg-gray-100"
                  disabled={!hexView?.hasNext || hexLoading}
                  onClick={() => void loadHexPage(hexView?.nextOffset ?? 0)}
                >
                  下一頁
                </button>
                <button
                  type="button"
                  className="px-3 py-1 rounded border border-gray-300 text-sm disabled:bg-gray-100"
                  disabled={!selectedCipherPath || hexLoading}
                  onClick={() => void loadHexPage(hexView?.offset ?? 0)}
                >
                  重新載入
                </button>
              </div>

              <div className="text-xs text-gray-600">
                {hexView
                  ? `檔案: ${hexView.path} | offset=${hexView.offset} | 顯示=${hexView.length} bytes | 總大小=${hexView.totalBytes} bytes`
                  : '尚未選擇密文檔案'}
              </div>

              <pre className="bg-gray-900 text-gray-100 rounded p-3 overflow-auto max-h-[480px] text-xs leading-5">
                {hexLoading ? '載入中...' : hexView?.hexDump || '無資料'}
              </pre>
            </div>
          </TabsContent>

          <TabsContent value="history">
            <div className="bg-white border border-gray-200 rounded p-4">
              <h2 className="text-base font-medium text-gray-900 mb-4">執行紀錄</h2>

              {executionHistory.length === 0 ? (
                <div className="text-center py-12 text-gray-400">
                  <History className="w-12 h-12 mx-auto mb-3" />
                  <p>尚無執行紀錄</p>
                  <p className="text-sm mt-1">執行後端分析以建立紀錄</p>
                </div>
              ) : (
                <div className="space-y-6">
                  {executionHistory.map((record) => (
                    <div key={record.id} className="border border-gray-200 rounded p-4">
                      <div className="flex items-center justify-between mb-4">
                        <h3 className="font-medium text-gray-900">執行 #{record.id}</h3>
                        <span className="text-sm text-gray-600">{record.timestamp}</span>
                      </div>

                      <div className="mb-4">
                        <table className="w-full text-sm">
                          <thead className="bg-gray-50">
                            <tr>
                              <th className="text-left py-2 px-3 font-medium text-gray-700">指標</th>
                              <th className="text-left py-2 px-3 font-medium text-gray-700">數值</th>
                              <th className="text-left py-2 px-3 font-medium text-gray-700">狀態</th>
                            </tr>
                          </thead>
                          <tbody className="divide-y divide-gray-200">
                            <tr>
                              <td className="py-2 px-3">準確率</td>
                              <td className="py-2 px-3">{(record.metrics.accuracy * 100).toFixed(2)}%</td>
                              <td className="py-2 px-3">
                                <span className={`px-2 py-1 rounded text-xs ${
                                  getStatus('accuracy', record.metrics.accuracy) === '正常'
                                    ? 'bg-green-100 text-green-800'
                                    : getStatus('accuracy', record.metrics.accuracy) === '警告'
                                      ? 'bg-yellow-100 text-yellow-800'
                                      : 'bg-red-100 text-red-800'
                                }`}>
                                  {getStatus('accuracy', record.metrics.accuracy)}
                                </span>
                              </td>
                            </tr>
                            <tr>
                              <td className="py-2 px-3">延遲</td>
                              <td className="py-2 px-3">{record.metrics.latencySec.toFixed(4)} sec</td>
                              <td className="py-2 px-3">
                                <span className={`px-2 py-1 rounded text-xs ${
                                  getStatus('latencySec', record.metrics.latencySec) === '正常'
                                    ? 'bg-green-100 text-green-800'
                                    : getStatus('latencySec', record.metrics.latencySec) === '警告'
                                      ? 'bg-yellow-100 text-yellow-800'
                                      : 'bg-red-100 text-red-800'
                                }`}>
                                  {getStatus('latencySec', record.metrics.latencySec)}
                                </span>
                              </td>
                            </tr>
                            <tr>
                              <td className="py-2 px-3">偵測效率</td>
                              <td className="py-2 px-3">{record.metrics.detectionEfficiency.toExponential(3)}</td>
                              <td className="py-2 px-3">
                                <span className={`px-2 py-1 rounded text-xs ${
                                  getStatus('detectionEfficiency', record.metrics.detectionEfficiency) === '正常'
                                    ? 'bg-green-100 text-green-800'
                                    : getStatus('detectionEfficiency', record.metrics.detectionEfficiency) === '警告'
                                      ? 'bg-yellow-100 text-yellow-800'
                                      : 'bg-red-100 text-red-800'
                                }`}>
                                  {getStatus('detectionEfficiency', record.metrics.detectionEfficiency)}
                                </span>
                              </td>
                            </tr>
                            <tr>
                              <td className="py-2 px-3">資訊洩漏 (kb)</td>
                              <td className="py-2 px-3">{record.metrics.infoLeakage.toFixed(3)} kb</td>
                              <td className="py-2 px-3">
                                <span className={`px-2 py-1 rounded text-xs ${
                                  getStatus('infoLeakage', record.metrics.infoLeakage) === '正常'
                                    ? 'bg-green-100 text-green-800'
                                    : getStatus('infoLeakage', record.metrics.infoLeakage) === '警告'
                                      ? 'bg-yellow-100 text-yellow-800'
                                      : 'bg-red-100 text-red-800'
                                }`}>
                                  {getStatus('infoLeakage', record.metrics.infoLeakage)}
                                </span>
                              </td>
                            </tr>
                          </tbody>
                        </table>
                      </div>

                      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                        <div className="border border-gray-200 rounded p-2">
                          <p className="text-xs text-gray-600 mb-1">準確率</p>
                          <MetricCard title="" value="" status="正常" chartData={record.chartSeries.accuracy} compact />
                        </div>
                        <div className="border border-gray-200 rounded p-2">
                          <p className="text-xs text-gray-600 mb-1">延遲</p>
                          <MetricCard title="" value="" status="正常" chartData={record.chartSeries.latency} compact />
                        </div>
                        <div className="border border-gray-200 rounded p-2">
                          <p className="text-xs text-gray-600 mb-1">偵測效率</p>
                          <MetricCard title="" value="" status="正常" chartData={record.chartSeries.detectionEfficiency} compact />
                        </div>
                        <div className="border border-gray-200 rounded p-2">
                          <p className="text-xs text-gray-600 mb-1">資訊洩漏 (kb)</p>
                          <MetricCard title="" value="" status="正常" chartData={record.chartSeries.infoLeakage} tooltipUnit=" kb" compact />
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </TabsContent>
        </Tabs>
      </main>
    </div>
  );
}
