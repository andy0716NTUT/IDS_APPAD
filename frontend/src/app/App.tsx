import { useEffect, useState } from 'react';
import { MetricCard } from './components/MetricCard';
import { Play, History, BarChart3, GitCompareArrows, Server, Shield, Zap, Eye, Lock, Unlock, ArrowRight, CheckCircle, AlertTriangle, ShieldCheck, Loader2 } from 'lucide-react';
import { Tabs, TabsContent, TabsList, TabsTrigger } from './components/ui/tabs';
import {
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, Legend,
  ResponsiveContainer, RadarChart, PolarGrid, PolarAngleAxis,
  PolarRadiusAxis, Radar, PieChart, Pie, Cell,
} from 'recharts';

/* ------------------------------------------------------------------ */
/* Types                                                               */
/* ------------------------------------------------------------------ */

interface ChartPoint { ratio: number; value: number }

interface MetricData {
  accuracy: number;
  latencySec: number;
  detectionEfficiency: number;
  infoLeakage: number;
  precision: number;
  recall: number;
  f1: number;
  unencryptedSensitiveRatio: number;
}

interface TrafficBreakdown {
  plaintextBytes: number;
  ciphertextBytes: number;
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
  mode: string;
  metrics: MetricData;
  chartSeries: ChartSeries;
  traffic: TrafficBreakdown;
}

interface ApiPayload {
  mode?: string;
  metrics?: {
    metrics?: {
      accuracy?: number;
      information_leakage?: number;
      detection_efficiency?: number;
      precision?: number;
      recall?: number;
      f1?: number;
      unencrypted_sensitive_ratio?: number;
    };
    latency_sec?: { avg?: number };
    traffic_breakdown_bytes?: {
      plaintext_nonsensitive?: number;
      ciphertext_sensitive?: number;
    };
  };
  chartSeries?: {
    accuracy?: ChartPoint[];
    latency?: ChartPoint[];
    informationLeakage?: ChartPoint[];
    detectionEfficiency?: ChartPoint[];
  };
  stdout?: string;
  error?: string;
}

interface DemoStep {
  id: number;
  name: string;
  description: string;
  data: Record<string, any>;
  duration_ms: number;
}

interface DemoResult {
  steps: DemoStep[];
  summary: {
    mode: string;
    total_ms: number;
    enable_he: boolean;
    sensitivity_level: string;
    is_anomaly: boolean;
    probability: number;
    inference_location: string;
  };
}

/* ------------------------------------------------------------------ */
/* Defaults                                                            */
/* ------------------------------------------------------------------ */

const defaultMetrics: MetricData = {
  accuracy: 0, latencySec: 0, detectionEfficiency: 0, infoLeakage: 0,
  precision: 0, recall: 0, f1: 0, unencryptedSensitiveRatio: 0,
};

const defaultChartSeries: ChartSeries = {
  accuracy: [], latency: [], detectionEfficiency: [], infoLeakage: [],
};

const defaultTraffic: TrafficBreakdown = { plaintextBytes: 0, ciphertextBytes: 0 };

/* ------------------------------------------------------------------ */
/* Helpers                                                             */
/* ------------------------------------------------------------------ */

function toMetricData(p: ApiPayload): MetricData {
  const m = p.metrics?.metrics;
  return {
    accuracy: Number(m?.accuracy ?? 0),
    latencySec: Number(p.metrics?.latency_sec?.avg ?? 0),
    detectionEfficiency: Number(m?.detection_efficiency ?? 0),
    infoLeakage: Number(m?.information_leakage ?? 0),
    precision: Number(m?.precision ?? 0),
    recall: Number(m?.recall ?? 0),
    f1: Number(m?.f1 ?? 0),
    unencryptedSensitiveRatio: Number(m?.unencrypted_sensitive_ratio ?? 0),
  };
}

function toTraffic(p: ApiPayload): TrafficBreakdown {
  const t = p.metrics?.traffic_breakdown_bytes;
  return {
    plaintextBytes: Number(t?.plaintext_nonsensitive ?? 0),
    ciphertextBytes: Number(t?.ciphertext_sensitive ?? 0),
  };
}

function toChartSeries(p: ApiPayload): ChartSeries {
  const c = p.chartSeries;
  return {
    accuracy: c?.accuracy ?? [],
    latency: c?.latency ?? [],
    detectionEfficiency: c?.detectionEfficiency ?? [],
    infoLeakage: c?.informationLeakage ?? [],
  };
}

function getStatus(metric: string, value: number): '正常' | '警告' | '危險' {
  if (metric === 'accuracy') return value >= 0.9 ? '正常' : value >= 0.8 ? '警告' : '危險';
  if (metric === 'latencySec') return value <= 0.5 ? '正常' : value <= 1.5 ? '警告' : '危險';
  if (metric === 'detectionEfficiency') return value >= 0.5 ? '正常' : value >= 0.1 ? '警告' : '危險';
  if (metric === 'infoLeakage') return value <= 300 ? '正常' : value <= 500 ? '警告' : '危險';
  return '正常';
}

const MODE_LABELS: Record<string, string> = {
  plaintext: 'Plaintext (明文)',
  mixed: 'Mixed (混合)',
  ckks: 'CKKS (全加密)',
};

const MODE_COLORS: Record<string, string> = {
  plaintext: '#3b82f6',
  mixed: '#10b981',
  ckks: '#8b5cf6',
};

const STATUS_STYLE: Record<string, string> = {
  '正常': 'bg-green-100 text-green-800',
  '警告': 'bg-yellow-100 text-yellow-800',
  '危險': 'bg-red-100 text-red-800',
};

const PIE_COLORS = ['#3b82f6', '#f59e0b'];

/* ------------------------------------------------------------------ */
/* Component                                                           */
/* ------------------------------------------------------------------ */

export default function App() {
  const [metrics, setMetrics] = useState<MetricData>(defaultMetrics);
  const [lastUpdated, setLastUpdated] = useState<string>(new Date().toLocaleString('zh-TW'));
  const [logs, setLogs] = useState<string[]>([
    '[系統] 已初始化',
    '[系統] IDS 監控已啟動',
  ]);
  const [chartSeries, setChartSeries] = useState<ChartSeries>(defaultChartSeries);
  const [traffic, setTraffic] = useState<TrafficBreakdown>(defaultTraffic);
  const [isRunning, setIsRunning] = useState(false);
  const [executionHistory, setExecutionHistory] = useState<ExecutionRecord[]>([]);
  const [recordIdCounter, setRecordIdCounter] = useState(1);

  /* -- Run controls -- */
  const [selectedMode, setSelectedMode] = useState<string>('mixed');
  const [seed, setSeed] = useState<number>(42);
  const [runSweep, setRunSweep] = useState(true);

  /* -- Mode comparison -- */
  const [compareResults, setCompareResults] = useState<Record<string, MetricData>>({});
  const [compareTraffic, setCompareTraffic] = useState<Record<string, TrafficBreakdown>>({});
  const [isComparing, setIsComparing] = useState(false);
  const [compareProgress, setCompareProgress] = useState('');

  /* -- Server info -- */
  const [serverUrl, setServerUrl] = useState<string | null>(null);
  const [serverMode, setServerMode] = useState<string>('local');

  /* -- Demo visualization -- */
  const [demoResult, setDemoResult] = useState<DemoResult | null>(null);
  const [isDemoRunning, setIsDemoRunning] = useState(false);
  const [demoMode, setDemoMode] = useState<string>('mixed');
  const [activeStep, setActiveStep] = useState<number>(0);
  const [animating, setAnimating] = useState(false);

  const appendLog = (line: string) => setLogs(prev => [...prev.slice(-14), line]);
  const ts = () => new Date().toLocaleString('zh-TW', {
    year: 'numeric', month: '2-digit', day: '2-digit',
    hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false,
  });

  /* ---- Load server info + initial data ---- */
  const loadServerInfo = async () => {
    try {
      const res = await fetch('/api/server-info');
      if (res.ok) {
        const info = await res.json();
        setServerUrl(info.serverUrl);
        setServerMode(info.mode);
        if (info.serverUrl) {
          appendLog(`[系統] 遠端推論伺服器: ${info.serverUrl}`);
        }
      }
    } catch { /* ignore */ }
  };

  const loadLatestResults = async () => {
    try {
      const res = await fetch('/api/results?mode=mixed');
      if (!res.ok) return;
      const payload: ApiPayload = await res.json();
      setMetrics(toMetricData(payload));
      setChartSeries(toChartSeries(payload));
      setTraffic(toTraffic(payload));
      setLastUpdated(new Date().toLocaleString('zh-TW'));
    } catch { /* ignore */ }
  };
  useEffect(() => { void loadServerInfo(); void loadLatestResults(); }, []);

  /* ---- Single-mode run ---- */
  const handleRun = async () => {
    setIsRunning(true);
    appendLog(`[${ts()}] 開始執行 ${MODE_LABELS[selectedMode]} 分析...`);

    try {
      const res = await fetch('/api/run', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ inferenceMode: selectedMode, seed, runPrivacySweep: runSweep }),
      });
      const payload: ApiPayload = await res.json();
      if (!res.ok) throw new Error(payload.error ?? '後端執行失敗');

      const newMetrics = toMetricData(payload);
      const newChartSeries = toChartSeries(payload);
      const newTraffic = toTraffic(payload);
      setMetrics(newMetrics);
      setChartSeries(newChartSeries);
      setTraffic(newTraffic);
      setLastUpdated(new Date().toLocaleString('zh-TW'));

      setExecutionHistory(prev => [{
        id: recordIdCounter, timestamp: new Date().toLocaleString('zh-TW'),
        mode: selectedMode, metrics: newMetrics, chartSeries: newChartSeries, traffic: newTraffic,
      }, ...prev]);
      setRecordIdCounter(prev => prev + 1);

      appendLog(`[${ts()}] ${MODE_LABELS[selectedMode]} 分析完成 — Accuracy: ${(newMetrics.accuracy * 100).toFixed(2)}%`);
      if (payload.stdout) {
        payload.stdout.split(/\r?\n/).filter(l => l.trim()).forEach(l => appendLog(`[main] ${l.trim()}`));
      }
    } catch (err) {
      appendLog(`[${ts()}] 執行失敗: ${err instanceof Error ? err.message : '未知錯誤'}`);
    } finally {
      setIsRunning(false);
    }
  };

  /* ---- Three-mode comparison ---- */
  const handleCompareAll = async () => {
    setIsComparing(true);
    const results: Record<string, MetricData> = {};
    const traffics: Record<string, TrafficBreakdown> = {};
    for (const mode of ['plaintext', 'mixed', 'ckks']) {
      setCompareProgress(`正在執行 ${MODE_LABELS[mode]}...`);
      appendLog(`[${ts()}] 三模式比較: 執行 ${MODE_LABELS[mode]}...`);
      try {
        const res = await fetch('/api/run', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ inferenceMode: mode, seed, runPrivacySweep: false }),
        });
        const payload: ApiPayload = await res.json();
        if (!res.ok) throw new Error(payload.error ?? `${mode} 執行失敗`);
        results[mode] = toMetricData(payload);
        traffics[mode] = toTraffic(payload);
      } catch (err) {
        appendLog(`[${ts()}] ${mode} 失敗: ${err instanceof Error ? err.message : '未知錯誤'}`);
      }
    }
    setCompareResults(results);
    setCompareTraffic(traffics);
    setCompareProgress('');
    setIsComparing(false);
    appendLog(`[${ts()}] 三模式比較完成`);
  };

  /* ---- Demo: single-record visualization ---- */
  const handleDemo = async () => {
    setIsDemoRunning(true);
    setDemoResult(null);
    setActiveStep(0);
    setAnimating(true);
    try {
      const res = await fetch('/api/demo', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ inferenceMode: demoMode, seed: Math.floor(Math.random() * 10000) }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error ?? 'Demo failed');
      setDemoResult(data);
      // Animate steps one by one
      for (let i = 0; i < data.steps.length; i++) {
        await new Promise(r => setTimeout(r, 600));
        setActiveStep(i + 1);
      }
    } catch (err) {
      appendLog(`[${ts()}] Demo 失敗: ${err instanceof Error ? err.message : '未知錯誤'}`);
    } finally {
      setIsDemoRunning(false);
      setAnimating(false);
    }
  };

  /* ---- Hex viewer (from hex viewer branch) ---- */
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

  /* ---- Derived data for comparison charts ---- */
  const comparisonBarData = Object.keys(compareResults).length > 0 ? ['plaintext', 'mixed', 'ckks']
    .filter(m => compareResults[m])
    .map(m => ({
      mode: MODE_LABELS[m],
      '準確率': +(compareResults[m].accuracy * 100).toFixed(2),
      '延遲 (ms)': +(compareResults[m].latencySec * 1000).toFixed(2),
      'F1 Score': +(compareResults[m].f1 * 100).toFixed(2),
    })) : [];

  const comparisonTrafficData = Object.keys(compareTraffic).length > 0 ? ['plaintext', 'mixed', 'ckks']
    .filter(m => compareTraffic[m])
    .map(m => ({
      mode: MODE_LABELS[m],
      '明文 (bytes)': compareTraffic[m].plaintextBytes,
      '密文 (bytes)': compareTraffic[m].ciphertextBytes,
    })) : [];

  const radarData = Object.keys(compareResults).length > 0 ? [
    { metric: 'Accuracy', ...Object.fromEntries(['plaintext', 'mixed', 'ckks'].filter(m => compareResults[m]).map(m => [m, compareResults[m].accuracy * 100])) },
    { metric: 'Precision', ...Object.fromEntries(['plaintext', 'mixed', 'ckks'].filter(m => compareResults[m]).map(m => [m, compareResults[m].precision * 100])) },
    { metric: 'Recall', ...Object.fromEntries(['plaintext', 'mixed', 'ckks'].filter(m => compareResults[m]).map(m => [m, compareResults[m].recall * 100])) },
    { metric: 'F1', ...Object.fromEntries(['plaintext', 'mixed', 'ckks'].filter(m => compareResults[m]).map(m => [m, compareResults[m].f1 * 100])) },
  ] : [];

  const pieData = traffic.plaintextBytes + traffic.ciphertextBytes > 0
    ? [
        { name: '明文流量', value: traffic.plaintextBytes },
        { name: '密文流量', value: traffic.ciphertextBytes },
      ]
    : [];

  /* ---------------------------------------------------------------- */
  /* Render                                                            */
  /* ---------------------------------------------------------------- */

  return (
    <div className="min-h-screen bg-gray-50">
      {/* ---- Header ---- */}
      <header className="bg-white border-b border-gray-200">
        <div className="max-w-7xl mx-auto px-6 py-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <Shield className="w-7 h-7 text-blue-600" />
              <h1 className="text-2xl font-semibold text-gray-900">IDS 監控儀表板</h1>
            </div>
            <div className="flex items-center gap-4 mt-2 text-sm text-gray-500">
              <span>最後更新: {lastUpdated}</span>
              <span className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-xs font-medium ${
                serverMode === 'remote' ? 'bg-purple-100 text-purple-800' : 'bg-gray-100 text-gray-600'
              }`}>
                <span className={`w-2 h-2 rounded-full ${serverMode === 'remote' ? 'bg-purple-500' : 'bg-gray-400'}`} />
                {serverMode === 'remote' ? `遠端: ${serverUrl}` : '本地推論'}
              </span>
            </div>
          </div>
        </div>
      </header>

      <main className="max-w-7xl mx-auto px-6 py-6">
        <Tabs defaultValue="dashboard" className="w-full">
          <TabsList className="mb-4">
            <TabsTrigger value="dashboard">
              <Zap className="w-4 h-4 mr-1" /> 儀表板
            </TabsTrigger>
            <TabsTrigger value="demo">
              <Eye className="w-4 h-4 mr-1" /> 加密流程
            </TabsTrigger>
            <TabsTrigger value="compare">
              <GitCompareArrows className="w-4 h-4 mr-1" /> 模式比較
            </TabsTrigger>
            <TabsTrigger value="history">
              <History className="w-4 h-4 mr-1" /> 執行紀錄
            </TabsTrigger>
          </TabsList>

          {/* ================================================================ */}
          {/*  Dashboard Tab                                                    */}
          {/* ================================================================ */}
          <TabsContent value="dashboard">
            {/* -- Control Panel -- */}
            <div className="bg-white border border-gray-200 rounded p-4 mb-6">
              <h2 className="text-base font-medium text-gray-900 mb-3 flex items-center gap-2">
                <Server className="w-4 h-4" /> 執行控制
              </h2>
              <div className="flex flex-wrap items-end gap-4">
                <div>
                  <label className="block text-xs text-gray-600 mb-1">推論模式</label>
                  <select
                    value={selectedMode}
                    onChange={e => setSelectedMode(e.target.value)}
                    className="border border-gray-300 rounded px-3 py-2 text-sm bg-white"
                  >
                    <option value="plaintext">Plaintext (明文)</option>
                    <option value="mixed">Mixed (混合加密)</option>
                    <option value="ckks">CKKS (全加密)</option>
                  </select>
                </div>
                <div>
                  <label className="block text-xs text-gray-600 mb-1">隨機種子</label>
                  <input
                    type="number" value={seed} onChange={e => setSeed(Number(e.target.value))}
                    className="border border-gray-300 rounded px-3 py-2 text-sm w-24"
                  />
                </div>
                <div className="flex items-center gap-2">
                  <input type="checkbox" id="sweep" checked={runSweep} onChange={e => setRunSweep(e.target.checked)} />
                  <label htmlFor="sweep" className="text-sm text-gray-700">隱私比例掃描</label>
                </div>
                <button
                  onClick={handleRun}
                  disabled={isRunning || isComparing}
                  className="px-5 py-2 bg-blue-600 text-white rounded hover:bg-blue-700 transition-colors disabled:bg-gray-400 disabled:cursor-not-allowed inline-flex items-center gap-2 text-sm font-medium"
                >
                  <Play className="w-4 h-4" />
                  {isRunning ? '執行中...' : '執行分析'}
                </button>
              </div>
            </div>

            {/* -- Metric Cards (2x2) -- */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-6">
              <MetricCard title="準確率 (Accuracy)" value={(metrics.accuracy * 100).toFixed(2)} unit="%" tooltipUnit="%" status={getStatus('accuracy', metrics.accuracy)} chartData={chartSeries.accuracy} />
              <MetricCard title="延遲 (Latency)" value={metrics.latencySec.toFixed(4)} unit=" sec" tooltipUnit=" sec" status={getStatus('latencySec', metrics.latencySec)} chartData={chartSeries.latency} />
              <MetricCard title="偵測效率 (Detection Efficiency)" value={metrics.detectionEfficiency.toExponential(3)} status={getStatus('detectionEfficiency', metrics.detectionEfficiency)} chartData={chartSeries.detectionEfficiency} />
              <MetricCard title="資訊洩漏 (Information Leakage)" value={metrics.infoLeakage.toFixed(3)} unit=" kb" tooltipUnit=" kb" status={getStatus('infoLeakage', metrics.infoLeakage)} chartData={chartSeries.infoLeakage} />
            </div>

            {/* -- Extra metrics row -- */}
            <div className="grid grid-cols-2 md:grid-cols-5 gap-3 mb-6">
              {[
                { label: 'Precision', val: (metrics.precision * 100).toFixed(2) + '%' },
                { label: 'Recall', val: (metrics.recall * 100).toFixed(2) + '%' },
                { label: 'F1 Score', val: (metrics.f1 * 100).toFixed(2) + '%' },
                { label: '未加密敏感比例', val: (metrics.unencryptedSensitiveRatio * 100).toFixed(1) + '%' },
                { label: '流量結構', val: '' },
              ].map((item, i) => (
                <div key={i} className="bg-white border border-gray-200 rounded p-3">
                  <div className="text-xs text-gray-500 mb-1">{item.label}</div>
                  {i === 4 && pieData.length > 0 ? (
                    <div className="h-20">
                      <ResponsiveContainer width="100%" height="100%">
                        <PieChart>
                          <Pie data={pieData} dataKey="value" cx="50%" cy="50%" outerRadius={30} innerRadius={15}>
                            {pieData.map((_, idx) => <Cell key={idx} fill={PIE_COLORS[idx]} />)}
                          </Pie>
                          <Tooltip formatter={(v: number) => `${v.toLocaleString()} bytes`} />
                        </PieChart>
                      </ResponsiveContainer>
                    </div>
                  ) : i === 4 ? (
                    <div className="text-sm text-gray-400">無資料</div>
                  ) : (
                    <div className="text-lg font-semibold text-gray-900">{item.val}</div>
                  )}
                </div>
              ))}
            </div>

            {/* -- Logs -- */}
            <div className="bg-white border border-gray-200 rounded p-4">
              <h2 className="text-base font-medium text-gray-900 mb-3">系統日誌</h2>
              <div className="bg-gray-900 rounded p-3 h-44 overflow-y-auto">
                <div className="font-mono text-xs text-green-400 space-y-0.5">
                  {logs.map((log, i) => <div key={i}>{log}</div>)}
                </div>
              </div>
            </div>
          </TabsContent>

          {/* ================================================================ */}
          {/*  Demo / Encryption Flow Tab                                       */}
          {/* ================================================================ */}
          <TabsContent value="demo">
            {/* Control bar */}
            <div className="bg-white border border-gray-200 rounded p-4 mb-6">
              <div className="flex items-center justify-between mb-2">
                <h2 className="text-base font-medium text-gray-900 flex items-center gap-2">
                  <Eye className="w-5 h-5" /> 即時加密流程視覺化
                </h2>
                <div className="flex items-center gap-3">
                  <select value={demoMode} onChange={e => setDemoMode(e.target.value)}
                    className="border border-gray-300 rounded px-3 py-1.5 text-sm bg-white">
                    <option value="plaintext">Plaintext</option>
                    <option value="mixed">Mixed</option>
                    <option value="ckks">CKKS</option>
                  </select>
                  <button onClick={handleDemo} disabled={isDemoRunning}
                    className="px-4 py-1.5 bg-indigo-600 text-white rounded hover:bg-indigo-700 transition-colors disabled:bg-gray-400 disabled:cursor-not-allowed inline-flex items-center gap-2 text-sm font-medium">
                    {isDemoRunning ? <><Loader2 className="w-4 h-4 animate-spin" /> 處理中...</> : <><Play className="w-4 h-4" /> 執行 Demo</>}
                  </button>
                </div>
              </div>
              <p className="text-sm text-gray-500">隨機取一筆資料，完整展示 Client 加密 → Server 推論 → Client 解密決策的每個步驟。</p>
            </div>

            {demoResult ? (
              <>
                {/* Summary banner */}
                <div className={`rounded p-4 mb-6 flex items-center justify-between ${
                  demoResult.summary.is_anomaly ? 'bg-red-50 border border-red-200' : 'bg-green-50 border border-green-200'
                }`}>
                  <div className="flex items-center gap-3">
                    {demoResult.summary.is_anomaly
                      ? <AlertTriangle className="w-6 h-6 text-red-600" />
                      : <ShieldCheck className="w-6 h-6 text-green-600" />}
                    <div>
                      <div className={`text-lg font-semibold ${demoResult.summary.is_anomaly ? 'text-red-800' : 'text-green-800'}`}>
                        判定結果: {demoResult.summary.is_anomaly ? '異常' : '正常'}
                      </div>
                      <div className="text-sm text-gray-600">
                        機率: {(demoResult.summary.probability * 100).toFixed(2)}% | 模式: {MODE_LABELS[demoResult.summary.mode]} |
                        敏感度: {demoResult.summary.sensitivity_level} |
                        耗時: {demoResult.summary.total_ms.toFixed(1)}ms |
                        推論: {demoResult.summary.inference_location}
                      </div>
                    </div>
                  </div>
                </div>

                {/* Step-by-step flow */}
                <div className="space-y-0">
                  {demoResult.steps.map((step, idx) => {
                    const visible = activeStep > idx || !animating;
                    const stepIcons = [Shield, Eye, Lock, Lock, Server, Unlock];
                    const stepColors = ['blue', 'amber', 'purple', 'purple', 'indigo', 'green'];
                    const Icon = stepIcons[idx] || Shield;
                    const color = stepColors[idx] || 'gray';

                    return (
                      <div key={step.id}>
                        {/* Arrow connector */}
                        {idx > 0 && (
                          <div className="flex justify-center py-1">
                            <ArrowRight className={`w-5 h-5 rotate-90 transition-all duration-300 ${visible ? `text-${color}-400` : 'text-gray-200'}`} />
                          </div>
                        )}
                        <div className={`bg-white border rounded p-4 transition-all duration-500 ${
                          visible ? 'border-gray-300 opacity-100 translate-y-0' : 'border-gray-100 opacity-30 translate-y-2'
                        }`}>
                          <div className="flex items-start gap-3">
                            <div className={`w-10 h-10 rounded-lg flex items-center justify-center shrink-0 ${
                              color === 'blue' ? 'bg-blue-100 text-blue-600' :
                              color === 'amber' ? 'bg-amber-100 text-amber-600' :
                              color === 'purple' ? 'bg-purple-100 text-purple-600' :
                              color === 'indigo' ? 'bg-indigo-100 text-indigo-600' :
                              'bg-green-100 text-green-600'
                            }`}>
                              <Icon className="w-5 h-5" />
                            </div>
                            <div className="flex-1 min-w-0">
                              <div className="flex items-center justify-between mb-1">
                                <h3 className="font-medium text-gray-900">Step {step.id}: {step.name}</h3>
                                {step.duration_ms > 0 && (
                                  <span className="text-xs text-gray-400 bg-gray-100 px-2 py-0.5 rounded">{step.duration_ms.toFixed(1)} ms</span>
                                )}
                              </div>
                              <p className="text-sm text-gray-600 mb-3">{step.description}</p>

                              {/* Step 1: Original data table */}
                              {step.id === 1 && (
                                <div className="overflow-x-auto">
                                  <table className="w-full text-xs border-collapse">
                                    <thead><tr className="bg-gray-50">
                                      {Object.keys(step.data).map(k => <th key={k} className="py-1.5 px-2 text-left font-medium text-gray-600 border border-gray-200">{k}</th>)}
                                    </tr></thead>
                                    <tbody><tr>
                                      {Object.entries(step.data).map(([k, v]) => (
                                        <td key={k} className="py-1.5 px-2 border border-gray-200 font-mono">{typeof v === 'number' ? Number(v).toFixed(4) : String(v)}</td>
                                      ))}
                                    </tr></tbody>
                                  </table>
                                </div>
                              )}

                              {/* Step 2: Sensitivity */}
                              {step.id === 2 && (
                                <div className="flex flex-wrap gap-2">
                                  <span className={`px-3 py-1 rounded-full text-xs font-medium ${
                                    step.data.sensitivity_level === 'HIGH' ? 'bg-red-100 text-red-800' :
                                    step.data.sensitivity_level === 'MEDIUM' ? 'bg-yellow-100 text-yellow-800' :
                                    'bg-green-100 text-green-800'
                                  }`}>
                                    {step.data.sensitivity_level}
                                  </span>
                                  <span className="px-3 py-1 rounded-full text-xs bg-gray-100 text-gray-700">
                                    風險: {step.data.risk_score}
                                  </span>
                                  {step.data.encryption_required && (
                                    <span className="px-3 py-1 rounded-full text-xs bg-purple-100 text-purple-800 flex items-center gap-1">
                                      <Lock className="w-3 h-3" /> 需加密
                                    </span>
                                  )}
                                  {(step.data.reasons as string[]).map((r: string, i: number) => (
                                    <span key={i} className="px-3 py-1 rounded-full text-xs bg-blue-50 text-blue-700">{r}</span>
                                  ))}
                                </div>
                              )}

                              {/* Step 3: Field encryption decision — before/after comparison */}
                              {step.id === 3 && step.data.field_status && (
                                <div className="overflow-x-auto">
                                  <table className="w-full text-xs border-collapse">
                                    <thead><tr className="bg-gray-50">
                                      <th className="py-1.5 px-3 text-left font-medium text-gray-600 border border-gray-200">欄位名稱</th>
                                      <th className="py-1.5 px-3 text-left font-medium text-gray-600 border border-gray-200">狀態</th>
                                    </tr></thead>
                                    <tbody>
                                      {Object.entries(step.data.field_status as Record<string, string>).map(([field, status]) => (
                                        <tr key={field} className={
                                          status === 'encrypted' ? 'bg-purple-50' :
                                          status === 'sensitive_not_encrypted' ? 'bg-amber-50' : ''
                                        }>
                                          <td className="py-1.5 px-3 border border-gray-200 font-mono">{field}</td>
                                          <td className="py-1.5 px-3 border border-gray-200">
                                            {status === 'encrypted'
                                              ? <span className="inline-flex items-center gap-1 text-purple-700"><Lock className="w-3 h-3" /> 已加密</span>
                                              : status === 'sensitive_not_encrypted'
                                              ? <span className="inline-flex items-center gap-1 text-amber-700"><AlertTriangle className="w-3 h-3" /> 敏感但未加密</span>
                                              : <span className="inline-flex items-center gap-1 text-green-700"><Unlock className="w-3 h-3" /> 明文</span>}
                                          </td>
                                        </tr>
                                      ))}
                                    </tbody>
                                  </table>
                                </div>
                              )}

                              {/* Step 4: Before/after encryption comparison */}
                              {step.id === 4 && (
                                <div className="overflow-x-auto">
                                  <table className="w-full text-xs border-collapse">
                                    <thead><tr className="bg-gray-50">
                                      <th className="py-1.5 px-3 text-left font-medium text-gray-600 border border-gray-200">欄位</th>
                                      <th className="py-1.5 px-3 text-left font-medium text-gray-600 border border-gray-200">加密前 (原始值)</th>
                                      <th className="py-1.5 px-3 text-left font-medium text-gray-600 border border-gray-200">加密後 (傳輸值)</th>
                                    </tr></thead>
                                    <tbody>
                                      {(step.data.plain_fields as string[]).map((f: string) => (
                                        <tr key={f}>
                                          <td className="py-1.5 px-3 border border-gray-200 font-mono font-medium">{f}</td>
                                          <td className="py-1.5 px-3 border border-gray-200 font-mono text-gray-700">
                                            {step.data.plain_values?.[f] ?? '—'}
                                          </td>
                                          <td className="py-1.5 px-3 border border-gray-200 font-mono text-gray-700">
                                            <span className="inline-flex items-center gap-1 text-green-600">
                                              <Unlock className="w-3 h-3" /> {step.data.plain_values?.[f] ?? '—'}
                                            </span>
                                          </td>
                                        </tr>
                                      ))}
                                      {(step.data.encrypted_fields as string[]).map((f: string) => {
                                        const preview = step.data.encrypted_preview?.[f];
                                        const origVal = step.data.original_values?.[f];
                                        return (
                                        <tr key={f} className="bg-purple-50">
                                          <td className="py-1.5 px-3 border border-gray-200 font-mono font-medium">{f}</td>
                                          <td className="py-1.5 px-3 border border-gray-200 font-mono text-gray-700">
                                            {origVal != null ? Number(origVal).toFixed(4) : (
                                              demoResult.steps[0]?.data?.[f] != null
                                                ? String(demoResult.steps[0].data[f])
                                                : '—'
                                            )}
                                          </td>
                                          <td className="py-1.5 px-3 border border-gray-200">
                                            <div className="space-y-1">
                                              <span className="inline-flex items-center gap-1 text-purple-700 text-xs">
                                                <Lock className="w-3 h-3" /> CKKS 密文
                                                {preview?.size_bytes && (
                                                  <span className="text-gray-400 ml-1">({(preview.size_bytes / 1024).toFixed(1)} KB)</span>
                                                )}
                                              </span>
                                              {preview?.base64_preview && (
                                                <code className="block bg-purple-100 text-purple-900 px-2 py-1 rounded text-[9px] leading-tight font-mono break-all max-w-xs">
                                                  {preview.base64_preview}
                                                </code>
                                              )}
                                            </div>
                                          </td>
                                        </tr>
                                        );
                                      })}
                                    </tbody>
                                  </table>
                                  <div className="mt-2 text-xs text-gray-400 flex items-center gap-1">
                                    <Lock className="w-3 h-3" /> 紫色列 = CKKS 同態加密（Server 僅能做密文運算，無法解密）
                                  </div>
                                </div>
                              )}

                              {/* Step 5: Server inference */}
                              {step.id === 5 && (
                                <div className="flex flex-wrap gap-2">
                                  <span className="px-3 py-1 rounded-full text-xs bg-indigo-100 text-indigo-800 flex items-center gap-1">
                                    <Server className="w-3 h-3" /> {step.data.inference_location}
                                  </span>
                                  <span className="px-3 py-1 rounded-full text-xs bg-gray-100 text-gray-700">{step.data.method}</span>
                                  <p className="w-full text-xs text-gray-500 mt-1">{step.data.note}</p>
                                </div>
                              )}

                              {/* Step 6: Decision */}
                              {step.id === 6 && (
                                <div className="space-y-2">
                                  <div className="flex flex-wrap gap-2">
                                    {step.data.decrypted && (
                                      <span className="px-3 py-1 rounded-full text-xs bg-green-100 text-green-800 flex items-center gap-1">
                                        <Unlock className="w-3 h-3" /> 已解密 (Client 私鑰)
                                      </span>
                                    )}
                                    <span className="px-3 py-1 rounded-full text-xs bg-gray-100 text-gray-700">
                                      z = {step.data.z_plain?.toFixed(4)}
                                    </span>
                                    <span className="px-3 py-1 rounded-full text-xs bg-gray-100 text-gray-700">
                                      sigmoid(z) = {(step.data.probability * 100).toFixed(2)}%
                                    </span>
                                    <span className="px-3 py-1 rounded-full text-xs bg-gray-100 text-gray-700">
                                      閾值 = {step.data.threshold * 100}%
                                    </span>
                                  </div>
                                  <div className={`inline-flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium ${
                                    step.data.is_anomaly ? 'bg-red-100 text-red-800' : 'bg-green-100 text-green-800'
                                  }`}>
                                    {step.data.is_anomaly
                                      ? <><AlertTriangle className="w-4 h-4" /> {step.data.probability.toFixed(4)} &gt; {step.data.threshold} → 判定為異常</>
                                      : <><CheckCircle className="w-4 h-4" /> {step.data.probability.toFixed(4)} &le; {step.data.threshold} → 判定為正常</>}
                                  </div>
                                </div>
                              )}
                            </div>
                          </div>
                        </div>
                      </div>
                    );
                  })}
                </div>
              </>
            ) : (
              <div className="bg-white border border-gray-200 rounded p-12 text-center text-gray-400">
                <Eye className="w-16 h-16 mx-auto mb-4 opacity-30" />
                <p className="text-lg">點擊「執行 Demo」查看加密流程</p>
                <p className="text-sm mt-1">將隨機選取一筆資料，展示完整的加密 → 推論 → 解密流程</p>
              </div>
            )}
          </TabsContent>

          {/* ================================================================ */}
          {/*  Compare Tab                                                      */}
          {/* ================================================================ */}
          <TabsContent value="compare">
            <div className="bg-white border border-gray-200 rounded p-4 mb-6">
              <div className="flex items-center justify-between mb-4">
                <h2 className="text-base font-medium text-gray-900 flex items-center gap-2">
                  <GitCompareArrows className="w-5 h-5" /> 三模式效能比較
                </h2>
                <button
                  onClick={handleCompareAll}
                  disabled={isRunning || isComparing}
                  className="px-5 py-2 bg-purple-600 text-white rounded hover:bg-purple-700 transition-colors disabled:bg-gray-400 disabled:cursor-not-allowed inline-flex items-center gap-2 text-sm font-medium"
                >
                  <BarChart3 className="w-4 h-4" />
                  {isComparing ? compareProgress || '比較中...' : '執行三模式比較'}
                </button>
              </div>
              <p className="text-sm text-gray-500">同時執行 Plaintext、Mixed、CKKS 三種推論模式，比較準確率、延遲、流量等指標。</p>
            </div>

            {Object.keys(compareResults).length > 0 ? (
              <>
                {/* -- Summary table -- */}
                <div className="bg-white border border-gray-200 rounded p-4 mb-6 overflow-x-auto">
                  <h3 className="text-sm font-medium text-gray-900 mb-3">指標總覽</h3>
                  <table className="w-full text-sm">
                    <thead className="bg-gray-50">
                      <tr>
                        <th className="text-left py-2 px-3">指標</th>
                        {['plaintext', 'mixed', 'ckks'].filter(m => compareResults[m]).map(m => (
                          <th key={m} className="text-center py-2 px-3">
                            <span className="inline-block w-3 h-3 rounded-full mr-1" style={{ backgroundColor: MODE_COLORS[m] }} />
                            {MODE_LABELS[m]}
                          </th>
                        ))}
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-gray-200">
                      {[
                        { label: 'Accuracy', fn: (m: MetricData) => (m.accuracy * 100).toFixed(2) + '%' },
                        { label: 'Precision', fn: (m: MetricData) => (m.precision * 100).toFixed(2) + '%' },
                        { label: 'Recall', fn: (m: MetricData) => (m.recall * 100).toFixed(2) + '%' },
                        { label: 'F1 Score', fn: (m: MetricData) => (m.f1 * 100).toFixed(2) + '%' },
                        { label: '平均延遲', fn: (m: MetricData) => (m.latencySec * 1000).toFixed(2) + ' ms' },
                        { label: '偵測效率', fn: (m: MetricData) => m.detectionEfficiency.toExponential(3) },
                        { label: '資訊洩漏', fn: (m: MetricData) => m.infoLeakage.toFixed(2) + ' kb' },
                        { label: '未加密敏感比例', fn: (m: MetricData) => (m.unencryptedSensitiveRatio * 100).toFixed(1) + '%' },
                      ].map(row => (
                        <tr key={row.label}>
                          <td className="py-2 px-3 font-medium">{row.label}</td>
                          {['plaintext', 'mixed', 'ckks'].filter(m => compareResults[m]).map(m => (
                            <td key={m} className="py-2 px-3 text-center">{row.fn(compareResults[m])}</td>
                          ))}
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>

                {/* -- Charts row -- */}
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-6">
                  {/* Bar chart: accuracy + latency + F1 */}
                  <div className="bg-white border border-gray-200 rounded p-4">
                    <h3 className="text-sm font-medium text-gray-900 mb-3">效能指標對比</h3>
                    <div className="h-64">
                      <ResponsiveContainer width="100%" height="100%">
                        <BarChart data={comparisonBarData}>
                          <CartesianGrid strokeDasharray="3 3" />
                          <XAxis dataKey="mode" tick={{ fontSize: 11 }} />
                          <YAxis tick={{ fontSize: 11 }} />
                          <Tooltip />
                          <Legend />
                          <Bar dataKey="準確率" fill="#3b82f6" />
                          <Bar dataKey="F1 Score" fill="#10b981" />
                        </BarChart>
                      </ResponsiveContainer>
                    </div>
                  </div>

                  {/* Radar chart */}
                  <div className="bg-white border border-gray-200 rounded p-4">
                    <h3 className="text-sm font-medium text-gray-900 mb-3">模型品質雷達圖</h3>
                    <div className="h-64">
                      <ResponsiveContainer width="100%" height="100%">
                        <RadarChart data={radarData}>
                          <PolarGrid />
                          <PolarAngleAxis dataKey="metric" tick={{ fontSize: 11 }} />
                          <PolarRadiusAxis angle={30} domain={[0, 100]} tick={{ fontSize: 10 }} />
                          {['plaintext', 'mixed', 'ckks'].filter(m => compareResults[m]).map(m => (
                            <Radar key={m} name={MODE_LABELS[m]} dataKey={m} stroke={MODE_COLORS[m]} fill={MODE_COLORS[m]} fillOpacity={0.15} />
                          ))}
                          <Legend />
                          <Tooltip />
                        </RadarChart>
                      </ResponsiveContainer>
                    </div>
                  </div>

                  {/* Traffic breakdown bar chart */}
                  <div className="bg-white border border-gray-200 rounded p-4">
                    <h3 className="text-sm font-medium text-gray-900 mb-3">流量分布 (bytes)</h3>
                    <div className="h-64">
                      <ResponsiveContainer width="100%" height="100%">
                        <BarChart data={comparisonTrafficData}>
                          <CartesianGrid strokeDasharray="3 3" />
                          <XAxis dataKey="mode" tick={{ fontSize: 11 }} />
                          <YAxis tick={{ fontSize: 11 }} />
                          <Tooltip />
                          <Legend />
                          <Bar dataKey="明文 (bytes)" fill="#3b82f6" stackId="traffic" />
                          <Bar dataKey="密文 (bytes)" fill="#f59e0b" stackId="traffic" />
                        </BarChart>
                      </ResponsiveContainer>
                    </div>
                  </div>

                  {/* Latency bar chart */}
                  <div className="bg-white border border-gray-200 rounded p-4">
                    <h3 className="text-sm font-medium text-gray-900 mb-3">延遲比較 (ms)</h3>
                    <div className="h-64">
                      <ResponsiveContainer width="100%" height="100%">
                        <BarChart data={['plaintext', 'mixed', 'ckks'].filter(m => compareResults[m]).map(m => ({
                          mode: MODE_LABELS[m],
                          latency: +(compareResults[m].latencySec * 1000).toFixed(2),
                        }))}>
                          <CartesianGrid strokeDasharray="3 3" />
                          <XAxis dataKey="mode" tick={{ fontSize: 11 }} />
                          <YAxis tick={{ fontSize: 11 }} />
                          <Tooltip />
                          <Bar dataKey="latency" name="延遲 (ms)">
                            {['plaintext', 'mixed', 'ckks'].filter(m => compareResults[m]).map((m, i) => (
                              <Cell key={i} fill={MODE_COLORS[m]} />
                            ))}
                          </Bar>
                        </BarChart>
                      </ResponsiveContainer>
                    </div>
                  </div>
                </div>
              </>
            ) : (
              <div className="bg-white border border-gray-200 rounded p-12 text-center text-gray-400">
                <GitCompareArrows className="w-16 h-16 mx-auto mb-4 opacity-30" />
                <p className="text-lg">尚無比較資料</p>
                <p className="text-sm mt-1">點擊「執行三模式比較」開始</p>
              </div>
            )}
          </TabsContent>

          {/* ================================================================ */}
          {/*  History Tab                                                      */}
          {/* ================================================================ */}
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
                  {executionHistory.map(record => (
                    <div key={record.id} className="border border-gray-200 rounded p-4">
                      <div className="flex items-center justify-between mb-4">
                        <div className="flex items-center gap-3">
                          <h3 className="font-medium text-gray-900">執行 #{record.id}</h3>
                          <span className="px-2 py-0.5 rounded text-xs font-medium text-white" style={{ backgroundColor: MODE_COLORS[record.mode] || '#6b7280' }}>
                            {MODE_LABELS[record.mode] || record.mode}
                          </span>
                        </div>
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
                            {[
                              { label: '準確率', val: (record.metrics.accuracy * 100).toFixed(2) + '%', key: 'accuracy', raw: record.metrics.accuracy },
                              { label: '延遲', val: record.metrics.latencySec.toFixed(4) + ' sec', key: 'latencySec', raw: record.metrics.latencySec },
                              { label: '偵測效率', val: record.metrics.detectionEfficiency.toExponential(3), key: 'detectionEfficiency', raw: record.metrics.detectionEfficiency },
                              { label: '資訊洩漏', val: record.metrics.infoLeakage.toFixed(3) + ' kb', key: 'infoLeakage', raw: record.metrics.infoLeakage },
                            ].map(r => (
                              <tr key={r.label}>
                                <td className="py-2 px-3">{r.label}</td>
                                <td className="py-2 px-3">{r.val}</td>
                                <td className="py-2 px-3">
                                  <span className={`px-2 py-1 rounded text-xs ${STATUS_STYLE[getStatus(r.key, r.raw)]}`}>
                                    {getStatus(r.key, r.raw)}
                                  </span>
                                </td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>

                      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                        {[
                          { label: '準確率', data: record.chartSeries.accuracy },
                          { label: '延遲', data: record.chartSeries.latency },
                          { label: '偵測效率', data: record.chartSeries.detectionEfficiency },
                          { label: '資訊洩漏', data: record.chartSeries.infoLeakage },
                        ].map(c => (
                          <div key={c.label} className="border border-gray-200 rounded p-2">
                            <p className="text-xs text-gray-600 mb-1">{c.label}</p>
                            <MetricCard title="" value="" status="正常" chartData={c.data} compact />
                          </div>
                        ))}
                      </div>
                    </div>
                  ))}
                </div>
              )}
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
        </Tabs>
      </main>
    </div>
  );
}
