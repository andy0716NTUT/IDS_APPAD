import { useEffect, useState } from 'react';
import { MetricCard } from './components/MetricCard';
import { Play, History, BarChart3, GitCompareArrows, Server, Shield, Zap } from 'lucide-react';
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
        </Tabs>
      </main>
    </div>
  );
}
