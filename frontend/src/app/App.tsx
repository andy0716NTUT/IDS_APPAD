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
  stdout?: string;
  stderr?: string;
  error?: string;
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
    if (value <= 0.1) {
      return '正常';
    }
    if (value <= 0.2) {
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
  const [isRunning, setIsRunning] = useState(false);
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
    setLastUpdated(new Date().toLocaleString('zh-TW'));
  };

  useEffect(() => {
    void loadLatestResults();
  }, []);

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
      const res = await fetch('/api/run', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ inferenceMode: 'mixed', seed: 42 }),
      });

      const payload: ApiPayload = await res.json();
      if (!res.ok) {
        throw new Error(payload.error ?? '後端執行失敗');
      }

      const newMetrics = toMetricData(payload);
      const newChartSeries = toChartSeries(payload);
      setMetrics(newMetrics);
      setChartSeries(newChartSeries);
      setLastUpdated(new Date().toLocaleString('zh-TW'));

      const newRecord: ExecutionRecord = {
        id: recordIdCounter,
        timestamp: new Date().toLocaleString('zh-TW'),
        metrics: newMetrics,
        chartSeries: newChartSeries,
      };
      setExecutionHistory((prev: ExecutionRecord[]) => [newRecord, ...prev]);
      setRecordIdCounter((prev: number) => prev + 1);

      appendLog(`[${timestamp}] 後端分析完成`);
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
          </TabsList>

          <TabsContent value="dashboard">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-6">
              <MetricCard
                title="準確率 (Accuracy)"
                value={(metrics.accuracy * 100).toFixed(2)}
                unit="%"
                status={getStatus('accuracy', metrics.accuracy)}
                chartData={chartSeries.accuracy}
              />

              <MetricCard
                title="延遲 (Latency)"
                value={metrics.latencySec.toFixed(4)}
                unit=" sec"
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
                title="資訊洩漏 (Information Leakage)"
                value={metrics.infoLeakage.toFixed(3)}
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
                              <td className="py-2 px-3">資訊洩漏</td>
                              <td className="py-2 px-3">{record.metrics.infoLeakage.toFixed(3)}</td>
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
                          <p className="text-xs text-gray-600 mb-1">資訊洩漏</p>
                          <MetricCard title="" value="" status="正常" chartData={record.chartSeries.infoLeakage} compact />
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
