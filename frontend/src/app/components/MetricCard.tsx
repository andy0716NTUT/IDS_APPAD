import {
  CartesianGrid,
  Line,
  LineChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';

interface ChartPoint {
  ratio: number;
  value: number;
}

interface MetricCardProps {
  title: string;
  value: string | number;
  status: '正常' | '警告' | '危險';
  chartData?: ChartPoint[];
  unit?: string;
  tooltipUnit?: string;
  compact?: boolean;
}

export function MetricCard({ title, value, status, chartData, unit = '', tooltipUnit = '', compact = false }: MetricCardProps) {
  const statusColors = {
    正常: 'bg-green-100 text-green-800',
    警告: 'bg-yellow-100 text-yellow-800',
    危險: 'bg-red-100 text-red-800'
  };

  return (
    <div className="bg-white border border-gray-200 rounded p-4">
      {!compact && (
        <>
          <div className="flex items-center justify-between mb-3">
            <h3 className="text-base font-medium text-gray-900">{title}</h3>
            <span className={`px-2 py-1 rounded text-xs ${statusColors[status]}`}>
              {status}
            </span>
          </div>

          <div className="mb-4">
            <div className="text-3xl font-semibold text-gray-900">
              {value}{unit}
            </div>
          </div>
        </>
      )}

      <div className={`${compact ? 'h-20' : 'h-40'} border border-gray-200 rounded bg-gray-50 flex items-center justify-center`}>
        {chartData && chartData.length > 0 ? (
          <div className="w-full h-full p-2">
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={chartData} margin={{ top: 8, right: 8, left: 2, bottom: 2 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#d1d5db" />
                <XAxis
                  dataKey="ratio"
                  tick={!compact ? { fontSize: 10, fill: '#6b7280' } : false}
                  tickFormatter={(v) => `${v}%`}
                  axisLine={!compact}
                />
                <YAxis tick={!compact ? { fontSize: 10, fill: '#6b7280' } : false} width={54} axisLine={!compact} />
                {!compact && (
                  <Tooltip
                    formatter={(val: number) => `${Number(val).toLocaleString()}${tooltipUnit}`}
                    labelFormatter={(label) => `敏感比例: ${label}%`}
                  />
                )}
                <Line
                  type="monotone"
                  dataKey="value"
                  stroke="#111827"
                  strokeWidth={2}
                  dot={{ r: compact ? 0 : 2 }}
                  activeDot={{ r: compact ? 0 : 4 }}
                />
              </LineChart>
            </ResponsiveContainer>
          </div>
        ) : (
          <div className="text-center text-gray-400 text-sm">
            <p>{compact ? '無資料' : '尚無圖表資料'}</p>
            {!compact && <p className="text-xs mt-1">請先執行後端分析</p>}
          </div>
        )}
      </div>
    </div>
  );
}