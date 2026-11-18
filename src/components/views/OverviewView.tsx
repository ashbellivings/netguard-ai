import React from 'react';
import {
  FlowRecord,
  SecurityAlert,
  ModelMetrics,
} from '../../types';
import {
  ShieldAlert,
  Activity,
  AlertTriangle,
  CheckCircle,
  Database,
  ArrowUpRight,
  TrendingUp,
} from 'lucide-react';

interface OverviewViewProps {
  flows: FlowRecord[];
  alerts: SecurityAlert[];
  metrics?: ModelMetrics;
  isSyntheticData: boolean;
  onLoadDemo: () => void;
  onNavigateToTab: (tab: any) => void;
  onSelectAlert: (alertId: string) => void;
}

export const OverviewView: React.FC<OverviewViewProps> = ({
  flows,
  alerts,
  metrics,
  isSyntheticData,
  onLoadDemo,
  onNavigateToTab,
  onSelectAlert,
}) => {
  if (flows.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center min-h-[60vh] text-center p-8">
        <div className="w-16 h-16 rounded-full bg-slate-900 border border-slate-800 flex items-center justify-center text-cyan-400 mb-4">
          <Database className="w-8 h-8" />
        </div>
        <h2 className="text-xl font-bold text-slate-100">No Network Telemetry Loaded</h2>
        <p className="text-sm text-slate-400 max-w-md mt-2 mb-6">
          To initiate security monitoring and intrusion detection, load the built-in realistic
          demonstration dataset or upload custom CSV flow records.
        </p>
        <button
          onClick={onLoadDemo}
          className="px-5 py-2.5 bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-semibold rounded text-sm transition-colors flex items-center gap-2 shadow-lg shadow-cyan-950"
        >
          <Database className="w-4 h-4" />
          <span>Load Demonstration Dataset</span>
        </button>
      </div>
    );
  }

  const totalFlows = flows.length;
  const normalFlows = flows.filter(f => f.label === 'NORMAL').length;
  const suspiciousFlows = flows.filter(f => f.label === 'SUSPICIOUS').length;
  const totalAlerts = alerts.length;
  const criticalAlerts = alerts.filter(a => a.severity === 'CRITICAL').length;
  const highAlerts = alerts.filter(a => a.severity === 'HIGH').length;
  const mediumAlerts = alerts.filter(a => a.severity === 'MEDIUM').length;
  const lowAlerts = alerts.filter(a => a.severity === 'LOW').length;

  const accuracyFormatted = metrics ? `${(metrics.accuracy * 100).toFixed(1)}%` : 'Pending ML';

  // Protocol distribution
  const protoCounts: Record<string, number> = {};
  flows.forEach(f => {
    protoCounts[f.protocol] = (protoCounts[f.protocol] || 0) + 1;
  });

  // Top suspicious source IPs
  const susIpCounts: Record<string, number> = {};
  alerts.forEach(a => {
    susIpCounts[a.sourceIp] = (susIpCounts[a.sourceIp] || 0) + 1;
  });
  const topSuspiciousIps = Object.entries(susIpCounts)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 5);

  // Time-bucketed flow distribution for attack trend
  const timeBuckets: Record<string, { total: number; suspicious: number }> = {};
  flows.forEach(f => {
    const timeKey = f.timestamp.substring(11, 16); // e.g. "08:05"
    if (!timeBuckets[timeKey]) {
      timeBuckets[timeKey] = { total: 0, suspicious: 0 };
    }
    timeBuckets[timeKey].total++;
    if (f.label === 'SUSPICIOUS') {
      timeBuckets[timeKey].suspicious++;
    }
  });

  const timeEntries = Object.entries(timeBuckets).slice(0, 10);
  const maxBucketTotal = Math.max(...timeEntries.map(e => e[1].total), 1);

  return (
    <div className="space-y-6">
      {/* Page Title & Context Banner */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-2 border-b border-slate-850">
        <div>
          <h1 className="text-xl font-bold tracking-tight text-slate-100 flex items-center gap-2">
            <span>Security Operations Center Overview</span>
          </h1>
          <p className="text-xs text-slate-400 mt-0.5">
            {isSyntheticData
              ? 'Simulated synthetic telemetry baseline — upload your own CSV capture in Traffic Data Management for live file analysis.'
              : 'Analyzing uploaded network flow capture telemetry with client-side ML detection benchmarks.'}
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2 text-xs text-slate-400 font-mono">
          <span
            className={`px-2.5 py-1.5 rounded border text-[11px] font-semibold ${
              isSyntheticData
                ? 'bg-amber-950/40 text-amber-300 border-amber-500/30'
                : 'bg-emerald-950/40 text-emerald-300 border-emerald-500/30'
            }`}
          >
            {isSyntheticData ? 'Synthetic Demo Data' : 'Uploaded CSV Capture'}
          </span>
          <div className="flex items-center gap-2 px-3 py-1.5 rounded bg-slate-900 border border-slate-800">
            <span className="text-slate-500">Engine:</span>
            <span className="text-cyan-400 font-semibold">{metrics ? metrics.algorithmName : 'Trained Classifiers'}</span>
          </div>
        </div>
      </div>

      {/* KPI Cards Row (6 Required Cards) */}
      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3.5">
        <div className="p-4 rounded-lg bg-slate-900/90 border border-slate-800">
          <div className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider">
            Total Flows
          </div>
          <div className="text-2xl font-bold text-slate-100 mt-1 font-mono tabular-nums">
            {totalFlows.toLocaleString()}
          </div>
          <div className="text-[11px] text-slate-500 mt-1">Monitored packets</div>
        </div>

        <div className="p-4 rounded-lg bg-slate-900/90 border border-slate-800">
          <div className="text-[11px] font-semibold text-emerald-400 uppercase tracking-wider flex items-center justify-between">
            <span>Normal Traffic</span>
            <CheckCircle className="w-3.5 h-3.5 text-emerald-500" />
          </div>
          <div className="text-2xl font-bold text-emerald-400 mt-1 font-mono tabular-nums">
            {normalFlows.toLocaleString()}
          </div>
          <div className="text-[11px] text-slate-500 mt-1">
            {Math.round((normalFlows / totalFlows) * 100)}% benign
          </div>
        </div>

        <div className="p-4 rounded-lg bg-slate-900/90 border border-slate-800">
          <div className="text-[11px] font-semibold text-red-400 uppercase tracking-wider flex items-center justify-between">
            <span>Suspicious Traffic</span>
            <AlertTriangle className="w-3.5 h-3.5 text-red-400" />
          </div>
          <div className="text-2xl font-bold text-red-400 mt-1 font-mono tabular-nums">
            {suspiciousFlows.toLocaleString()}
          </div>
          <div className="text-[11px] text-slate-500 mt-1">
            {Math.round((suspiciousFlows / totalFlows) * 100)}% flagged
          </div>
        </div>

        <div className="p-4 rounded-lg bg-slate-900/90 border border-slate-800">
          <div className="text-[11px] font-semibold text-amber-400 uppercase tracking-wider flex items-center justify-between">
            <span>Security Alerts</span>
            <ShieldAlert className="w-3.5 h-3.5 text-amber-400" />
          </div>
          <div className="text-2xl font-bold text-amber-400 mt-1 font-mono tabular-nums">
            {totalAlerts}
          </div>
          <div className="text-[11px] text-slate-500 mt-1">Logged in SQLite</div>
        </div>

        <div className="p-4 rounded-lg bg-slate-900/90 border border-slate-800">
          <div className="text-[11px] font-semibold text-red-500 uppercase tracking-wider flex items-center justify-between">
            <span>Critical Alerts</span>
            <Activity className="w-3.5 h-3.5 text-red-500" />
          </div>
          <div className="text-2xl font-bold text-red-500 mt-1 font-mono tabular-nums">
            {criticalAlerts}
          </div>
          <div className="text-[11px] text-slate-500 mt-1">Immediate triage</div>
        </div>

        <div className="p-4 rounded-lg bg-slate-900/90 border border-slate-800">
          <div className="text-[11px] font-semibold text-cyan-400 uppercase tracking-wider flex items-center justify-between">
            <span>Detection Accuracy</span>
            <TrendingUp className="w-3.5 h-3.5 text-cyan-400" />
          </div>
          <div className="text-2xl font-bold text-cyan-400 mt-1 font-mono tabular-nums">
            {accuracyFormatted}
          </div>
          <div className="text-[11px] text-slate-500 mt-1">Hold-out test set</div>
        </div>
      </div>

      {/* Interactive Charts Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
        {/* Chart 1: Normal vs Suspicious Visual Proportion */}
        <div className="p-5 rounded-lg bg-slate-900/90 border border-slate-800">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-sm font-bold text-slate-100">
              Normal vs. Suspicious Traffic Distribution
            </h3>
            <span className="text-xs text-slate-400 font-mono">
              Total: {totalFlows.toLocaleString()}
            </span>
          </div>

          <div className="space-y-3">
            <div>
              <div className="flex justify-between text-xs mb-1">
                <span className="text-emerald-400 font-medium">Normal / Benign Flows</span>
                <span className="font-mono text-slate-300">
                  {normalFlows} ({Math.round((normalFlows / totalFlows) * 100)}%)
                </span>
              </div>
              <div className="w-full h-3 bg-slate-800 rounded-full overflow-hidden">
                <div
                  className="h-full bg-emerald-500 transition-all duration-500"
                  style={{ width: `${(normalFlows / totalFlows) * 100}%` }}
                />
              </div>
            </div>

            <div>
              <div className="flex justify-between text-xs mb-1">
                <span className="text-red-400 font-medium">Suspicious / Malicious Flows</span>
                <span className="font-mono text-slate-300">
                  {suspiciousFlows} ({Math.round((suspiciousFlows / totalFlows) * 100)}%)
                </span>
              </div>
              <div className="w-full h-3 bg-slate-800 rounded-full overflow-hidden">
                <div
                  className="h-full bg-red-500 transition-all duration-500"
                  style={{ width: `${(suspiciousFlows / totalFlows) * 100}%` }}
                />
              </div>
            </div>
          </div>

          <div className="mt-5 pt-4 border-t border-slate-800/80 grid grid-cols-2 gap-4 text-xs">
            <div className="p-2.5 rounded bg-slate-950/60 border border-slate-850">
              <div className="text-slate-400 font-medium">Class Balance Ratio</div>
              <div className="text-sm font-bold font-mono text-slate-200 mt-0.5">
                {(normalFlows / Math.max(suspiciousFlows, 1)).toFixed(2)} : 1
              </div>
            </div>
            <div className="p-2.5 rounded bg-slate-950/60 border border-slate-850">
              <div className="text-slate-400 font-medium">Threat Ratio</div>
              <div className="text-sm font-bold font-mono text-red-400 mt-0.5">
                {((suspiciousFlows / totalFlows) * 100).toFixed(1)}% of flows
              </div>
            </div>
          </div>
        </div>

        {/* Chart 2: Alerts by Severity */}
        <div className="p-5 rounded-lg bg-slate-900/90 border border-slate-800">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-sm font-bold text-slate-100">
              Security Alerts by Severity Ranking
            </h3>
            <span className="text-xs text-slate-400 font-mono">
              Active: {totalAlerts}
            </span>
          </div>

          <div className="grid grid-cols-4 gap-2.5 text-center mb-4">
            <div className="p-2.5 rounded bg-red-950/30 border border-red-500/20">
              <div className="text-[10px] uppercase font-bold text-red-400">Critical</div>
              <div className="text-xl font-bold font-mono text-red-400 mt-1">{criticalAlerts}</div>
            </div>
            <div className="p-2.5 rounded bg-orange-950/30 border border-orange-500/20">
              <div className="text-[10px] uppercase font-bold text-orange-400">High</div>
              <div className="text-xl font-bold font-mono text-orange-400 mt-1">{highAlerts}</div>
            </div>
            <div className="p-2.5 rounded bg-amber-950/30 border border-amber-500/20">
              <div className="text-[10px] uppercase font-bold text-amber-400">Medium</div>
              <div className="text-xl font-bold font-mono text-amber-400 mt-1">{mediumAlerts}</div>
            </div>
            <div className="p-2.5 rounded bg-emerald-950/30 border border-emerald-500/20">
              <div className="text-[10px] uppercase font-bold text-emerald-400">Low</div>
              <div className="text-xl font-bold font-mono text-emerald-400 mt-1">{lowAlerts}</div>
            </div>
          </div>

          <div className="space-y-2 text-xs">
            <div className="flex items-center gap-2">
              <span className="w-16 font-mono text-slate-400">CRITICAL</span>
              <div className="flex-1 h-2 bg-slate-800 rounded-full overflow-hidden">
                <div
                  className="h-full bg-red-500"
                  style={{ width: `${(criticalAlerts / Math.max(totalAlerts, 1)) * 100}%` }}
                />
              </div>
              <span className="w-8 text-right font-mono text-slate-300">{criticalAlerts}</span>
            </div>
            <div className="flex items-center gap-2">
              <span className="w-16 font-mono text-slate-400">HIGH</span>
              <div className="flex-1 h-2 bg-slate-800 rounded-full overflow-hidden">
                <div
                  className="h-full bg-orange-500"
                  style={{ width: `${(highAlerts / Math.max(totalAlerts, 1)) * 100}%` }}
                />
              </div>
              <span className="w-8 text-right font-mono text-slate-300">{highAlerts}</span>
            </div>
            <div className="flex items-center gap-2">
              <span className="w-16 font-mono text-slate-400">MEDIUM</span>
              <div className="flex-1 h-2 bg-slate-800 rounded-full overflow-hidden">
                <div
                  className="h-full bg-amber-500"
                  style={{ width: `${(mediumAlerts / Math.max(totalAlerts, 1)) * 100}%` }}
                />
              </div>
              <span className="w-8 text-right font-mono text-slate-300">{mediumAlerts}</span>
            </div>
            <div className="flex items-center gap-2">
              <span className="w-16 font-mono text-slate-400">LOW</span>
              <div className="flex-1 h-2 bg-slate-800 rounded-full overflow-hidden">
                <div
                  className="h-full bg-emerald-500"
                  style={{ width: `${(lowAlerts / Math.max(totalAlerts, 1)) * 100}%` }}
                />
              </div>
              <span className="w-8 text-right font-mono text-slate-300">{lowAlerts}</span>
            </div>
          </div>
        </div>

        {/* Chart 3: Attack Trends Over Time */}
        <div className="p-5 rounded-lg bg-slate-900/90 border border-slate-800">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-sm font-bold text-slate-100">
              Traffic Activity & Attack Density Over Time
            </h3>
            <span className="text-xs text-slate-400 font-mono">10-Minute Intervals</span>
          </div>

          <div className="space-y-2">
            {timeEntries.map(([minute, data]) => {
              const susWidth = (data.suspicious / maxBucketTotal) * 100;
              const normWidth = ((data.total - data.suspicious) / maxBucketTotal) * 100;
              return (
                <div key={minute} className="flex items-center gap-3 text-xs">
                  <span className="w-12 font-mono text-slate-400 shrink-0">{minute}</span>
                  <div className="flex-1 h-3.5 bg-slate-950 rounded flex overflow-hidden border border-slate-850">
                    <div
                      style={{ width: `${normWidth}%` }}
                      className="bg-cyan-600/70 hover:bg-cyan-500 transition-colors"
                      title={`${data.total - data.suspicious} Normal`}
                    />
                    <div
                      style={{ width: `${susWidth}%` }}
                      className="bg-red-500 hover:bg-red-400 transition-colors"
                      title={`${data.suspicious} Suspicious`}
                    />
                  </div>
                  <span className="w-16 font-mono text-right text-slate-300 shrink-0">
                    {data.suspicious > 0 ? (
                      <span className="text-red-400 font-bold">{data.suspicious} threats</span>
                    ) : (
                      <span className="text-slate-500">{data.total} normal</span>
                    )}
                  </span>
                </div>
              );
            })}
          </div>
          <div className="flex items-center gap-4 mt-4 pt-3 border-t border-slate-800 text-[11px] text-slate-400">
            <div className="flex items-center gap-1.5">
              <span className="w-2.5 h-2.5 bg-cyan-600 rounded-sm" />
              <span>Normal Flows</span>
            </div>
            <div className="flex items-center gap-1.5">
              <span className="w-2.5 h-2.5 bg-red-500 rounded-sm" />
              <span>Flagged Attacks</span>
            </div>
          </div>
        </div>

        {/* Chart 4: Traffic by Protocol & Top Threat IPs */}
        <div className="p-5 rounded-lg bg-slate-900/90 border border-slate-800 flex flex-col justify-between">
          <div>
            <h3 className="text-sm font-bold text-slate-100 mb-3">
              Traffic Distribution by Protocol
            </h3>
            <div className="grid grid-cols-3 gap-2.5 mb-5">
              {Object.entries(protoCounts).map(([proto, count]) => (
                <div key={proto} className="p-2.5 rounded bg-slate-950/60 border border-slate-850">
                  <div className="text-[11px] font-bold text-slate-400 uppercase font-mono">{proto}</div>
                  <div className="text-lg font-bold font-mono text-cyan-400 mt-1">{count}</div>
                  <div className="text-[10px] text-slate-500">
                    {Math.round((count / totalFlows) * 100)}% of traffic
                  </div>
                </div>
              ))}
            </div>

            <h3 className="text-sm font-bold text-slate-100 mb-2">
              Top Suspicious Source IP Addresses
            </h3>
            <div className="space-y-1.5">
              {topSuspiciousIps.length > 0 ? (
                topSuspiciousIps.map(([ip, count]) => (
                  <div
                    key={ip}
                    className="flex items-center justify-between p-2 rounded bg-slate-950/40 border border-slate-850 text-xs"
                  >
                    <code className="text-red-400 font-mono font-semibold">{ip}</code>
                    <div className="flex items-center gap-2">
                      <span className="font-mono text-slate-300">{count} alerts</span>
                      <span className="text-[10px] px-1.5 py-0.5 rounded bg-red-950/50 text-red-400 border border-red-500/30">
                        ATTACKER
                      </span>
                    </div>
                  </div>
                ))
              ) : (
                <div className="text-xs text-slate-500 italic p-2">
                  No suspicious source IP addresses flagged yet.
                </div>
              )}
            </div>
          </div>

          <div className="pt-3 border-t border-slate-800/80 mt-4 flex justify-end">
            <button
              onClick={() => onNavigateToTab('threat_intel')}
              className="text-xs text-cyan-400 hover:text-cyan-300 flex items-center gap-1 font-medium"
            >
              <span>Detailed Threat Intelligence</span>
              <ArrowUpRight className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>
      </div>

      {/* Recent Security Alerts Table */}
      <div className="p-5 rounded-lg bg-slate-900/90 border border-slate-800">
        <div className="flex items-center justify-between mb-4">
          <div>
            <h3 className="text-sm font-bold text-slate-100">
              Recent High & Critical Security Alerts
            </h3>
            <p className="text-xs text-slate-400">
              Generated from supervised and unsupervised detection models
            </p>
          </div>
          <button
            onClick={() => onNavigateToTab('alerts')}
            className="text-xs text-cyan-400 hover:text-cyan-300 flex items-center gap-1 font-medium"
          >
            <span>View All ({totalAlerts})</span>
            <ArrowUpRight className="w-3.5 h-3.5" />
          </button>
        </div>

        {alerts.length > 0 ? (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs border-collapse">
              <thead>
                <tr className="border-b border-slate-800 text-slate-400 uppercase font-mono text-[10px] tracking-wider">
                  <th className="py-2.5 px-3">Alert ID</th>
                  <th className="py-2.5 px-3">Timestamp</th>
                  <th className="py-2.5 px-3">Source IP</th>
                  <th className="py-2.5 px-3">Destination Port</th>
                  <th className="py-2.5 px-3">Category</th>
                  <th className="py-2.5 px-3">Severity</th>
                  <th className="py-2.5 px-3">Status</th>
                  <th className="py-2.5 px-3 text-right">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-850 font-mono">
                {alerts.slice(0, 6).map((a) => {
                  let sevBadge = 'text-red-400 bg-red-950/30 border-red-500/30';
                  if (a.severity === 'HIGH') sevBadge = 'text-orange-400 bg-orange-950/30 border-orange-500/30';
                  else if (a.severity === 'MEDIUM') sevBadge = 'text-amber-400 bg-amber-950/30 border-amber-500/30';
                  else if (a.severity === 'LOW') sevBadge = 'text-emerald-400 bg-emerald-950/30 border-emerald-500/30';

                  return (
                    <tr key={a.id} className="hover:bg-slate-850/40 transition-colors">
                      <td className="py-2.5 px-3 font-bold text-slate-200">{a.id}</td>
                      <td className="py-2.5 px-3 text-slate-400">{a.timestamp}</td>
                      <td className="py-2.5 px-3 text-red-300">{a.sourceIp}</td>
                      <td className="py-2.5 px-3 text-slate-300">{a.destinationPort} ({a.protocol})</td>
                      <td className="py-2.5 px-3 font-sans text-slate-200">{a.predictedCategory}</td>
                      <td className="py-2.5 px-3">
                        <span className={`inline-block px-2 py-0.5 rounded text-[10px] font-bold border ${sevBadge}`}>
                          {a.severity}
                        </span>
                      </td>
                      <td className="py-2.5 px-3 font-sans">
                        <span className="text-slate-300">{a.status}</span>
                      </td>
                      <td className="py-2.5 px-3 text-right">
                        <button
                          onClick={() => {
                            onSelectAlert(a.id);
                            onNavigateToTab('incidents');
                          }}
                          className="px-2 py-1 bg-slate-800 hover:bg-slate-700 text-cyan-400 rounded text-[11px] font-sans font-medium transition-colors"
                        >
                          Investigate
                        </button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="p-6 text-center text-xs text-slate-400">
            No alerts generated yet. Click "AI Intrusion Detection" to classify flows.
          </div>
        )}
      </div>
    </div>
  );
};
