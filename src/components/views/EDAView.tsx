import React, { useState } from 'react';
import { FlowRecord, EDAFinding } from '../../types';
import { computePearsonCorrelation } from '../../utils/edaFindings';
import { BarChart3, AlertCircle, Info, ShieldAlert, ArrowRight } from 'lucide-react';

interface EDAViewProps {
  flows: FlowRecord[];
  findings: EDAFinding[];
  onNavigateToTab: (tab: any) => void;
}

export const EDAView: React.FC<EDAViewProps> = ({
  flows,
  findings,
  onNavigateToTab,
}) => {
  const [selectedCategory, setSelectedCategory] = useState<string>('all');

  const total = flows.length;
  if (total === 0) {
    return (
      <div className="p-8 text-center text-slate-400">
        No dataset loaded to explore. Please load demo data or upload a CSV file.
      </div>
    );
  }

  // 1. Attack categories breakdown
  const categoryCounts: Record<string, number> = {};
  flows.forEach(f => {
    const cat = f.attackCategory || 'Normal';
    categoryCounts[cat] = (categoryCounts[cat] || 0) + 1;
  });

  // 2. Protocols
  const protoCounts: Record<string, number> = {};
  flows.forEach(f => {
    protoCounts[f.protocol] = (protoCounts[f.protocol] || 0) + 1;
  });

  // 3. Port distributions
  const portCounts: Record<number, number> = {};
  flows.forEach(f => {
    portCounts[f.destinationPort] = (portCounts[f.destinationPort] || 0) + 1;
  });
  const topPorts = Object.entries(portCounts)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 8);

  // 4. Duration Histogram Buckets
  const durBuckets = [
    { label: '<0.05s (Probes)', count: flows.filter(f => f.flowDuration < 0.05).length },
    { label: '0.05s - 1s (Standard)', count: flows.filter(f => f.flowDuration >= 0.05 && f.flowDuration < 1).length },
    { label: '1s - 5s (Transfers)', count: flows.filter(f => f.flowDuration >= 1 && f.flowDuration < 5).length },
    { label: '5s - 15s (Web API)', count: flows.filter(f => f.flowDuration >= 5 && f.flowDuration < 15).length },
    { label: '>15s (Persistent/C2)', count: flows.filter(f => f.flowDuration >= 15).length },
  ];
  const maxDurCount = Math.max(...durBuckets.map(b => b.count), 1);

  // 5. Packet Count Distribution
  const pktBuckets = [
    { label: '1-3 pkts (SYN Probes)', count: flows.filter(f => f.packetCount <= 3).length },
    { label: '4-20 pkts (Interactive)', count: flows.filter(f => f.packetCount > 3 && f.packetCount <= 20).length },
    { label: '21-100 pkts (Page loads)', count: flows.filter(f => f.packetCount > 20 && f.packetCount <= 100).length },
    { label: '101-500 pkts (Streaming)', count: flows.filter(f => f.packetCount > 100 && f.packetCount <= 500).length },
    { label: '>500 pkts (DoS Flood)', count: flows.filter(f => f.packetCount > 500).length },
  ];
  const maxPktCount = Math.max(...pktBuckets.map(b => b.count), 1);

  // 6. Byte Count Buckets
  const byteBuckets = [
    { label: '< 200 B (Headers)', count: flows.filter(f => f.byteCount < 200).length },
    { label: '200 B - 2 KB (RPC)', count: flows.filter(f => f.byteCount >= 200 && f.byteCount < 2000).length },
    { label: '2 KB - 20 KB (Web)', count: flows.filter(f => f.byteCount >= 2000 && f.byteCount < 20000).length },
    { label: '20 KB - 100 KB (Large)', count: flows.filter(f => f.byteCount >= 20000 && f.byteCount < 100000).length },
    { label: '> 100 KB (Volumetric)', count: flows.filter(f => f.byteCount >= 100000).length },
  ];
  const maxByteCount = Math.max(...byteBuckets.map(b => b.count), 1);

  // 7. Numerical Feature Correlation Matrix (Pearson r)
  const durations = flows.map(f => f.flowDuration);
  const packets = flows.map(f => f.packetCount);
  const bytes = flows.map(f => f.byteCount);
  const rates = flows.map(f => f.flowRate);
  const ports = flows.map(f => f.destinationPort);

  const numFeatures = ['Duration', 'Packets', 'Bytes', 'Flow Rate', 'Dst Port'];
  const numVectors = [durations, packets, bytes, rates, ports];

  const corrMatrix = numFeatures.map((_, i) =>
    numFeatures.map((_, j) => (i === j ? 1.0 : computePearsonCorrelation(numVectors[i], numVectors[j])))
  );

  const filteredFindings = selectedCategory === 'all' 
    ? findings 
    : findings.filter(f => f.severity === selectedCategory);

  return (
    <div className="space-y-6">
      {/* Title */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-2 border-b border-slate-850">
        <div>
          <h1 className="text-xl font-bold tracking-tight text-slate-100 flex items-center gap-2">
            <span>Exploratory Security Data Analysis</span>
          </h1>
          <p className="text-xs text-slate-400 mt-0.5">
            Statistical distribution profiling, anomaly detection indicators, and 10 dynamic data findings.
          </p>
        </div>

        <button
          onClick={() => onNavigateToTab('detection')}
          className="px-3.5 py-1.5 bg-cyan-500 hover:bg-cyan-400 text-slate-950 rounded text-xs font-semibold transition-colors flex items-center gap-1.5 self-start sm:self-auto"
        >
          <span>Train AI Intrusion Models</span>
          <ArrowRight className="w-3.5 h-3.5" />
        </button>
      </div>

      {/* 10 Automated Security Data Findings */}
      <div className="p-5 rounded-lg bg-slate-900/90 border border-slate-800">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 mb-4">
          <div>
            <h3 className="text-sm font-bold text-slate-100 flex items-center gap-2">
              <BarChart3 className="w-4 h-4 text-cyan-400" />
              10 Automated Security Data Findings
            </h3>
            <p className="text-xs text-slate-400">
              Dynamically derived from actual network flow properties and attack signatures
            </p>
          </div>

          <div className="flex items-center gap-1.5 bg-slate-950 p-1 rounded border border-slate-800 text-xs">
            <button
              onClick={() => setSelectedCategory('all')}
              className={`px-2.5 py-1 rounded text-xs font-medium transition-colors ${
                selectedCategory === 'all' ? 'bg-slate-800 text-cyan-300' : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              All ({findings.length})
            </button>
            <button
              onClick={() => setSelectedCategory('critical')}
              className={`px-2.5 py-1 rounded text-xs font-medium transition-colors ${
                selectedCategory === 'critical' ? 'bg-red-950/60 text-red-400 border border-red-500/30' : 'text-slate-400 hover:text-red-400'
              }`}
            >
              Critical
            </button>
            <button
              onClick={() => setSelectedCategory('warning')}
              className={`px-2.5 py-1 rounded text-xs font-medium transition-colors ${
                selectedCategory === 'warning' ? 'bg-amber-950/60 text-amber-400 border border-amber-500/30' : 'text-slate-400 hover:text-amber-400'
              }`}
            >
              Warning
            </button>
            <button
              onClick={() => setSelectedCategory('info')}
              className={`px-2.5 py-1 rounded text-xs font-medium transition-colors ${
                selectedCategory === 'info' ? 'bg-cyan-950/60 text-cyan-400 border border-cyan-500/30' : 'text-slate-400 hover:text-cyan-400'
              }`}
            >
              Info
            </button>
          </div>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
          {filteredFindings.map((finding) => {
            let borderClass = 'border-slate-800 bg-slate-950/40';
            let icon = <Info className="w-4 h-4 text-cyan-400 shrink-0 mt-0.5" />;
            if (finding.severity === 'critical') {
              borderClass = 'border-red-500/30 bg-red-950/15';
              icon = <ShieldAlert className="w-4 h-4 text-red-400 shrink-0 mt-0.5" />;
            } else if (finding.severity === 'warning') {
              borderClass = 'border-amber-500/30 bg-amber-950/15';
              icon = <AlertCircle className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />;
            }

            return (
              <div
                key={finding.id}
                className={`p-3.5 rounded border ${borderClass} transition-colors`}
              >
                <div className="flex items-start justify-between gap-2">
                  <div className="flex items-start gap-2">
                    {icon}
                    <div>
                      <div className="text-xs font-bold text-slate-200">
                        {finding.title}
                      </div>
                      <div className="text-[11px] font-mono text-cyan-400 font-semibold mt-0.5">
                        {finding.metric}
                      </div>
                    </div>
                  </div>
                  <span className="text-[10px] font-mono text-slate-500 uppercase">
                    {finding.category}
                  </span>
                </div>
                <p className="text-xs text-slate-400 mt-2 leading-relaxed">
                  {finding.description}
                </p>
              </div>
            );
          })}
        </div>
      </div>

      {/* 8 Meaningful Visualizations Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
        {/* Viz 1: Attack Category Breakdown */}
        <div className="p-5 rounded-lg bg-slate-900/90 border border-slate-800">
          <h3 className="text-sm font-bold text-slate-100 mb-3">
            1. Attack Category & Threat Distribution
          </h3>
          <div className="space-y-2.5">
            {Object.entries(categoryCounts).map(([cat, count]) => {
              const pct = (count / total) * 100;
              const isNormal = cat === 'Normal';
              return (
                <div key={cat} className="space-y-1 text-xs">
                  <div className="flex justify-between">
                    <span className={isNormal ? 'text-emerald-400 font-medium' : 'text-slate-200 font-medium'}>
                      {cat}
                    </span>
                    <span className="font-mono text-slate-300">
                      {count} ({pct.toFixed(1)}%)
                    </span>
                  </div>
                  <div className="w-full h-2 bg-slate-950 rounded-full overflow-hidden border border-slate-850">
                    <div
                      className={`h-full ${isNormal ? 'bg-emerald-500' : 'bg-red-500'}`}
                      style={{ width: `${pct}%` }}
                    />
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* Viz 2: Traffic Volume by Transport Protocol */}
        <div className="p-5 rounded-lg bg-slate-900/90 border border-slate-800">
          <h3 className="text-sm font-bold text-slate-100 mb-3">
            2. Transport Protocol Breakdown (TCP / UDP / ICMP)
          </h3>
          <div className="grid grid-cols-3 gap-3 mb-4">
            {Object.entries(protoCounts).map(([proto, count]) => (
              <div key={proto} className="p-3 rounded bg-slate-950/60 border border-slate-850 text-center">
                <span className="text-xs font-mono font-bold text-cyan-400">{proto}</span>
                <div className="text-xl font-bold font-mono text-slate-100 mt-1">{count}</div>
                <div className="text-[10px] text-slate-500">{((count / total) * 100).toFixed(1)}%</div>
              </div>
            ))}
          </div>
          <p className="text-xs text-slate-400 leading-relaxed">
            TCP is utilized for high-reliability web, administrative, and port-scan traffic. UDP supports lightweight DNS queries and NTP synchronization. ICMP handles network diagnostic probes.
          </p>
        </div>

        {/* Viz 3: Connection Duration Histogram */}
        <div className="p-5 rounded-lg bg-slate-900/90 border border-slate-800">
          <h3 className="text-sm font-bold text-slate-100 mb-3">
            3. Flow Duration Binned Distribution
          </h3>
          <div className="space-y-2">
            {durBuckets.map((bucket) => {
              const pct = (bucket.count / maxDurCount) * 100;
              return (
                <div key={bucket.label} className="text-xs space-y-1">
                  <div className="flex justify-between text-slate-300">
                    <span>{bucket.label}</span>
                    <span className="font-mono text-cyan-400">{bucket.count} flows</span>
                  </div>
                  <div className="w-full h-2 bg-slate-950 rounded-full overflow-hidden">
                    <div className="h-full bg-cyan-500" style={{ width: `${pct}%` }} />
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* Viz 4: Packet Count Anomaly Analysis */}
        <div className="p-5 rounded-lg bg-slate-900/90 border border-slate-800">
          <h3 className="text-sm font-bold text-slate-100 mb-3">
            4. Packet Volume Anomaly Bins
          </h3>
          <div className="space-y-2">
            {pktBuckets.map((bucket) => {
              const pct = (bucket.count / maxPktCount) * 100;
              return (
                <div key={bucket.label} className="text-xs space-y-1">
                  <div className="flex justify-between text-slate-300">
                    <span>{bucket.label}</span>
                    <span className="font-mono text-amber-400">{bucket.count} flows</span>
                  </div>
                  <div className="w-full h-2 bg-slate-950 rounded-full overflow-hidden">
                    <div className="h-full bg-amber-500" style={{ width: `${pct}%` }} />
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* Viz 5: Byte Count Distribution */}
        <div className="p-5 rounded-lg bg-slate-900/90 border border-slate-800">
          <h3 className="text-sm font-bold text-slate-100 mb-3">
            5. Byte Volume Transferred Distribution
          </h3>
          <div className="space-y-2">
            {byteBuckets.map((bucket) => {
              const pct = (bucket.count / maxByteCount) * 100;
              return (
                <div key={bucket.label} className="text-xs space-y-1">
                  <div className="flex justify-between text-slate-300">
                    <span>{bucket.label}</span>
                    <span className="font-mono text-purple-400">{bucket.count} flows</span>
                  </div>
                  <div className="w-full h-2 bg-slate-950 rounded-full overflow-hidden">
                    <div className="h-full bg-purple-500" style={{ width: `${pct}%` }} />
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* Viz 6: Destination Port Frequencies */}
        <div className="p-5 rounded-lg bg-slate-900/90 border border-slate-800">
          <h3 className="text-sm font-bold text-slate-100 mb-3">
            6. Top Destination Service Ports
          </h3>
          <div className="space-y-2">
            {topPorts.map(([port, count]) => {
              const pct = (count / total) * 100;
              return (
                <div key={port} className="text-xs space-y-1">
                  <div className="flex justify-between text-slate-300 font-mono">
                    <span>Port {port}</span>
                    <span>{count} connections ({pct.toFixed(1)}%)</span>
                  </div>
                  <div className="w-full h-2 bg-slate-950 rounded-full overflow-hidden">
                    <div className="h-full bg-cyan-400" style={{ width: `${pct}%` }} />
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* Viz 7: Feature Correlation Matrix */}
        <div className="lg:col-span-2 p-5 rounded-lg bg-slate-900/90 border border-slate-800">
          <h3 className="text-sm font-bold text-slate-100 mb-2">
            7. Pearson Correlation Heatmap Matrix
          </h3>
          <p className="text-xs text-slate-400 mb-4">
            Linear correlation coefficient r between -1.0 and +1.0 for numeric network telemetry features
          </p>

          <div className="overflow-x-auto">
            <table className="w-full text-center text-xs border-collapse">
              <thead>
                <tr>
                  <th className="p-2 text-left font-mono text-slate-400">Feature</th>
                  {numFeatures.map(f => (
                    <th key={f} className="p-2 font-mono text-slate-300">{f}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {numFeatures.map((rowFeat, i) => (
                  <tr key={rowFeat} className="border-t border-slate-800">
                    <td className="p-2 text-left font-mono font-bold text-slate-300">{rowFeat}</td>
                    {corrMatrix[i].map((val, j) => {
                      let bg = 'bg-slate-950 text-slate-400';
                      if (val === 1.0) bg = 'bg-cyan-500/30 text-cyan-200 font-bold';
                      else if (val > 0.6) bg = 'bg-cyan-600/40 text-cyan-200';
                      else if (val > 0.3) bg = 'bg-cyan-800/30 text-cyan-300';
                      else if (val < -0.3) bg = 'bg-red-800/30 text-red-300';

                      return (
                        <td key={j} className="p-2">
                          <span className={`inline-block px-2.5 py-1 rounded font-mono text-xs ${bg}`}>
                            {val.toFixed(2)}
                          </span>
                        </td>
                      );
                    })}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  );
};
