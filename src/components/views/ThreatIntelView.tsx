import React from 'react';
import { SecurityAlert, FlowRecord, ModelMetrics } from '../../types';
import { Globe2, ShieldAlert, AlertTriangle, ArrowRight } from 'lucide-react';

interface ThreatIntelViewProps {
  alerts: SecurityAlert[];
  flows: FlowRecord[];
  metrics?: ModelMetrics;
  onNavigateToTab: (tab: any) => void;
}

export const ThreatIntelView: React.FC<ThreatIntelViewProps> = ({
  alerts,
  flows,
  metrics,
  onNavigateToTab,
}) => {
  const totalAlerts = alerts.length;

  // Attack category frequency
  const catCounts: Record<string, number> = {};
  alerts.forEach(a => {
    catCounts[a.predictedCategory] = (catCounts[a.predictedCategory] || 0) + 1;
  });

  // Top targeted ports
  const portCounts: Record<number, { count: number; protocol: string }> = {};
  alerts.forEach(a => {
    if (!portCounts[a.destinationPort]) {
      portCounts[a.destinationPort] = { count: 0, protocol: a.protocol };
    }
    portCounts[a.destinationPort].count++;
  });
  const topPorts = Object.entries(portCounts)
    .sort((a, b) => b[1].count - a[1].count)
    .slice(0, 6);

  // Top attacking IPs with threat vector profile
  const ipProfiles: Record<string, { count: number; categories: Set<string>; severities: Set<string> }> = {};
  alerts.forEach(a => {
    if (!ipProfiles[a.sourceIp]) {
      ipProfiles[a.sourceIp] = { count: 0, categories: new Set(), severities: new Set() };
    }
    ipProfiles[a.sourceIp].count++;
    ipProfiles[a.sourceIp].categories.add(a.predictedCategory);
    ipProfiles[a.sourceIp].severities.add(a.severity);
  });

  const topAttackingIps = Object.entries(ipProfiles)
    .sort((a, b) => b[1].count - a[1].count)
    .slice(0, 6);

  if (flows.length === 0 || alerts.length === 0) {
    return (
      <div className="p-10 rounded-lg bg-slate-900/90 border border-slate-800 text-center space-y-3">
        <p className="text-sm text-slate-200 font-semibold">
          {flows.length === 0 ? 'No Network Telemetry Loaded' : 'No Threat Intelligence Alerts Flagged'}
        </p>
        <p className="text-xs text-slate-400">
          {flows.length === 0
            ? 'Load the demonstration dataset or upload a custom CSV capture to analyze threat infrastructure.'
            : 'All analyzed flows were classified as benign, or intrusion detection inference has not been run yet.'}
        </p>
        <button
          type="button"
          onClick={() => onNavigateToTab(flows.length === 0 ? 'data_management' : 'detection')}
          className="px-4 py-2 bg-cyan-500 hover:bg-cyan-400 text-slate-950 rounded text-xs font-semibold transition-colors cursor-pointer"
        >
          {flows.length === 0 ? 'Open Traffic Data Management' : 'Open AI Intrusion Detection'}
        </button>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Title */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-2 border-b border-slate-850">
        <div>
          <h1 className="text-xl font-bold tracking-tight text-slate-100 flex items-center gap-2">
            <span>Threat Intelligence & Attack Profiling</span>
          </h1>
          <p className="text-xs text-slate-400 mt-0.5">
            Tactical threat signatures, attacker infrastructure profiling, targeted service analysis, and trade-off metrics.
          </p>
        </div>

        <button
          onClick={() => onNavigateToTab('reports')}
          className="px-3.5 py-1.5 bg-cyan-500 hover:bg-cyan-400 text-slate-950 rounded text-xs font-semibold transition-colors flex items-center gap-1.5 self-start sm:self-auto"
        >
          <span>Generate Threat Report</span>
          <ArrowRight className="w-3.5 h-3.5" />
        </button>
      </div>

      {/* Top Attacker IP Profiles */}
      <div className="p-5 rounded-lg bg-slate-900/90 border border-slate-800">
        <h3 className="text-sm font-bold text-slate-100 mb-1 flex items-center gap-2">
          <Globe2 className="w-4 h-4 text-cyan-400" />
          Primary Adversary Infrastructure (Top Flagged Source IPs)
        </h3>
        <p className="text-xs text-slate-400 mb-4">
          Identified adversary endpoints executing automated network reconnaissance and exploitation campaigns
        </p>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3.5">
          {topAttackingIps.map(([ip, data]) => (
            <div
              key={ip}
              className="p-4 rounded-lg bg-slate-950/70 border border-slate-850 space-y-2 text-xs"
            >
              <div className="flex items-center justify-between">
                <code className="text-sm font-bold font-mono text-red-400">{ip}</code>
                <span className="text-[10px] uppercase font-mono px-1.5 py-0.5 rounded bg-red-950/60 text-red-300 border border-red-500/30">
                  {data.count} Incidents
                </span>
              </div>

              <div className="text-slate-400">
                <span className="font-semibold text-slate-300">Threat Tactics: </span>
                {Array.from(data.categories).join(', ')}
              </div>

              <div className="flex items-center gap-1.5 pt-2 border-t border-slate-850 text-[11px]">
                <span className="text-slate-500">Max Severity:</span>
                <span className="font-mono text-amber-400 font-bold">
                  {data.severities.has('CRITICAL') ? 'CRITICAL' : data.severities.has('HIGH') ? 'HIGH' : 'MEDIUM'}
                </span>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Attack Category Taxonomy & Targeted Service Ports */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
        {/* Attack Category Taxonomy */}
        <div className="p-5 rounded-lg bg-slate-900/90 border border-slate-800">
          <h3 className="text-sm font-bold text-slate-100 mb-3">
            Threat Taxonomy Breakdown
          </h3>
          <div className="space-y-3">
            {Object.entries(catCounts).map(([cat, count]) => {
              const pct = (count / Math.max(totalAlerts, 1)) * 100;
              return (
                <div key={cat} className="space-y-1 text-xs">
                  <div className="flex justify-between">
                    <span className="font-semibold text-slate-200">{cat}</span>
                    <span className="font-mono text-cyan-400">
                      {count} ({pct.toFixed(1)}%)
                    </span>
                  </div>
                  <div className="w-full h-2 bg-slate-950 rounded-full overflow-hidden">
                    <div className="h-full bg-red-500" style={{ width: `${pct}%` }} />
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* Targeted Destination Service Ports */}
        <div className="p-5 rounded-lg bg-slate-900/90 border border-slate-800">
          <h3 className="text-sm font-bold text-slate-100 mb-3">
            Targeted Critical Ports & Services
          </h3>
          <div className="space-y-2.5">
            {topPorts.map(([port, data]) => {
              const pNum = parseInt(port, 10);
              let sName = 'Application Service';
              if (pNum === 22) sName = 'SSH Remote Administration';
              else if (pNum === 3389) sName = 'Windows Remote Desktop (RDP)';
              else if (pNum === 80 || pNum === 8080) sName = 'HTTP Web Server';
              else if (pNum === 443) sName = 'HTTPS Web Server';
              else if (pNum === 445) sName = 'Microsoft SMB File Sharing';
              else if (pNum === 4444) sName = 'Metasploit Default C2 Listener';
              else if (pNum === 21) sName = 'FTP File Transfer';

              return (
                <div key={port} className="p-3 rounded bg-slate-950/60 border border-slate-850 flex items-center justify-between text-xs">
                  <div>
                    <span className="font-mono font-bold text-slate-200">Port {port} ({data.protocol})</span>
                    <div className="text-[11px] text-slate-400">{sName}</div>
                  </div>
                  <span className="font-mono text-cyan-400 font-bold">{data.count} attacks</span>
                </div>
              );
            })}
          </div>
        </div>
      </div>

      {/* FP / FN Trade-Off Analysis */}
      <div className="p-5 rounded-lg bg-slate-900/90 border border-slate-800">
        <h3 className="text-sm font-bold text-slate-100 mb-2">
          False Positive vs. False Negative Operational Trade-Off
        </h3>
        <p className="text-xs text-slate-400 mb-4">
          A fundamental challenge in enterprise SOC engineering is balancing threat sensitivity against analyst alert overload.
        </p>

        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 text-xs">
          <div className="p-4 rounded-lg bg-amber-950/20 border border-amber-500/20">
            <h4 className="font-bold text-amber-400 mb-1">
              High False Positives (Analyst Alert Fatigue)
            </h4>
            <p className="text-slate-300 leading-relaxed">
              When the detection engine uses overly aggressive anomaly thresholds, benign transfers trigger false alarms. Junior analysts waste time investigating legitimate developer queries, causing genuine attacks to be overlooked in the queue.
            </p>
          </div>

          <div className="p-4 rounded-lg bg-red-950/20 border border-red-500/20">
            <h4 className="font-bold text-red-400 mb-1">
              High False Negatives (Undetected Compromise)
            </h4>
            <p className="text-slate-300 leading-relaxed">
              When models are calibrated too conservatively, stealthy low-and-slow port sweeps, C2 beaconing, or distributed DoS floods pass unrecognized as normal traffic. This leads to dwell time and catastrophic lateral network breach.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
};
