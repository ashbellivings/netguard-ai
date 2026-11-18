import React, { useState } from 'react';
import { SecurityAlert, SeverityLevel, AlertStatus } from '../../types';
import {
  Bell,
  Search,
  CheckCircle,
  Clock,
  ShieldX,
  FileSpreadsheet,
  ArrowRight,
  Filter,
} from 'lucide-react';
import { triggerDownload, exportAlertsToCSV } from '../../utils/reportExporter';

interface AlertManagementViewProps {
  alerts: SecurityAlert[];
  onUpdateStatus: (alertId: string, status: AlertStatus, noteText: string) => void;
  onSelectAlert: (alertId: string) => void;
  onNavigateToTab: (tab: any) => void;
}

export const AlertManagementView: React.FC<AlertManagementViewProps> = ({
  alerts,
  onUpdateStatus,
  onSelectAlert,
  onNavigateToTab,
}) => {
  const [severityFilter, setSeverityFilter] = useState<string>('ALL');
  const [statusFilter, setStatusFilter] = useState<string>('ALL');
  const [protocolFilter, setProtocolFilter] = useState<string>('ALL');
  const [searchQuery, setSearchQuery] = useState('');

  const filteredAlerts = alerts.filter((alert) => {
    if (severityFilter !== 'ALL' && alert.severity !== severityFilter) return false;
    if (statusFilter !== 'ALL' && alert.status !== statusFilter) return false;
    if (protocolFilter !== 'ALL' && alert.protocol !== protocolFilter) return false;
    if (searchQuery) {
      const q = searchQuery.toLowerCase();
      return (
        alert.id.toLowerCase().includes(q) ||
        alert.sourceIp.includes(q) ||
        alert.destinationIp.includes(q) ||
        alert.predictedCategory.toLowerCase().includes(q) ||
        alert.detectionReason.toLowerCase().includes(q)
      );
    }
    return true;
  });

  const handleQuickStatusChange = (alertId: string, newStatus: AlertStatus) => {
    onUpdateStatus(alertId, newStatus, `Quick status update to ${newStatus}`);
  };

  return (
    <div className="space-y-6">
      {/* Title */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-2 border-b border-slate-850">
        <div>
          <h1 className="text-xl font-bold tracking-tight text-slate-100 flex items-center gap-2">
            <span>Security Alert Management</span>
          </h1>
          <p className="text-xs text-slate-400 mt-0.5">
            Operational alert triage queue, forensic filtering, severity prioritization, and investigation notes ledger.
          </p>
        </div>

        {alerts.length > 0 && (
          <button
            onClick={() => triggerDownload(exportAlertsToCSV(alerts), 'netguard_security_alerts.csv')}
            className="px-3.5 py-1.5 bg-slate-900 hover:bg-slate-800 text-slate-200 border border-slate-750 rounded text-xs font-medium transition-colors flex items-center gap-1.5 self-start sm:self-auto"
          >
            <FileSpreadsheet className="w-3.5 h-3.5" />
            <span>Export Alerts (CSV)</span>
          </button>
        )}
      </div>

      {/* Filter and Search Bar */}
      <div className="p-4 rounded-lg bg-slate-900/90 border border-slate-800 space-y-3">
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3 text-xs">
          {/* Search Box */}
          <div className="relative">
            <Search className="w-4 h-4 text-slate-500 absolute left-3 top-2.5" />
            <input
              type="text"
              placeholder="Search Alert ID, IP, or threat..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full pl-9 pr-3 py-1.5 bg-slate-950 border border-slate-800 rounded text-xs text-slate-200 placeholder:text-slate-600 focus:outline-none focus:border-cyan-500"
            />
          </div>

          {/* Severity Filter */}
          <div>
            <select
              value={severityFilter}
              onChange={(e) => setSeverityFilter(e.target.value)}
              className="w-full px-3 py-1.5 bg-slate-950 border border-slate-800 rounded text-xs text-slate-200 focus:outline-none focus:border-cyan-500"
            >
              <option value="ALL">All Severities</option>
              <option value="CRITICAL">Critical Severity</option>
              <option value="HIGH">High Severity</option>
              <option value="MEDIUM">Medium Severity</option>
              <option value="LOW">Low Severity</option>
            </select>
          </div>

          {/* Status Filter */}
          <div>
            <select
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value)}
              className="w-full px-3 py-1.5 bg-slate-950 border border-slate-800 rounded text-xs text-slate-200 focus:outline-none focus:border-cyan-500"
            >
              <option value="ALL">All Operational Statuses</option>
              <option value="New">Status: New</option>
              <option value="Investigating">Status: Investigating</option>
              <option value="Resolved">Status: Resolved</option>
              <option value="False Positive">Status: False Positive</option>
            </select>
          </div>

          {/* Protocol Filter */}
          <div>
            <select
              value={protocolFilter}
              onChange={(e) => setProtocolFilter(e.target.value)}
              className="w-full px-3 py-1.5 bg-slate-950 border border-slate-800 rounded text-xs text-slate-200 focus:outline-none focus:border-cyan-500"
            >
              <option value="ALL">All Protocols</option>
              <option value="TCP">TCP</option>
              <option value="UDP">UDP</option>
              <option value="ICMP">ICMP</option>
            </select>
          </div>
        </div>

        <div className="flex items-center justify-between text-xs text-slate-400 pt-2 border-t border-slate-850">
          <span>
            Showing <strong className="text-slate-200">{filteredAlerts.length}</strong> of{' '}
            <strong className="text-slate-200">{alerts.length}</strong> total alerts
          </span>
          <div className="flex items-center gap-2">
            <span className="text-red-400 font-mono font-bold">
              {alerts.filter(a => a.severity === 'CRITICAL').length} Critical
            </span>
            <span>·</span>
            <span className="text-amber-400 font-mono font-bold">
              {alerts.filter(a => a.status === 'Investigating').length} Investigating
            </span>
          </div>
        </div>
      </div>

      {/* Alerts Table */}
      <div className="p-5 rounded-lg bg-slate-900/90 border border-slate-800">
        {filteredAlerts.length > 0 ? (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs border-collapse">
              <thead>
                <tr className="border-b border-slate-800 text-slate-400 uppercase font-mono text-[10px] tracking-wider">
                  <th className="py-2.5 px-3">Alert ID</th>
                  <th className="py-2.5 px-3">Timestamp</th>
                  <th className="py-2.5 px-3">Source IP</th>
                  <th className="py-2.5 px-3">Target IP:Port</th>
                  <th className="py-2.5 px-3">Proto</th>
                  <th className="py-2.5 px-3">Category</th>
                  <th className="py-2.5 px-3">Severity</th>
                  <th className="py-2.5 px-3">Status</th>
                  <th className="py-2.5 px-3 text-right">Triage Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-850 font-mono">
                {filteredAlerts.map((alert) => {
                  let sevClass = 'text-red-400 bg-red-950/40 border-red-500/30';
                  if (alert.severity === 'HIGH') sevClass = 'text-orange-400 bg-orange-950/40 border-orange-500/30';
                  else if (alert.severity === 'MEDIUM') sevClass = 'text-amber-400 bg-amber-950/40 border-amber-500/30';
                  else if (alert.severity === 'LOW') sevClass = 'text-emerald-400 bg-emerald-950/40 border-emerald-500/30';

                  let statusBadge = 'text-slate-400 bg-slate-800/80';
                  if (alert.status === 'Investigating') statusBadge = 'text-amber-300 bg-amber-950/50 border border-amber-500/30';
                  else if (alert.status === 'Resolved') statusBadge = 'text-emerald-300 bg-emerald-950/50 border border-emerald-500/30';
                  else if (alert.status === 'False Positive') statusBadge = 'text-slate-400 bg-slate-900 border border-slate-700';

                  return (
                    <tr key={alert.id} className="hover:bg-slate-850/40 transition-colors">
                      <td className="py-2.5 px-3 font-bold text-slate-200">
                        <button
                          onClick={() => {
                            onSelectAlert(alert.id);
                            onNavigateToTab('incidents');
                          }}
                          className="hover:text-cyan-400 underline underline-offset-2"
                        >
                          {alert.id}
                        </button>
                      </td>
                      <td className="py-2.5 px-3 text-slate-400">{alert.timestamp}</td>
                      <td className="py-2.5 px-3 text-red-300 font-semibold">{alert.sourceIp}</td>
                      <td className="py-2.5 px-3 text-slate-300">
                        {alert.destinationIp}:{alert.destinationPort}
                      </td>
                      <td className="py-2.5 px-3 text-cyan-400">{alert.protocol}</td>
                      <td className="py-2.5 px-3 font-sans text-slate-200">{alert.predictedCategory}</td>
                      <td className="py-2.5 px-3">
                        <span className={`inline-block px-1.5 py-0.5 rounded text-[10px] font-bold border ${sevClass}`}>
                          {alert.severity}
                        </span>
                      </td>
                      <td className="py-2.5 px-3 font-sans">
                        <span className={`inline-block px-2 py-0.5 rounded text-[10px] font-medium ${statusBadge}`}>
                          {alert.status}
                        </span>
                      </td>
                      <td className="py-2.5 px-3 text-right font-sans">
                        <div className="flex items-center justify-end gap-1.5">
                          <button
                            onClick={() => handleQuickStatusChange(alert.id, 'Investigating')}
                            title="Mark as Investigating"
                            className="p-1 hover:bg-slate-800 rounded text-amber-400 hover:text-amber-300 transition-colors"
                          >
                            <Clock className="w-3.5 h-3.5" />
                          </button>
                          <button
                            onClick={() => handleQuickStatusChange(alert.id, 'Resolved')}
                            title="Mark as Resolved"
                            className="p-1 hover:bg-slate-800 rounded text-emerald-400 hover:text-emerald-300 transition-colors"
                          >
                            <CheckCircle className="w-3.5 h-3.5" />
                          </button>
                          <button
                            onClick={() => handleQuickStatusChange(alert.id, 'False Positive')}
                            title="Mark as False Positive"
                            className="p-1 hover:bg-slate-800 rounded text-slate-400 hover:text-slate-300 transition-colors"
                          >
                            <ShieldX className="w-3.5 h-3.5" />
                          </button>
                          <button
                            onClick={() => {
                              onSelectAlert(alert.id);
                              onNavigateToTab('incidents');
                            }}
                            className="px-2 py-1 bg-slate-800 hover:bg-slate-700 text-cyan-400 rounded text-[11px] font-medium transition-colors ml-1"
                          >
                            Investigate
                          </button>
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="p-8 text-center text-xs text-slate-400 space-y-3">
            {alerts.length === 0 ? (
              <>
                <p>No security alerts generated yet. Run Intrusion Detection to analyze network flows.</p>
                <button
                  type="button"
                  onClick={() => onNavigateToTab('detection')}
                  className="px-3.5 py-1.5 bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-semibold rounded text-xs transition-colors cursor-pointer"
                >
                  Go to AI Intrusion Detection
                </button>
              </>
            ) : (
              <>
                <p>No alerts match current search and filter criteria.</p>
                <button
                  type="button"
                  onClick={() => {
                    setSeverityFilter('ALL');
                    setStatusFilter('ALL');
                    setProtocolFilter('ALL');
                    setSearchQuery('');
                  }}
                  className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded text-xs transition-colors cursor-pointer"
                >
                  Reset Filters
                </button>
              </>
            )}
          </div>
        )}
      </div>
    </div>
  );
};
