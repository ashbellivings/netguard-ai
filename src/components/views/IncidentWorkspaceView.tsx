import React, { useState, useEffect } from 'react';
import { SecurityAlert, AlertStatus } from '../../types';
import {
  ShieldAlert,
  Clock,
  User,
  Plus,
  CheckCircle2,
  AlertTriangle,
  FileText,
  ArrowLeft,
  Terminal,
  Send,
  Database,
} from 'lucide-react';
import { triggerDownload, exportAlertsToSQLiteSQL } from '../../utils/reportExporter';

interface IncidentWorkspaceViewProps {
  alerts: SecurityAlert[];
  selectedAlertId?: string;
  onSelectAlert: (alertId: string) => void;
  onUpdateStatus: (alertId: string, status: AlertStatus, noteText: string, author?: string) => void;
  onAddNote: (alertId: string, noteText: string, author?: string) => void;
  onNavigateToTab: (tab: any) => void;
}

export const IncidentWorkspaceView: React.FC<IncidentWorkspaceViewProps> = ({
  alerts,
  selectedAlertId,
  onSelectAlert,
  onUpdateStatus,
  onNavigateToTab,
}) => {
  const currentAlert = alerts.find(a => a.id === selectedAlertId) || alerts[0];
  const [newNote, setNewNote] = useState('');
  const [selectedStatus, setSelectedStatus] = useState<AlertStatus>(currentAlert?.status || 'New');
  const [analystName, setAnalystName] = useState('Junior SOC Analyst');
  const [savedFeedback, setSavedFeedback] = useState(false);

  useEffect(() => {
    if (currentAlert) {
      setSelectedStatus(currentAlert.status);
    }
  }, [currentAlert?.id, currentAlert?.status]);

  if (!currentAlert) {
    return (
      <div className="p-10 rounded-lg bg-slate-900/90 border border-slate-800 text-center space-y-3">
        <p className="text-sm text-slate-300 font-medium">
          No incidents available to investigate.
        </p>
        <p className="text-xs text-slate-400">
          Run AI Intrusion Detection to classify flows and raise security alerts for triage.
        </p>
        <button
          type="button"
          onClick={() => onNavigateToTab('detection')}
          className="px-4 py-2 bg-cyan-500 hover:bg-cyan-400 text-slate-950 rounded text-xs font-semibold transition-colors cursor-pointer"
        >
          Go to AI Intrusion Detection
        </button>
      </div>
    );
  }

  const hasPendingChanges = selectedStatus !== currentAlert.status || newNote.trim().length > 0;

  const handleSaveInvestigation = (e: React.FormEvent) => {
    e.preventDefault();
    if (!hasPendingChanges) return;
    const author = analystName.trim() || 'Junior SOC Analyst';
    onUpdateStatus(currentAlert.id, selectedStatus, newNote.trim(), author);
    setNewNote('');
    setSavedFeedback(true);
    setTimeout(() => setSavedFeedback(false), 2500);
  };

  const exportIncidentSummary = () => {
    const text = `NETGUARD AI - INCIDENT FORENSIC DOSSIER
==================================================
Incident ID:          ${currentAlert.id}
Detection Timestamp:  ${currentAlert.timestamp}
Investigation Status: ${currentAlert.status}
Severity Rating:      ${currentAlert.severity}
Predicted Threat:     ${currentAlert.predictedCategory} (Confidence: ${(currentAlert.confidence * 100).toFixed(1)}%)

NETWORK TELEMETRY:
- Attacker Source:    ${currentAlert.sourceIp}:${currentAlert.sourcePort}
- Target Destination: ${currentAlert.destinationIp}:${currentAlert.destinationPort}
- Protocol:           ${currentAlert.protocol}
- Packet Count:       ${currentAlert.packetCount.toLocaleString()}
- Byte Volume:        ${currentAlert.byteCount.toLocaleString()} bytes
- Flow Transfer Rate: ${currentAlert.flowRate.toLocaleString()} bytes/sec

DETECTION RATIONALE:
${currentAlert.detectionReason}

RECOMMENDED SOC PLAYBOOK STEPS:
${currentAlert.recommendedActions.map((act, i) => `${i + 1}. ${act}`).join('\n')}

INVESTIGATION AUDIT LOG:
${currentAlert.investigationNotes.map(n => `[${n.timestamp}] ${n.author} (Status: ${n.statusChange || 'Note'}):\n  ${n.text}`).join('\n\n')}

RESOLUTION:
${currentAlert.resolutionSummary || 'Incident under active SOC triage.'}
`;
    triggerDownload(text, `Incident_${currentAlert.id}_Dossier.txt`, 'text/plain');
  };

  const handleExportSQLiteDump = () => {
    const sql = exportAlertsToSQLiteSQL(alerts);
    triggerDownload(sql, 'netguard_soc_incidents.sql', 'application/sql');
  };

  return (
    <div className="space-y-6">
      {/* Title & Incident Selector */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-2 border-b border-slate-850">
        <div>
          <h1 className="text-xl font-bold tracking-tight text-slate-100 flex items-center gap-2">
            <span>SOC Analyst Incident Workspace</span>
            <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-cyan-950 border border-cyan-800 text-cyan-300">
              SQLite Synced
            </span>
          </h1>
          <p className="text-xs text-slate-400 mt-0.5">
            Forensic flow dissection, threat containment playbooks, and structured case notes with persistent SQLite database synchronization.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <select
            value={currentAlert.id}
            onChange={(e) => onSelectAlert(e.target.value)}
            className="px-3 py-1.5 bg-slate-900 border border-slate-750 text-slate-200 rounded text-xs font-mono focus:outline-none focus:border-cyan-500"
          >
            {alerts.map(a => (
              <option key={a.id} value={a.id}>
                {a.id} · {a.predictedCategory} ({a.severity})
              </option>
            ))}
          </select>

          <button
            onClick={handleExportSQLiteDump}
            className="px-3 py-1.5 bg-slate-900 hover:bg-slate-800 text-cyan-300 border border-cyan-800/60 rounded text-xs font-medium transition-colors flex items-center gap-1.5 cursor-pointer"
            title="Download complete SQLite SQL DDL and DML statements"
          >
            <Database className="w-3.5 h-3.5 text-cyan-400" />
            <span>Export SQLite (.sql)</span>
          </button>

          <button
            onClick={exportIncidentSummary}
            className="px-3 py-1.5 bg-slate-900 hover:bg-slate-800 text-slate-200 border border-slate-750 rounded text-xs font-medium transition-colors flex items-center gap-1.5 cursor-pointer"
          >
            <FileText className="w-3.5 h-3.5" />
            <span>Export Dossier</span>
          </button>
        </div>
      </div>

      {/* Main Incident Dossier Split */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
        {/* Left Column: Forensic Packet & Flow Details */}
        <div className="lg:col-span-2 space-y-5">
          {/* Incident Banner Card */}
          <div className="p-5 rounded-lg bg-slate-900/90 border border-slate-800">
            <div className="flex flex-wrap items-center justify-between gap-3 mb-4 pb-3 border-b border-slate-800/80">
              <div className="flex items-center gap-2.5">
                <span className="font-mono text-base font-bold text-cyan-400">
                  {currentAlert.id}
                </span>
                <span className="text-xs text-slate-400">·</span>
                <span className="text-sm font-semibold text-slate-200">
                  {currentAlert.predictedCategory}
                </span>
              </div>

              <div className="flex items-center gap-2">
                <span className={`px-2 py-0.5 rounded text-[10px] font-bold border ${
                  currentAlert.severity === 'CRITICAL'
                    ? 'bg-red-950/60 text-red-400 border-red-500/30'
                    : currentAlert.severity === 'HIGH'
                    ? 'bg-orange-950/60 text-orange-400 border-orange-500/30'
                    : 'bg-amber-950/60 text-amber-400 border-amber-500/30'
                }`}>
                  {currentAlert.severity} SEVERITY
                </span>

                <span className="px-2 py-0.5 rounded text-[10px] font-medium bg-slate-800 text-slate-300">
                  {currentAlert.status}
                </span>
              </div>
            </div>

            {/* Network 5-tuple forensic cards */}
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs mb-4">
              <div className="p-3 rounded bg-slate-950/60 border border-slate-850">
                <div className="text-slate-500 font-medium">Attacking Source</div>
                <div className="text-sm font-bold font-mono text-red-400 mt-1 truncate">
                  {currentAlert.sourceIp}
                </div>
                <div className="text-[10px] text-slate-500 mt-0.5">Port {currentAlert.sourcePort}</div>
              </div>

              <div className="p-3 rounded bg-slate-950/60 border border-slate-850">
                <div className="text-slate-500 font-medium">Victim Destination</div>
                <div className="text-sm font-bold font-mono text-slate-200 mt-1 truncate">
                  {currentAlert.destinationIp}
                </div>
                <div className="text-[10px] text-slate-500 mt-0.5">Port {currentAlert.destinationPort} ({currentAlert.protocol})</div>
              </div>

              <div className="p-3 rounded bg-slate-950/60 border border-slate-850">
                <div className="text-slate-500 font-medium">Traffic Volumetrics</div>
                <div className="text-sm font-bold font-mono text-cyan-400 mt-1">
                  {currentAlert.packetCount} pkts
                </div>
                <div className="text-[10px] text-slate-500 mt-0.5">{(currentAlert.byteCount / 1024).toFixed(1)} KB transferred</div>
              </div>

              <div className="p-3 rounded bg-slate-950/60 border border-slate-850">
                <div className="text-slate-500 font-medium">Model Confidence</div>
                <div className="text-sm font-bold font-mono text-emerald-400 mt-1">
                  {(currentAlert.confidence * 100).toFixed(1)}%
                </div>
                <div className="text-[10px] text-slate-500 mt-0.5">Duration: {currentAlert.flowDuration}s</div>
              </div>
            </div>

            {/* Detection Rationale Box */}
            <div className="p-3.5 rounded bg-slate-950/80 border border-slate-800 text-xs">
              <div className="text-slate-400 font-semibold mb-1 flex items-center gap-1.5">
                <Terminal className="w-3.5 h-3.5 text-cyan-400" />
                <span>Detection Explanation & Signature Rationale</span>
              </div>
              <p className="text-slate-300 leading-relaxed font-sans">
                {currentAlert.detectionReason}
              </p>
            </div>
          </div>

          {/* Recommended Investigation Playbook */}
          <div className="p-5 rounded-lg bg-slate-900/90 border border-slate-800">
            <h3 className="text-sm font-bold text-slate-100 flex items-center gap-2 mb-3">
              <ShieldAlert className="w-4 h-4 text-cyan-400" />
              Standard SOC Investigation Playbook
            </h3>

            <div className="space-y-2.5">
              {currentAlert.recommendedActions.map((step, idx) => (
                <div
                  key={idx}
                  className="flex items-start gap-3 p-3 rounded bg-slate-950/40 border border-slate-850 text-xs"
                >
                  <span className="w-5 h-5 rounded-full bg-slate-800 text-cyan-400 font-mono font-bold flex items-center justify-center shrink-0 mt-0.5 text-[11px]">
                    {idx + 1}
                  </span>
                  <span className="text-slate-300 leading-relaxed font-sans">{step}</span>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Right Column: Case Management & Notes Ledger */}
        <div className="space-y-5">
          {/* Triage Action Box */}
          <form onSubmit={handleSaveInvestigation} className="p-5 rounded-lg bg-slate-900/90 border border-slate-800 space-y-4">
            <h3 className="text-sm font-bold text-slate-100">
              Update Incident Triage Record
            </h3>

            <div>
              <label className="block text-xs text-slate-400 mb-1">Investigation Status</label>
              <select
                value={selectedStatus}
                onChange={(e) => setSelectedStatus(e.target.value as AlertStatus)}
                className="w-full px-3 py-1.5 bg-slate-950 border border-slate-800 rounded text-xs text-slate-200 focus:outline-none focus:border-cyan-500"
              >
                <option value="New">Status: New</option>
                <option value="Investigating">Status: Investigating</option>
                <option value="Resolved">Status: Resolved (Threat Mitigated)</option>
                <option value="False Positive">Status: False Positive (Benign)</option>
              </select>
            </div>

            <div>
              <label className="block text-xs text-slate-400 mb-1">SOC Analyst Identifier</label>
              <input
                type="text"
                value={analystName}
                onChange={(e) => setAnalystName(e.target.value)}
                className="w-full px-3 py-1.5 bg-slate-950 border border-slate-800 rounded text-xs text-slate-200 focus:outline-none focus:border-cyan-500 font-sans"
              />
            </div>

            <div>
              <label className="block text-xs text-slate-400 mb-1">Forensic Investigation Note</label>
              <textarea
                rows={3}
                placeholder="Log findings, PCAP hash, IP block rule ticket, or triage notes..."
                value={newNote}
                onChange={(e) => setNewNote(e.target.value)}
                className="w-full p-2.5 bg-slate-950 border border-slate-800 rounded text-xs text-slate-200 placeholder:text-slate-600 focus:outline-none focus:border-cyan-500"
              />
            </div>

            <button
              type="submit"
              disabled={!hasPendingChanges}
              className={`w-full py-2 rounded text-xs font-semibold transition-colors flex items-center justify-center gap-1.5 shadow-sm cursor-pointer disabled:opacity-50 disabled:cursor-not-allowed ${
                savedFeedback
                  ? 'bg-emerald-500 text-slate-950'
                  : 'bg-cyan-500 hover:bg-cyan-400 text-slate-950'
              }`}
            >
              <CheckCircle2 className="w-3.5 h-3.5" />
              <span>{savedFeedback ? 'Record Saved to Storage!' : 'Save & Persist Record'}</span>
            </button>
          </form>

          {/* Investigation Notes History */}
          <div className="p-5 rounded-lg bg-slate-900/90 border border-slate-800">
            <h3 className="text-sm font-bold text-slate-100 flex items-center gap-2 mb-3">
              <Clock className="w-4 h-4 text-cyan-400" />
              Investigation Audit Log ({currentAlert.investigationNotes.length})
            </h3>

            <div className="space-y-3 max-h-64 overflow-y-auto pr-1">
              {currentAlert.investigationNotes.map((note) => (
                <div key={note.id} className="p-3 rounded bg-slate-950/60 border border-slate-850 text-xs space-y-1">
                  <div className="flex items-center justify-between text-[11px] text-slate-500 font-mono">
                    <span className="text-cyan-400 font-semibold">{note.author}</span>
                    <span>{note.timestamp}</span>
                  </div>
                  <p className="text-slate-300 leading-relaxed font-sans">{note.text}</p>
                  {note.statusChange && (
                    <div className="text-[10px] text-amber-400 pt-1 border-t border-slate-850 font-mono">
                      Status transitioned to: {note.statusChange}
                    </div>
                  )}
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
