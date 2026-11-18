import React, { useState, useRef } from 'react';
import { SecurityAlert, CleanedFlowRecord, ModelMetrics, EDAFinding } from '../../types';
import { FileText, Download, Printer, ShieldAlert, Database, X } from 'lucide-react';
import {
  triggerDownload,
  exportAlertsToCSV,
  exportCleanedDatasetToCSV,
  generateExecutiveReportHTML,
  exportAlertsToSQLiteSQL,
} from '../../utils/reportExporter';

interface ReportGeneratorViewProps {
  datasetName: string;
  totalFlows: number;
  normalCount: number;
  suspiciousCount: number;
  alerts: SecurityAlert[];
  cleanedFlows: CleanedFlowRecord[];
  metrics?: ModelMetrics;
  findings: EDAFinding[];
}

export const ReportGeneratorView: React.FC<ReportGeneratorViewProps> = ({
  datasetName,
  totalFlows,
  normalCount,
  suspiciousCount,
  alerts,
  cleanedFlows,
  metrics,
  findings,
}) => {
  const [previewHtml, setPreviewHtml] = useState<string | null>(null);
  const printFrameRef = useRef<HTMLIFrameElement>(null);

  const handlePrintExecutiveReport = () => {
    const htmlContent = generateExecutiveReportHTML({
      datasetName,
      totalFlows,
      normalCount,
      suspiciousCount,
      alerts,
      metrics,
      findings,
    });
    setPreviewHtml(htmlContent);
  };

  const handlePrintFromModal = () => {
    if (printFrameRef.current?.contentWindow) {
      printFrameRef.current.contentWindow.focus();
      printFrameRef.current.contentWindow.print();
    }
  };

  const handleDownloadTextReport = () => {
    const nowStr = new Date().toISOString().replace('T', ' ').substring(0, 19);
    const critCount = alerts.filter(a => a.severity === 'CRITICAL').length;
    const highCount = alerts.filter(a => a.severity === 'HIGH').length;

    const reportText = `==============================================================================
NETGUARD AI - EXECUTIVE CYBERSECURITY AUDIT REPORT
==============================================================================
Generated: ${nowStr} UTC
Dataset:   ${datasetName}
Project:   B.Sc. Computer Science Cybersecurity Capstone Project
------------------------------------------------------------------------------

1. TRAFFIC FLOW OVERVIEW:
- Total Flows Analyzed:      ${totalFlows.toLocaleString()}
- Normal / Benign Flows:    ${normalCount.toLocaleString()} (${((normalCount / Math.max(totalFlows, 1)) * 100).toFixed(1)}%)
- Suspicious Threats:       ${suspiciousCount.toLocaleString()} (${((suspiciousCount / Math.max(totalFlows, 1)) * 100).toFixed(1)}%)
- Security Alerts Raised:   ${alerts.length}

2. SEVERITY BREAKDOWN:
- CRITICAL Severity:        ${critCount}
- HIGH Severity:            ${highCount}
- MEDIUM Severity:          ${alerts.filter(a => a.severity === 'MEDIUM').length}
- LOW Severity:             ${alerts.filter(a => a.severity === 'LOW').length}

3. ACTIVE CLASSIFIER BENCHMARK:
- Algorithm:                ${metrics ? metrics.algorithmName : 'Trained Classifier'}
- Hold-Out Accuracy:        ${metrics ? (metrics.accuracy * 100).toFixed(2) + '%' : 'Pending Evaluation'}
- F1-Score:                 ${metrics ? (metrics.f1Score * 100).toFixed(2) + '%' : 'Pending Evaluation'}
- Precision:                ${metrics ? (metrics.precision * 100).toFixed(2) + '%' : 'Pending Evaluation'}
- Recall:                   ${metrics ? (metrics.recall * 100).toFixed(2) + '%' : 'Pending Evaluation'}
- False Positive Rate:      ${metrics ? (metrics.falsePositiveRate * 100).toFixed(2) + '%' : 'Pending Evaluation'}

4. AUTOMATED SECURITY DATA FINDINGS:
${findings.map((f, i) => `[${i + 1}] ${f.title} (${f.metric})\n    ${f.description}`).join('\n\n')}

5. TOP INCIDENT INVESTIGATION LOGS:
${alerts.slice(0, 10).map(a => `* ${a.id} [${a.severity}] ${a.predictedCategory} from ${a.sourceIp} -> ${a.destinationIp}:${a.destinationPort} (${a.status})`).join('\n')}

6. RECOMMENDED REMEDIATION ACTIONS:
1. Block identified attacker IPs at edge security gateway.
2. Enforce MFA on administrative SSH (22) and RDP (3389) endpoints.
3. Deploy WAF virtual patches against SQL injection probes.
4. Quarantine internal hosts displaying C2 beaconing.

7. SYSTEM LIMITATIONS:
- Flow metadata inspection only (packet payloads and TLS payload encryption out of scope).
- Models require periodic retraining to prevent concept drift on novel attack techniques.
==============================================================================
END OF REPORT - NETGUARD AI
`;

    triggerDownload(reportText, `NETGUARD_AI_Report_${Date.now()}.txt`, 'text/plain');
  };

  return (
    <div className="space-y-6">
      {/* Title */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-2 border-b border-slate-850">
        <div>
          <h1 className="text-xl font-bold tracking-tight text-slate-100 flex items-center gap-2">
            <span>Security Report Generation</span>
          </h1>
          <p className="text-xs text-slate-400 mt-0.5">
            Download forensic CSV datasets, export alert audit logs, and print executive PDF incident reports.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={handlePrintExecutiveReport}
            className="px-3.5 py-1.5 bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-semibold rounded text-xs transition-colors flex items-center gap-1.5 shadow-sm"
          >
            <Printer className="w-3.5 h-3.5" />
            <span>Print Executive PDF Report</span>
          </button>
        </div>
      </div>

      {/* Download Cards Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Card 1: Executive PDF / Printable */}
        <div className="p-5 rounded-lg bg-slate-900/90 border border-slate-800 flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between text-xs text-cyan-400 font-bold mb-2">
              <span className="flex items-center gap-1.5">
                <FileText className="w-4 h-4" />
                <span>Executive Dossier</span>
              </span>
              <span className="text-[10px] uppercase font-mono px-1.5 py-0.2 rounded bg-cyan-950 text-cyan-300 border border-cyan-800">
                PDF / Print
              </span>
            </div>
            <h3 className="text-sm font-bold text-slate-100">SOC Management Report</h3>
            <p className="text-xs text-slate-400 mt-1 leading-relaxed">
              Formatted executive briefing including KPI summaries, model benchmarks, top 10 security findings, active threats, and playbook recommendations.
            </p>
          </div>

          <div className="mt-4 pt-3 border-t border-slate-800/80 flex flex-col gap-2">
            <button
              onClick={handlePrintExecutiveReport}
              className="w-full py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded text-xs font-medium transition-colors flex items-center justify-center gap-1.5"
            >
              <Printer className="w-3.5 h-3.5 text-cyan-400" />
              <span>Open Printable PDF View</span>
            </button>
            <button
              onClick={handleDownloadTextReport}
              className="w-full py-2 bg-slate-950 hover:bg-slate-900 text-slate-300 border border-slate-800 rounded text-xs font-medium transition-colors flex items-center justify-center gap-1.5"
            >
              <Download className="w-3.5 h-3.5" />
              <span>Download Text Report (.txt)</span>
            </button>
          </div>
        </div>

        {/* Card 2: Security Alerts CSV */}
        <div className="p-5 rounded-lg bg-slate-900/90 border border-slate-800 flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between text-xs text-amber-400 font-bold mb-2">
              <span className="flex items-center gap-1.5">
                <ShieldAlert className="w-4 h-4" />
                <span>Audit Logs</span>
              </span>
              <span className="text-[10px] uppercase font-mono px-1.5 py-0.2 rounded bg-amber-950 text-amber-300 border border-amber-800">
                CSV
              </span>
            </div>
            <h3 className="text-sm font-bold text-slate-100">Security Alerts Export</h3>
            <p className="text-xs text-slate-400 mt-1 leading-relaxed">
              Complete tabular export of all {alerts.length} security alerts, source/target 5-tuples, model confidence scores, assigned severity, and analyst notes.
            </p>
          </div>

          <div className="mt-4 pt-3 border-t border-slate-800/80">
            <button
              onClick={() => triggerDownload(exportAlertsToCSV(alerts), 'netguard_security_alerts.csv')}
              disabled={alerts.length === 0}
              className="w-full py-2 bg-slate-800 hover:bg-slate-700 disabled:opacity-50 text-slate-200 rounded text-xs font-medium transition-colors flex items-center justify-center gap-1.5"
            >
              <Download className="w-3.5 h-3.5 text-amber-400" />
              <span>Download Alerts CSV ({alerts.length})</span>
            </button>
          </div>
        </div>

        {/* Card 3: Preprocessed Flow Records CSV */}
        <div className="p-5 rounded-lg bg-slate-900/90 border border-slate-800 flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between text-xs text-emerald-400 font-bold mb-2">
              <span className="flex items-center gap-1.5">
                <Download className="w-4 h-4" />
                <span>Feature Data</span>
              </span>
              <span className="text-[10px] uppercase font-mono px-1.5 py-0.2 rounded bg-emerald-950 text-emerald-300 border border-emerald-800">
                CSV
              </span>
            </div>
            <h3 className="text-sm font-bold text-slate-100">Cleaned Dataset Export</h3>
            <p className="text-xs text-slate-400 mt-1 leading-relaxed">
              Export preprocessed and normalized feature vectors, log-scaled packets/bytes, and one-hot encoded transport protocols ready for machine learning.
            </p>
          </div>

          <div className="mt-4 pt-3 border-t border-slate-800/80">
            <button
              onClick={() => triggerDownload(exportCleanedDatasetToCSV(cleanedFlows), 'netguard_cleaned_traffic.csv')}
              disabled={cleanedFlows.length === 0}
              className="w-full py-2 bg-slate-800 hover:bg-slate-700 disabled:opacity-50 text-slate-200 rounded text-xs font-medium transition-colors flex items-center justify-center gap-1.5 cursor-pointer"
            >
              <Download className="w-3.5 h-3.5 text-emerald-400" />
              <span>Download Cleaned Dataset ({cleanedFlows.length})</span>
            </button>
          </div>
        </div>

        {/* Card 4: SQLite Database Script (.sql) */}
        <div className="p-5 rounded-lg bg-slate-900/90 border border-slate-800 flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between text-xs text-cyan-400 font-bold mb-2">
              <span className="flex items-center gap-1.5">
                <Database className="w-4 h-4 text-cyan-400" />
                <span>SQLite DB</span>
              </span>
              <span className="text-[10px] uppercase font-mono px-1.5 py-0.2 rounded bg-cyan-950 text-cyan-300 border border-cyan-800">
                .SQL
              </span>
            </div>
            <h3 className="text-sm font-bold text-slate-100">SQLite Incident Dump</h3>
            <p className="text-xs text-slate-400 mt-1 leading-relaxed">
              Export complete SQL schema DDL and DML statements with foreign keys, alert records, and triage case notes for SQLite3.
            </p>
          </div>

          <div className="mt-4 pt-3 border-t border-slate-800/80">
            <button
              onClick={() => triggerDownload(exportAlertsToSQLiteSQL(alerts), 'netguard_soc_incidents.sql', 'application/sql')}
              disabled={alerts.length === 0}
              className="w-full py-2 bg-slate-800 hover:bg-slate-700 disabled:opacity-50 text-cyan-300 rounded text-xs font-medium transition-colors flex items-center justify-center gap-1.5 cursor-pointer"
            >
              <Download className="w-3.5 h-3.5 text-cyan-400" />
              <span>Download SQLite Script ({alerts.length})</span>
            </button>
          </div>
        </div>
      </div>

      {/* Report Preview Window */}
      <div className="p-5 rounded-lg bg-slate-900/90 border border-slate-800">
        <h3 className="text-sm font-bold text-slate-100 mb-2">
          Report Content Overview & Metadata Inspection
        </h3>
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs mb-4">
          <div className="p-3 rounded bg-slate-950/60 border border-slate-850">
            <div className="text-slate-500 font-medium">Dataset Name</div>
            <div className="text-xs font-bold font-mono text-slate-200 mt-1 truncate">
              {datasetName}
            </div>
          </div>
          <div className="p-3 rounded bg-slate-950/60 border border-slate-850">
            <div className="text-slate-500 font-medium">Total Flows</div>
            <div className="text-base font-bold font-mono text-cyan-400 mt-1">
              {totalFlows.toLocaleString()}
            </div>
          </div>
          <div className="p-3 rounded bg-slate-950/60 border border-slate-850">
            <div className="text-slate-500 font-medium">Active Classifier</div>
            <div className="text-xs font-bold font-mono text-slate-200 mt-1 truncate">
              {metrics ? metrics.algorithmName : 'Trained Classifier'}
            </div>
          </div>
          <div className="p-3 rounded bg-slate-950/60 border border-slate-850">
            <div className="text-slate-500 font-medium">Security Findings</div>
            <div className="text-base font-bold font-mono text-emerald-400 mt-1">
              {findings.length} Derived
            </div>
          </div>
        </div>

        <div className="p-4 rounded bg-slate-950 border border-slate-850 font-mono text-xs text-slate-300 max-h-64 overflow-y-auto leading-relaxed">
          <div className="text-cyan-400 font-bold mb-2">
            [PREVIEW] NETGUARD AI EXECUTIVE CYBERSECURITY AUDIT REPORT
          </div>
          <div>======================================================================</div>
          <div>Dataset: {datasetName}</div>
          <div>Total Monitored Flows: {totalFlows.toLocaleString()}</div>
          <div>Normal Baseline: {normalCount.toLocaleString()} ({((normalCount / Math.max(totalFlows, 1)) * 100).toFixed(1)}%)</div>
          <div>Suspicious Flagged: {suspiciousCount.toLocaleString()} ({((suspiciousCount / Math.max(totalFlows, 1)) * 100).toFixed(1)}%)</div>
          <div>Active Alerts: {alerts.length} (Critical: {alerts.filter(a => a.severity === 'CRITICAL').length}, High: {alerts.filter(a => a.severity === 'HIGH').length})</div>
          <div>Hold-out Evaluation Accuracy: {metrics ? (metrics.accuracy * 100).toFixed(1) + '%' : 'Pending'}</div>
          <div>----------------------------------------------------------------------</div>
          <div className="mt-2 text-slate-400">
            Top Derived Findings:
          </div>
          {findings.slice(0, 4).map((f, i) => (
            <div key={i} className="text-slate-300 mt-1">
              * {f.title}: {f.metric} — {f.description}
            </div>
          ))}
        </div>
      </div>

      {/* In-App Printable Executive Report Modal (iFrame-safe, no window.open) */}
      {previewHtml && (
        <div className="fixed inset-0 z-50 bg-slate-950/85 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-xl w-full max-w-5xl h-[88vh] flex flex-col shadow-2xl overflow-hidden">
            <div className="flex items-center justify-between px-5 py-3.5 border-b border-slate-800 bg-slate-950/70">
              <div className="flex items-center gap-2.5">
                <FileText className="w-4 h-4 text-cyan-400" />
                <span className="text-sm font-bold text-slate-100">
                  Executive Cybersecurity Incident Report Preview
                </span>
              </div>
              <div className="flex items-center gap-2">
                <button
                  onClick={() => triggerDownload(previewHtml, `NETGUARD_Executive_Report_${Date.now()}.html`, 'text/html;charset=utf-8;')}
                  className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded text-xs font-medium flex items-center gap-1.5 cursor-pointer"
                >
                  <Download className="w-3.5 h-3.5 text-cyan-400" />
                  <span>Download HTML</span>
                </button>
                <button
                  onClick={handlePrintFromModal}
                  className="px-3.5 py-1.5 bg-cyan-500 hover:bg-cyan-400 text-slate-950 rounded text-xs font-semibold flex items-center gap-1.5 cursor-pointer"
                >
                  <Printer className="w-3.5 h-3.5" />
                  <span>Print / Save as PDF</span>
                </button>
                <button
                  onClick={() => setPreviewHtml(null)}
                  className="p-1.5 rounded text-slate-400 hover:text-slate-100 hover:bg-slate-800 transition-colors cursor-pointer"
                  aria-label="Close report preview"
                >
                  <X className="w-4 h-4" />
                </button>
              </div>
            </div>
            <iframe
              ref={printFrameRef}
              title="NETGUARD AI Executive Report"
              srcDoc={previewHtml}
              className="w-full flex-1 bg-white border-0"
            />
          </div>
        </div>
      )}
    </div>
  );
};
