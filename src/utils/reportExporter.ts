import { SecurityAlert, CleanedFlowRecord, ModelMetrics, EDAFinding } from '../types';

/**
 * Escapes HTML special characters to prevent XSS in generated HTML reports
 */
export function escapeHtml(value: string | number | undefined | null): string {
  if (value === undefined || value === null) return '';
  return String(value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

/**
 * Escapes a CSV cell and neutralizes spreadsheet formula injection (CWE-1236)
 */
export function escapeCsvCell(value: string | number | undefined | null): string {
  if (value === undefined || value === null) return '""';
  let str = String(value);
  if (/^[=+\-@\t\r]/.test(str)) {
    str = `'${str}`;
  }
  if (/[",\n\r]/.test(str) || str.startsWith("'")) {
    return `"${str.replace(/"/g, '""')}"`;
  }
  return str;
}

/**
 * Generates CSV string of security alerts for SOC audit export
 */
export function exportAlertsToCSV(alerts: SecurityAlert[]): string {
  const headers = [
    'Alert_ID',
    'Timestamp',
    'Source_IP',
    'Destination_IP',
    'Source_Port',
    'Destination_Port',
    'Protocol',
    'Predicted_Category',
    'Severity',
    'Status',
    'Confidence',
    'Packet_Count',
    'Byte_Count',
    'Flow_Rate',
    'Detection_Reason',
    'Latest_Notes'
  ];

  const rows = alerts.map(a => {
    const latestNoteText = a.investigationNotes.length > 0
      ? a.investigationNotes[a.investigationNotes.length - 1].text
      : '';

    return [
      escapeCsvCell(a.id),
      escapeCsvCell(a.timestamp),
      escapeCsvCell(a.sourceIp),
      escapeCsvCell(a.destinationIp),
      a.sourcePort,
      a.destinationPort,
      escapeCsvCell(a.protocol),
      escapeCsvCell(a.predictedCategory),
      escapeCsvCell(a.severity),
      escapeCsvCell(a.status),
      a.confidence.toFixed(2),
      a.packetCount,
      a.byteCount,
      a.flowRate,
      escapeCsvCell(a.detectionReason),
      escapeCsvCell(latestNoteText)
    ].join(',');
  });

  return [headers.join(','), ...rows].join('\n');
}

/**
 * Generates CSV of cleaned, preprocessed network flows
 */
export function exportCleanedDatasetToCSV(flows: CleanedFlowRecord[]): string {
  const headers = [
    'Flow_ID',
    'Timestamp',
    'Source_IP',
    'Destination_IP',
    'Source_Port',
    'Destination_Port',
    'Protocol',
    'Duration_Sec',
    'Packet_Count',
    'Byte_Count',
    'Flow_Rate_Bps',
    'Ground_Truth_Label',
    'Attack_Category',
    'Norm_Duration',
    'Norm_Packets',
    'Norm_Bytes',
    'Norm_Rate'
  ];

  const rows = flows.map(f => [
    escapeCsvCell(f.id),
    escapeCsvCell(f.timestamp),
    escapeCsvCell(f.sourceIp),
    escapeCsvCell(f.destinationIp),
    f.sourcePort,
    f.destinationPort,
    escapeCsvCell(f.protocol),
    f.flowDuration,
    f.packetCount,
    f.byteCount,
    f.flowRate,
    escapeCsvCell(f.label),
    escapeCsvCell(f.attackCategory || 'Normal'),
    f.normalizedDuration.toFixed(4),
    f.normalizedPackets.toFixed(4),
    f.normalizedBytes.toFixed(4),
    f.normalizedRate.toFixed(4)
  ].join(','));

  return [headers.join(','), ...rows].join('\n');
}

/**
 * Triggers a direct browser file download
 */
export function triggerDownload(content: string, filename: string, mimeType: string = 'text/csv;charset=utf-8;'): void {
  const blob = new Blob([content], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.setAttribute('href', url);
  link.setAttribute('download', filename);
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  URL.revokeObjectURL(url);
}

/**
 * Opens formatted printable HTML Executive Report in a popup/tab for Print to PDF
 */
export function generateExecutiveReportHTML(params: {
  datasetName: string;
  totalFlows: number;
  normalCount: number;
  suspiciousCount: number;
  alerts: SecurityAlert[];
  metrics?: ModelMetrics;
  findings: EDAFinding[];
}): string {
  const { datasetName, totalFlows, normalCount, suspiciousCount, alerts, metrics, findings } = params;
  const genTime = new Date().toISOString().replace('T', ' ').substring(0, 19);

  const criticalCount = alerts.filter(a => a.severity === 'CRITICAL').length;
  const highCount = alerts.filter(a => a.severity === 'HIGH').length;
  const mediumCount = alerts.filter(a => a.severity === 'MEDIUM').length;
  const lowCount = alerts.filter(a => a.severity === 'LOW').length;

  const resolvedCount = alerts.filter(a => a.status === 'Resolved').length;
  const investigatingCount = alerts.filter(a => a.status === 'Investigating').length;
  const fpCount = alerts.filter(a => a.status === 'False Positive').length;
  const newCount = alerts.filter(a => a.status === 'New').length;

  return `<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>NETGUARD AI - Executive Cybersecurity Incident Report</title>
  <style>
    body {
      font-family: 'Helvetica Neue', Arial, sans-serif;
      color: #1e293b;
      background: #ffffff;
      margin: 40px;
      line-height: 1.6;
    }
    .header {
      border-bottom: 3px solid #0f172a;
      padding-bottom: 20px;
      margin-bottom: 30px;
      display: flex;
      justify-content: space-between;
      align-items: flex-end;
    }
    .header h1 {
      margin: 0;
      color: #0f172a;
      font-size: 26px;
      letter-spacing: -0.5px;
    }
    .header p {
      margin: 4px 0 0;
      color: #64748b;
      font-size: 13px;
    }
    .badge {
      display: inline-block;
      padding: 4px 10px;
      background: #0ea5e9;
      color: #fff;
      font-weight: bold;
      font-size: 12px;
      border-radius: 4px;
    }
    .grid {
      display: grid;
      grid-template-columns: repeat(4, 1fr);
      gap: 15px;
      margin-bottom: 30px;
    }
    .card {
      border: 1px solid #e2e8f0;
      border-radius: 8px;
      padding: 16px;
      background: #f8fafc;
    }
    .card-label {
      font-size: 11px;
      text-transform: uppercase;
      color: #64748b;
      font-weight: 600;
    }
    .card-val {
      font-size: 24px;
      font-weight: 700;
      color: #0f172a;
      margin-top: 5px;
    }
    h2 {
      font-size: 18px;
      color: #0f172a;
      border-bottom: 1px solid #e2e8f0;
      padding-bottom: 8px;
      margin-top: 35px;
    }
    table {
      width: 100%;
      border-collapse: collapse;
      margin-top: 15px;
      font-size: 12px;
    }
    th, td {
      border: 1px solid #e2e8f0;
      padding: 10px 12px;
      text-align: left;
    }
    th {
      background: #f1f5f9;
      font-weight: 600;
      color: #334155;
    }
    .sev-critical { color: #dc2626; font-weight: bold; }
    .sev-high { color: #ea580c; font-weight: bold; }
    .sev-medium { color: #d97706; font-weight: bold; }
    .sev-low { color: #16a34a; font-weight: bold; }
    .findings-list {
      padding-left: 20px;
    }
    .findings-list li {
      margin-bottom: 10px;
    }
    .limitations-box {
      background: #fffbeb;
      border: 1px solid #fde68a;
      padding: 16px;
      border-radius: 6px;
      font-size: 13px;
      color: #92400e;
    }
    .footer {
      margin-top: 50px;
      border-top: 1px solid #e2e8f0;
      padding-top: 15px;
      font-size: 11px;
      color: #94a3b8;
      text-align: center;
    }
    @media print {
      body { margin: 15mm; font-size: 11pt; }
      .no-print { display: none; }
    }
  </style>
</head>
<body>
  <div class="no-print" style="margin-bottom: 20px; text-align: right;">
    <button onclick="window.print()" style="padding: 10px 20px; background: #0f172a; color: white; border: none; border-radius: 6px; cursor: pointer; font-weight: bold;">
      Print / Save to PDF
    </button>
  </div>

  <div class="header">
    <div>
      <h1>NETGUARD AI</h1>
      <p>Network Intrusion Detection & SOC Incident Investigation Report</p>
    </div>
    <div style="text-align: right;">
      <span class="badge">CONFIDENTIAL // SOC OPERATIONS</span>
      <p style="margin-top: 6px;">Generated: ${escapeHtml(genTime)} UTC</p>
      <p>Dataset: <strong>${escapeHtml(datasetName)}</strong></p>
    </div>
  </div>

  <h2>1. Executive Summary & Incident Metrics</h2>
  <div class="grid">
    <div class="card">
      <div class="card-label">Total Flows Analyzed</div>
      <div class="card-val">${totalFlows.toLocaleString()}</div>
    </div>
    <div class="card">
      <div class="card-label">Normal Traffic</div>
      <div class="card-val" style="color: #16a34a;">${normalCount.toLocaleString()}</div>
    </div>
    <div class="card">
      <div class="card-label">Suspicious Threats</div>
      <div class="card-val" style="color: #dc2626;">${suspiciousCount.toLocaleString()}</div>
    </div>
    <div class="card">
      <div class="card-label">Critical Incidents</div>
      <div class="card-val" style="color: #dc2626;">${criticalCount}</div>
    </div>
  </div>

  <div class="grid">
    <div class="card">
      <div class="card-label">Alerts by Severity</div>
      <div style="margin-top: 8px; font-size: 13px;">
        <div>Critical: <span class="sev-critical">${criticalCount}</span></div>
        <div>High: <span class="sev-high">${highCount}</span></div>
        <div>Medium: <span class="sev-medium">${mediumCount}</span></div>
        <div>Low: <span class="sev-low">${lowCount}</span></div>
      </div>
    </div>
    <div class="card">
      <div class="card-label">Investigation Triage</div>
      <div style="margin-top: 8px; font-size: 13px;">
        <div>New (Pending): <strong>${newCount}</strong></div>
        <div>Investigating: <strong>${investigatingCount}</strong></div>
        <div>Resolved: <strong style="color: #16a34a;">${resolvedCount}</strong></div>
        <div>False Positives: <strong>${fpCount}</strong></div>
      </div>
    </div>
    <div class="card" style="grid-column: span 2;">
      <div class="card-label">Active Machine Learning Model</div>
      <div style="margin-top: 8px; font-size: 13px;">
        <div>Algorithm: <strong>${escapeHtml(metrics ? metrics.algorithmName : 'Random Forest Classifier')}</strong></div>
        <div>Accuracy: <strong>${metrics ? (metrics.accuracy * 100).toFixed(2) + '%' : 'N/A'}</strong> | F1-Score: <strong>${metrics ? (metrics.f1Score * 100).toFixed(2) + '%' : 'N/A'}</strong></div>
        <div>Precision: <strong>${metrics ? (metrics.precision * 100).toFixed(2) + '%' : 'N/A'}</strong> | Recall: <strong>${metrics ? (metrics.recall * 100).toFixed(2) + '%' : 'N/A'}</strong></div>
        <div>False Positive Rate: <strong>${metrics ? (metrics.falsePositiveRate * 100).toFixed(2) + '%' : 'N/A'}</strong></div>
      </div>
    </div>
  </div>

  <h2>2. Automated Security Findings</h2>
  <ul class="findings-list">
    ${findings.slice(0, 8).map(f => `
      <li><strong>${escapeHtml(f.title)} (${escapeHtml(f.metric)}):</strong> ${escapeHtml(f.description)}</li>
    `).join('')}
  </ul>

  <h2>3. Top Security Incidents & Threat Activities</h2>
  <table>
    <thead>
      <tr>
        <th>Alert ID</th>
        <th>Timestamp</th>
        <th>Source IP</th>
        <th>Target IP</th>
        <th>Port/Proto</th>
        <th>Category</th>
        <th>Severity</th>
        <th>Status</th>
      </tr>
    </thead>
    <tbody>
      ${alerts.slice(0, 12).map(a => `
        <tr>
          <td><strong>${escapeHtml(a.id)}</strong></td>
          <td>${escapeHtml(a.timestamp)}</td>
          <td><code>${escapeHtml(a.sourceIp)}</code></td>
          <td><code>${escapeHtml(a.destinationIp)}</code></td>
          <td>${a.destinationPort} / ${escapeHtml(a.protocol)}</td>
          <td>${escapeHtml(a.predictedCategory)}</td>
          <td class="sev-${escapeHtml(a.severity.toLowerCase())}">${escapeHtml(a.severity)}</td>
          <td>${escapeHtml(a.status)}</td>
        </tr>
      `).join('')}
    </tbody>
  </table>

  <h2>4. Recommended Remediation & Containment Actions</h2>
  <ol style="font-size: 13px; line-height: 1.8;">
    <li><strong>Perimeter Defense:</strong> Block malicious external IP addresses identified in port scans and brute force attempts on edge firewalls.</li>
    <li><strong>Credential Hardening:</strong> Enforce mandatory Multi-Factor Authentication (MFA) across all administrative endpoints (SSH/RDP) and review lockout policies.</li>
    <li><strong>DDoS Mitigation:</strong> Implement rate limiting and activate upstream SYN-proxy protections on web-facing servers.</li>
    <li><strong>Internal Host Isolation:</strong> Immediately quarantine hosts demonstrating C2 beaconing patterns for digital forensic disk and memory imaging.</li>
  </ol>

  <h2>5. Academic System Limitations</h2>
  <div class="limitations-box">
    <strong>Academic Project Disclaimer:</strong> NETGUARD AI operates on network flow metadata (5-tuples, duration, packet count, byte volume, and transfer rates). Deep packet payload inspection (DPI) and encrypted traffic payload decryption (e.g. TLS 1.3) are out of scope. Machine learning models are subject to concept drift when exposed to novel zero-day attack vectors not represented in training distributions.
  </div>

  <div class="footer">
    NETGUARD AI · B.Sc. Computer Science Cybersecurity Capstone Project · Security Operations Center Simulation
  </div>
</body>
</html>`;
}

/**
 * Generates valid SQLite SQL DDL and DML script for persisting alerts and investigation notes
 */
export function exportAlertsToSQLiteSQL(alerts: SecurityAlert[]): string {
  const lines: string[] = [
    '-- ============================================================================',
    '-- NETGUARD AI: SQLite Incident & Alert Database Schema and Data Dump',
    '-- Compatible with SQLite3, PostgreSQL, MySQL',
    `-- Generated: ${new Date().toISOString()}`,
    '-- Database Target: netguard_soc.db',
    '-- ============================================================================',
    '',
    'PRAGMA foreign_keys = ON;',
    '',
    'CREATE TABLE IF NOT EXISTS alerts (',
    '    id TEXT PRIMARY KEY,',
    '    flow_id TEXT,',
    '    timestamp TEXT,',
    '    source_ip TEXT,',
    '    destination_ip TEXT,',
    '    source_port INTEGER,',
    '    destination_port INTEGER,',
    '    protocol TEXT,',
    '    predicted_category TEXT,',
    '    severity TEXT,',
    '    status TEXT,',
    '    confidence REAL,',
    '    detection_reason TEXT,',
    '    packet_count INTEGER,',
    '    byte_count INTEGER,',
    '    flow_rate REAL,',
    '    resolved_at TEXT,',
    '    resolution_summary TEXT',
    ');',
    '',
    'CREATE TABLE IF NOT EXISTS investigation_notes (',
    '    id TEXT PRIMARY KEY,',
    '    alert_id TEXT,',
    '    author TEXT,',
    '    timestamp TEXT,',
    '    note_text TEXT,',
    '    status_change TEXT,',
    '    FOREIGN KEY (alert_id) REFERENCES alerts (id) ON DELETE CASCADE',
    ');',
    '',
    '-- Begin Transaction',
    'BEGIN TRANSACTION;',
    ''
  ];

  alerts.forEach(a => {
    const esc = (s: string | undefined) => (s ? `'${s.replace(/'/g, "''")}'` : 'NULL');
    lines.push(
      `INSERT OR REPLACE INTO alerts VALUES (` +
      `${esc(a.id)}, ${esc(a.flowId)}, ${esc(a.timestamp)}, ${esc(a.sourceIp)}, ${esc(a.destinationIp)}, ` +
      `${a.sourcePort}, ${a.destinationPort}, ${esc(a.protocol)}, ${esc(a.predictedCategory)}, ` +
      `${esc(a.severity)}, ${esc(a.status)}, ${a.confidence.toFixed(4)}, ${esc(a.detectionReason)}, ` +
      `${a.packetCount}, ${a.byteCount}, ${a.flowRate}, ${esc(a.resolvedAt)}, ${esc(a.resolutionSummary)}` +
      `);`
    );

    a.investigationNotes.forEach(n => {
      lines.push(
        `INSERT OR REPLACE INTO investigation_notes VALUES (` +
        `${esc(n.id)}, ${esc(a.id)}, ${esc(n.author)}, ${esc(n.timestamp)}, ${esc(n.text)}, ${esc(n.statusChange)}` +
        `);`
      );
    });
  });

  lines.push('');
  lines.push('COMMIT;');
  lines.push('-- End of SQLite Dump');
  return lines.join('\n');
}
