import React, { useRef, useState } from 'react';
import { FlowRecord, DataQualityReport, AttackCategory } from '../../types';
import { 
  Upload, Database, Download, CheckCircle, RefreshCw, 
  Radio, Flame, Search, KeyRound, Bug, ArrowRight, 
  FileSpreadsheet, ShieldCheck, Layers, AlertCircle 
} from 'lucide-react';
import { triggerDownload } from '../../utils/reportExporter';
import { convertFlowsToCSV, SCENARIOS, TrafficScenario } from '../../data/demoTraffic';

interface DataManagementViewProps {
  flows: FlowRecord[];
  qualityReport?: DataQualityReport;
  datasetName: string;
  onFileUpload?: (file: File) => void;
  onLoadDemo: () => void;
  onSelectScenario?: (scenario: TrafficScenario) => void;
  onNavigateToTab: (tab: any) => void;
}

export const DataManagementView: React.FC<DataManagementViewProps> = ({
  flows,
  qualityReport,
  datasetName,
  onFileUpload,
  onLoadDemo,
  onSelectScenario,
  onNavigateToTab,
}) => {
  const fileInputRef = useRef<HTMLInputElement>(null);
  const [activeTabMode, setActiveTabMode] = useState<'upload' | 'scenarios'>('upload');
  const [dragActive, setDragActive] = useState(false);
  const [filterQuery, setFilterQuery] = useState('');
  const [activeScenarioId, setActiveScenarioId] = useState<TrafficScenario>('balanced');
  const [isProcessing, setIsProcessing] = useState(false);

  // Drag and drop handlers
  const handleDrag = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    if (e.type === 'dragenter' || e.type === 'dragover') {
      setDragActive(true);
    } else if (e.type === 'dragleave') {
      setDragActive(false);
    }
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setDragActive(false);
    if (e.dataTransfer.files && e.dataTransfer.files[0] && onFileUpload) {
      setIsProcessing(true);
      onFileUpload(e.dataTransfer.files[0]);
      setTimeout(() => setIsProcessing(false), 500);
    }
  };

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files[0] && onFileUpload) {
      const file = e.target.files[0];
      setIsProcessing(true);
      onFileUpload(file);
      // Reset input value so re-uploading the same file triggers onChange
      e.target.value = '';
      setTimeout(() => setIsProcessing(false), 500);
    }
  };

  const handleScenarioChange = (scenarioId: TrafficScenario) => {
    setActiveScenarioId(scenarioId);
    if (onSelectScenario) {
      setIsProcessing(true);
      onSelectScenario(scenarioId);
      setTimeout(() => setIsProcessing(false), 300);
    }
  };

  const handleDownloadActiveCSV = () => {
    const csv = convertFlowsToCSV(flows);
    triggerDownload(csv, `netguard_telemetry_${Date.now()}.csv`, 'text/csv');
  };

  const downloadQualityReport = () => {
    if (!qualityReport) return;
    const content = `NETGUARD AI - DATASET QUALITY AUDIT REPORT
==================================================
Dataset Name:            ${datasetName}
Audit Timestamp:         ${new Date().toISOString()}
Quality Health Score:    ${qualityReport.qualityScore}% / 100%

DATASET GEOMETRY & COMPOSITION:
- Total Flow Records:    ${qualityReport.totalRows}
- Total Columns Detected:${qualityReport.totalColumns}

ANOMALIES & INTEGRITY CHECKS:
- Missing Value Cells:   ${qualityReport.missingValuesCount}
- Duplicate Flow Tuples: ${qualityReport.duplicateCount}
- Invalid Numerics:      ${qualityReport.invalidNumericCount}
- Inconsistent Labels:   ${qualityReport.inconsistentLabelsCount}

COLUMN MAPPING:
${Object.entries(qualityReport.columnMapping)
  .map(([std, raw]) => `- Standard '${std}' mapped from raw '${raw}'`)
  .join('\n')}

MISSING REQUIRED COLUMNS:
${qualityReport.missingRequiredColumns.length > 0 
  ? qualityReport.missingRequiredColumns.map(c => `- CRITICAL: Missing ${c}`).join('\n')
  : '- None. All essential flow attributes present.'}
`;
    triggerDownload(content, `netguard_quality_report_${Date.now()}.txt`, 'text/plain');
  };

  // Compute Attack Categories Breakdown from currently loaded flows
  const categoryCounts: Record<string, number> = {};
  flows.forEach(f => {
    const cat = f.attackCategory || (f.label === 'NORMAL' ? 'Normal' : 'Unknown Anomaly');
    categoryCounts[cat] = (categoryCounts[cat] || 0) + 1;
  });

  const categoryList = Object.entries(categoryCounts).sort((a, b) => b[1] - a[1]);

  const filteredFlows = flows.filter(f => 
    !filterQuery || 
    f.sourceIp.includes(filterQuery) || 
    f.destinationIp.includes(filterQuery) || 
    f.protocol.toLowerCase().includes(filterQuery.toLowerCase()) ||
    (f.attackCategory && f.attackCategory.toLowerCase().includes(filterQuery.toLowerCase())) ||
    (f.label && f.label.toLowerCase().includes(filterQuery.toLowerCase()))
  );

  const normalCount = flows.filter(f => f.label === 'NORMAL').length;
  const suspiciousCount = flows.filter(f => f.label === 'SUSPICIOUS').length;

  return (
    <div className="space-y-6">
      {/* Module Title */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-2 border-b border-slate-850">
        <div>
          <h1 className="text-xl font-bold tracking-tight text-slate-100 flex items-center gap-2">
            <span>Network Traffic Data Management</span>
            <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-cyan-950 border border-cyan-800 text-cyan-300">
              SOC Module 2
            </span>
          </h1>
          <p className="text-xs text-slate-400 mt-0.5">
            Ingest custom CSV network captures or simulate live SOC threat scenarios. Automatically audits schema, extracts attack categories, and feeds the ML pipeline.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={handleDownloadActiveCSV}
            className="px-3 py-1.5 bg-slate-900 hover:bg-slate-800 text-slate-200 border border-slate-750 rounded text-xs font-medium transition-colors flex items-center gap-1.5 cursor-pointer"
          >
            <Download className="w-3.5 h-3.5 text-cyan-400" />
            <span>Export Active CSV</span>
          </button>
          <button
            onClick={() => {
              setActiveScenarioId('balanced');
              onLoadDemo();
            }}
            className="px-3.5 py-1.5 bg-cyan-500 hover:bg-cyan-400 text-slate-950 rounded text-xs font-semibold transition-colors flex items-center gap-1.5 cursor-pointer"
          >
            <RefreshCw className="w-3.5 h-3.5" />
            <span>Reset Demo Baseline</span>
          </button>
        </div>
      </div>

      {/* Mode Switcher Tabs */}
      <div className="flex items-center gap-2 border-b border-slate-800 pb-2">
        <button
          type="button"
          onClick={() => setActiveTabMode('upload')}
          className={`px-4 py-2 rounded-lg text-xs font-semibold flex items-center gap-2 transition-all cursor-pointer ${
            activeTabMode === 'upload'
              ? 'bg-cyan-500 text-slate-950 shadow-md shadow-cyan-950/50'
              : 'bg-slate-900 text-slate-300 hover:bg-slate-850 hover:text-slate-100 border border-slate-800'
          }`}
        >
          <Upload className="w-3.5 h-3.5" />
          <span>Upload Network Capture Dataset (.csv, .tsv, .txt)</span>
        </button>

        <button
          type="button"
          onClick={() => setActiveTabMode('scenarios')}
          className={`px-4 py-2 rounded-lg text-xs font-semibold flex items-center gap-2 transition-all cursor-pointer ${
            activeTabMode === 'scenarios'
              ? 'bg-cyan-500 text-slate-950 shadow-md shadow-cyan-950/50'
              : 'bg-slate-900 text-slate-300 hover:bg-slate-850 hover:text-slate-100 border border-slate-800'
          }`}
        >
          <Radio className="w-3.5 h-3.5" />
          <span>Simulate SOC Threat Scenarios (DDoS, Scan, Brute Force, C2)</span>
        </button>
      </div>

      {/* Ingestion & Telemetry Section: div:nth-of-type(2) */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
        {/* Main Ingestion Container: div:nth-of-type(1) */}
        <div className="lg:col-span-2">
          {activeTabMode === 'upload' ? (
            /* Upload Dataset Card */
            <div
              onDragEnter={handleDrag}
              onDragLeave={handleDrag}
              onDragOver={handleDrag}
              onDrop={handleDrop}
              className={`h-full border-2 border-dashed rounded-xl p-7 flex flex-col items-center justify-center text-center transition-all duration-200 relative group overflow-hidden ${
                dragActive
                  ? 'border-cyan-400 bg-cyan-950/40 shadow-[0_0_35px_rgba(6,182,212,0.3)] ring-1 ring-cyan-400/50 scale-[1.003]'
                  : 'border-slate-800 hover:border-cyan-500/50 bg-slate-900/70 hover:bg-slate-900/90 hover:shadow-[0_0_25px_rgba(6,182,212,0.12)]'
              }`}
            >
              {/* Subtle Cyber Grid Glow Background */}
              <div className="absolute inset-0 bg-[radial-gradient(#0891b2_1px,transparent_1px)] [background-size:16px_16px] opacity-10 pointer-events-none" />

              {/* Native Accessible File Input with Label */}
              <input
                id="dataset-file-input"
                ref={fileInputRef}
                type="file"
                accept=".csv,.tsv,.txt,text/csv,text/tab-separated-values,text/plain,application/vnd.ms-excel"
                onChange={handleFileChange}
                className="hidden"
              />

              {/* Upload Icon */}
              <div className="relative mb-3.5">
                <div className="w-14 h-14 rounded-2xl bg-gradient-to-br from-slate-900 to-slate-950 border border-cyan-500/40 group-hover:border-cyan-400 flex items-center justify-center text-cyan-400 shadow-lg shadow-cyan-950/60 transition-all duration-200 group-hover:scale-105">
                  <Upload className="w-6 h-6 animate-pulse" />
                </div>
                <div className="absolute -top-1 -right-1 w-3 h-3 rounded-full bg-cyan-400 border-2 border-slate-950 animate-ping opacity-75" />
              </div>

              <h3 className="text-base font-bold text-slate-100 group-hover:text-cyan-300 transition-colors">
                Ingest Network Traffic Dataset (.csv, .tsv, .txt)
              </h3>
              <p className="text-xs text-slate-400 max-w-lg mt-1.5 leading-relaxed">
                Upload your raw packet capture export or flow dataset. The engine automatically detects delimiters (comma, semicolon, tab, pipe), resolves column headers, extracts attack categories, and maps attributes for the entire SOC analytics pipeline.
              </p>

              {/* Native Click Button with Label */}
              <label
                htmlFor="dataset-file-input"
                className="mt-4 px-6 py-2.5 bg-gradient-to-r from-cyan-500 via-cyan-400 to-blue-500 hover:from-cyan-400 hover:to-blue-400 active:from-cyan-600 active:to-blue-600 text-slate-950 font-bold text-xs rounded-lg shadow-lg shadow-cyan-950/70 hover:shadow-cyan-500/30 transition-all duration-150 flex items-center gap-2 cursor-pointer border border-cyan-300/40 active:scale-95 z-10"
              >
                {isProcessing ? (
                  <>
                    <RefreshCw className="w-4 h-4 text-slate-950 animate-spin" />
                    <span>Analyzing Dataset Categories & Metrics...</span>
                  </>
                ) : (
                  <>
                    <FileSpreadsheet className="w-4 h-4 text-slate-950 stroke-[2.5]" />
                    <span>Select CSV / Dataset File From Device</span>
                  </>
                )}
              </label>

              {/* Supported Format Tags */}
              <div className="flex flex-wrap items-center justify-center gap-1.5 mt-4">
                <span className="px-2 py-0.5 rounded bg-slate-950/80 border border-cyan-500/30 text-cyan-300 text-[10px] font-mono font-medium">
                  CIC-IDS2017
                </span>
                <span className="px-2 py-0.5 rounded bg-slate-950/80 border border-slate-750 text-slate-300 text-[10px] font-mono font-medium">
                  UNSW-NB15
                </span>
                <span className="px-2 py-0.5 rounded bg-slate-950/80 border border-slate-750 text-slate-300 text-[10px] font-mono font-medium">
                  KDD-99 / NSL-KDD
                </span>
                <span className="px-2 py-0.5 rounded bg-slate-950/80 border border-slate-750 text-slate-300 text-[10px] font-mono font-medium">
                  Zeek conn.log
                </span>
                <span className="px-2 py-0.5 rounded bg-slate-950/80 border border-slate-750 text-slate-300 text-[10px] font-mono font-medium">
                  Suricata EVE
                </span>
                <span className="px-2 py-0.5 rounded bg-slate-950/80 border border-slate-750 text-slate-300 text-[10px] font-mono font-medium">
                  Wireshark CSV
                </span>
              </div>

              {/* Active File Ingested Info Strip */}
              <div className="w-full mt-5 pt-3 border-t border-slate-800/80 flex flex-wrap items-center justify-between gap-2 text-[11px] text-slate-400">
                <div className="flex items-center gap-2">
                  <span className="w-2 h-2 rounded-full bg-emerald-400" />
                  <span>Active Monitored File:</span>
                  <span className="font-mono text-slate-200 font-semibold truncate max-w-[260px]">
                    {datasetName}
                  </span>
                  <span className="px-1.5 py-0.2 rounded bg-cyan-950/70 border border-cyan-800/60 text-cyan-300 font-mono text-[10px]">
                    {flows.length.toLocaleString()} flows
                  </span>
                </div>

                <div className="flex items-center gap-2">
                  <span className="text-slate-500">
                    {qualityReport?.detectedDelimiter ? `Format: ${qualityReport.detectedDelimiter}` : 'Auto-Mapping Active'}
                  </span>
                </div>
              </div>
            </div>
          ) : (
            /* Threat Scenarios Card */
            <div className="p-5 rounded-xl bg-slate-900/90 border border-slate-800 flex flex-col justify-between h-full">
              <div>
                <div className="flex items-center justify-between gap-2 mb-3">
                  <div className="flex items-center gap-2">
                    <div className="w-8 h-8 rounded-lg bg-cyan-950/80 border border-cyan-800 flex items-center justify-center text-cyan-400">
                      <Radio className="w-4 h-4 animate-pulse" />
                    </div>
                    <div>
                      <h3 className="text-sm font-bold text-slate-100">
                        Pre-Configured SOC Threat Scenarios
                      </h3>
                      <p className="text-xs text-slate-400">
                        Simulate specific network intrusion campaigns to verify ML detection and alert generation.
                      </p>
                    </div>
                  </div>

                  <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-emerald-950 border border-emerald-800/80 text-emerald-300 font-semibold shrink-0">
                    ● Telemetry Engine
                  </span>
                </div>

                <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5 mt-3">
                  {SCENARIOS.map((sc) => {
                    const isSelected = activeScenarioId === sc.id;
                    let IconComponent = Database;
                    if (sc.id === 'ddos') IconComponent = Flame;
                    else if (sc.id === 'portscan') IconComponent = Search;
                    else if (sc.id === 'bruteforce') IconComponent = KeyRound;
                    else if (sc.id === 'botnet') IconComponent = Bug;

                    return (
                      <button
                        key={sc.id}
                        type="button"
                        onClick={() => handleScenarioChange(sc.id)}
                        className={`p-3 rounded-lg border text-left transition-all cursor-pointer flex flex-col justify-between ${
                          isSelected
                            ? 'bg-cyan-950/40 border-cyan-500 shadow-md shadow-cyan-950/40'
                            : 'bg-slate-950/60 border-slate-800 hover:border-slate-700 hover:bg-slate-850/50'
                        }`}
                      >
                        <div>
                          <div className="flex items-center justify-between gap-1 mb-1">
                            <span className="flex items-center gap-1.5 text-xs font-bold text-slate-100">
                              <IconComponent className={`w-3.5 h-3.5 ${isSelected ? 'text-cyan-400' : 'text-slate-400'}`} />
                              <span className={isSelected ? 'text-cyan-200' : 'text-slate-200'}>{sc.name}</span>
                            </span>
                            <span className={`text-[9px] px-1.5 py-0.2 rounded font-mono ${
                              isSelected ? 'bg-cyan-500 text-slate-950 font-bold' : 'bg-slate-800 text-slate-400'
                            }`}>
                              {sc.badge}
                            </span>
                          </div>
                          <p className="text-[11px] text-slate-400 leading-relaxed line-clamp-2">
                            {sc.description}
                          </p>
                        </div>

                        <div className="mt-2.5 pt-1.5 border-t border-slate-850/80 flex items-center justify-between text-[10px]">
                          <span className="text-slate-500">Vector: <strong className="text-slate-300">{sc.dominantAttack}</strong></span>
                          <span className={isSelected ? 'text-cyan-400 font-semibold' : 'text-slate-500'}>
                            {isSelected ? '✓ Active Scenario' : 'Click to Load →'}
                          </span>
                        </div>
                      </button>
                    );
                  })}
                </div>
              </div>

              <div className="mt-4 pt-3 border-t border-slate-800 flex flex-wrap items-center justify-between gap-2 text-xs text-slate-400">
                <div className="flex items-center gap-2">
                  <span className="font-semibold text-slate-300">Active Feed:</span>
                  <span className="font-mono text-cyan-300 font-medium">{datasetName}</span>
                </div>
                <button
                  onClick={() => setActiveTabMode('upload')}
                  className="text-xs text-cyan-400 hover:underline cursor-pointer"
                >
                  Switch to Upload Custom Dataset →
                </button>
              </div>
            </div>
          )}
        </div>

        {/* Dataset Function & Attack Categories Breakdown: div:nth-of-type(2) */}
        <div className="p-5 rounded-xl bg-slate-900/90 border border-slate-800 flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between text-xs font-semibold text-cyan-400 mb-2">
              <span className="flex items-center gap-1.5">
                <Layers className="w-3.5 h-3.5" />
                <span>Detected Categories & Functions</span>
              </span>
              <span className="text-[10px] uppercase px-1.5 py-0.5 rounded bg-cyan-950 border border-cyan-800 text-cyan-300">
                Live Analysis
              </span>
            </div>

            <h4 className="text-sm font-bold text-slate-100">Dataset Threat Taxonomy</h4>
            <p className="text-xs text-slate-400 mt-1 leading-relaxed">
              The engine parsed the uploaded telemetry and classified records into the following operational threat functions:
            </p>

            {/* Attack Category Badges */}
            <div className="space-y-2 mt-3.5">
              {categoryList.map(([cat, count]) => {
                const pct = Math.round((count / Math.max(flows.length, 1)) * 100);
                const isNormal = cat === 'Normal';
                return (
                  <div key={cat} className="p-2 rounded bg-slate-950/70 border border-slate-850 flex items-center justify-between text-xs">
                    <div className="flex items-center gap-2">
                      <span className={`w-2 h-2 rounded-full ${isNormal ? 'bg-emerald-400' : 'bg-red-400'}`} />
                      <span className="font-medium text-slate-200">{cat}</span>
                    </div>
                    <div className="flex items-center gap-2 font-mono">
                      <span className="text-slate-400 text-[11px]">{count.toLocaleString()} flows</span>
                      <span className={`px-1.5 py-0.2 rounded text-[10px] font-bold ${
                        isNormal 
                          ? 'bg-emerald-950/80 text-emerald-300 border border-emerald-800/60' 
                          : 'bg-red-950/80 text-red-300 border border-red-800/60'
                      }`}>
                        {pct}%
                      </span>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>

          <div className="mt-4 pt-3 border-t border-slate-800/80 space-y-2">
            <button
              onClick={() => onNavigateToTab('preprocessing')}
              className="w-full py-2.5 bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-slate-950 rounded-lg text-xs font-bold transition-all flex items-center justify-center gap-1.5 shadow-md shadow-cyan-950/40 cursor-pointer"
            >
              <span>Analyze in Preprocessing</span>
              <ArrowRight className="w-3.5 h-3.5 stroke-[2.5]" />
            </button>
            <button
              onClick={() => onNavigateToTab('detection')}
              className="w-full py-1.5 bg-slate-800 hover:bg-slate-750 text-slate-200 rounded text-xs font-medium transition-colors flex items-center justify-center gap-1.5 cursor-pointer"
            >
              <ShieldCheck className="w-3.5 h-3.5 text-cyan-400" />
              <span>Inspect AI Intrusion Detections →</span>
            </button>
          </div>
        </div>
      </div>

      {/* Dataset Quality Audit Card */}
      {qualityReport && (
        <div className="p-5 rounded-lg bg-slate-900/90 border border-slate-800">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 mb-4 pb-3 border-b border-slate-800/80">
            <div className="flex items-center gap-3">
              <div className="text-2xl font-bold font-mono text-cyan-400">
                {qualityReport.qualityScore}%
              </div>
              <div>
                <h3 className="text-sm font-bold text-slate-100">
                  Dataset Quality Assessment Score
                </h3>
                <p className="text-xs text-slate-400">
                  Active File: <span className="font-mono text-slate-300">{datasetName}</span>
                </p>
              </div>
            </div>

            <button
              onClick={downloadQualityReport}
              className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded text-xs font-medium transition-colors flex items-center gap-1.5 self-start sm:self-auto"
            >
              <Download className="w-3.5 h-3.5" />
              <span>Download Quality Report</span>
            </button>
          </div>

          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs mb-4">
            <div className="p-3 rounded bg-slate-950/60 border border-slate-850">
              <div className="text-slate-500 font-medium">Missing Values</div>
              <div className="text-base font-bold font-mono text-slate-200 mt-1">
                {qualityReport.missingValuesCount}
              </div>
              <div className="text-[10px] text-slate-500 mt-0.5">Imputed with median</div>
            </div>

            <div className="p-3 rounded bg-slate-950/60 border border-slate-850">
              <div className="text-slate-500 font-medium">Duplicate Flows</div>
              <div className="text-base font-bold font-mono text-slate-200 mt-1">
                {qualityReport.duplicateCount}
              </div>
              <div className="text-[10px] text-slate-500 mt-0.5">Matched on 5-tuple</div>
            </div>

            <div className="p-3 rounded bg-slate-950/60 border border-slate-850">
              <div className="text-slate-500 font-medium">Invalid Numerics</div>
              <div className="text-base font-bold font-mono text-slate-200 mt-1">
                {qualityReport.invalidNumericCount}
              </div>
              <div className="text-[10px] text-slate-500 mt-0.5">Negative or NaN</div>
            </div>

            <div className="p-3 rounded bg-slate-950/60 border border-slate-850">
              <div className="text-slate-500 font-medium">Inconsistent Labels</div>
              <div className="text-base font-bold font-mono text-slate-200 mt-1">
                {qualityReport.inconsistentLabelsCount}
              </div>
              <div className="text-[10px] text-slate-500 mt-0.5">Normalized to standard</div>
            </div>
          </div>

          {/* Missing Required / Imputation Notice */}
          {qualityReport.missingRequiredColumns.length > 0 && (
            <div className="p-3 rounded bg-cyan-950/40 border border-cyan-500/30 text-xs text-cyan-300 flex items-start gap-2 mb-3">
              <CheckCircle className="w-4 h-4 shrink-0 text-cyan-400 mt-0.5" />
              <div>
                <strong>Intelligent Auto-Imputation active:</strong> Standard flow attributes (
                <span className="font-mono text-cyan-200">{qualityReport.missingRequiredColumns.join(', ')}</span>
                ) were automatically imputed using valid network flow semantics. All downstream SOC modules (Preprocessing, ML Classification, EDA, and Incident Management) are fully functional.
              </div>
            </div>
          )}

          {/* Automatic Column Mapping Tags */}
          <div className="mt-2 text-xs">
            <span className="text-slate-400 font-medium mr-2">Automatic Column Mapping:</span>
            <div className="flex flex-wrap gap-2 mt-2">
              {Object.entries(qualityReport.columnMapping).map(([std, raw]) => (
                <span
                  key={std}
                  className="px-2 py-0.5 bg-slate-950 text-slate-300 border border-slate-800 rounded font-mono text-[11px]"
                >
                  <span className="text-cyan-400">{std}</span> ← <span>{raw}</span>
                </span>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* Data Records Table Preview */}
      <div className="p-5 rounded-lg bg-slate-900/90 border border-slate-800">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 mb-4">
          <div>
            <h3 className="text-sm font-bold text-slate-100">
              Network Traffic Flow Records Preview
            </h3>
            <p className="text-xs text-slate-400">
              Showing {filteredFlows.length} of {flows.length} rows
            </p>
          </div>

          <div className="flex items-center gap-3">
            <input
              type="text"
              placeholder="Search IP, protocol, category..."
              value={filterQuery}
              onChange={(e) => setFilterQuery(e.target.value)}
              className="px-3 py-1.5 bg-slate-950 border border-slate-800 rounded text-xs text-slate-200 placeholder:text-slate-600 focus:outline-none focus:border-cyan-500"
            />
            <button
              onClick={() => onNavigateToTab('preprocessing')}
              className="px-3.5 py-1.5 bg-cyan-500 hover:bg-cyan-400 text-slate-950 rounded text-xs font-semibold transition-colors whitespace-nowrap"
            >
              Proceed to Preprocessing →
            </button>
          </div>
        </div>

        <div className="overflow-x-auto max-h-[460px] overflow-y-auto">
          <table className="w-full text-left text-xs border-collapse">
            <thead className="sticky top-0 bg-slate-950 z-10">
              <tr className="border-b border-slate-800 text-slate-400 uppercase font-mono text-[10px] tracking-wider">
                <th className="py-2 px-3">Flow ID</th>
                <th className="py-2 px-3">Timestamp</th>
                <th className="py-2 px-3">Source IP</th>
                <th className="py-2 px-3">Destination IP</th>
                <th className="py-2 px-3">Port</th>
                <th className="py-2 px-3">Proto</th>
                <th className="py-2 px-3">Duration (s)</th>
                <th className="py-2 px-3">Packets</th>
                <th className="py-2 px-3">Bytes</th>
                <th className="py-2 px-3">Flow Rate (B/s)</th>
                <th className="py-2 px-3">Label</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-850 font-mono">
              {filteredFlows.slice(0, 50).map((f) => (
                <tr key={f.id} className="hover:bg-slate-850/40 transition-colors">
                  <td className="py-2 px-3 text-slate-400">{f.id}</td>
                  <td className="py-2 px-3 text-slate-400">{f.timestamp}</td>
                  <td className="py-2 px-3 text-slate-200">{f.sourceIp}</td>
                  <td className="py-2 px-3 text-slate-300">{f.destinationIp}</td>
                  <td className="py-2 px-3 text-slate-300">{f.destinationPort}</td>
                  <td className="py-2 px-3 text-cyan-400">{f.protocol}</td>
                  <td className="py-2 px-3 text-slate-300">{f.flowDuration.toFixed(3)}</td>
                  <td className="py-2 px-3 text-slate-300">{f.packetCount.toLocaleString()}</td>
                  <td className="py-2 px-3 text-slate-300">{f.byteCount.toLocaleString()}</td>
                  <td className="py-2 px-3 text-slate-300">{f.flowRate.toLocaleString()}</td>
                  <td className="py-2 px-3 font-sans">
                    <span
                      className={`inline-block px-1.5 py-0.5 rounded text-[10px] font-bold ${
                        f.label === 'SUSPICIOUS'
                          ? 'bg-red-950/60 text-red-400 border border-red-500/30'
                          : 'bg-emerald-950/60 text-emerald-400 border border-emerald-500/30'
                      }`}
                    >
                      {f.label}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
