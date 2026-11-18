import React, { useState, useEffect } from 'react';
import {
  FlowRecord,
  CleanedFlowRecord,
  DataQualityReport,
  PreprocessingSummary,
  EDAFinding,
  TrainedModels,
  DetectionPrediction,
  SecurityAlert,
  ModelAlgorithm,
  AlertStatus,
} from './types';
import { generateDemoDataset, generateScenarioDataset, TrafficScenario } from './data/demoTraffic';
import {
  parseCSV,
  detectColumnMapping,
  assessDatasetQuality,
  convertRowsToFlowRecords,
  preprocessDataset,
} from './utils/dataProcessor';
import {
  trainAllModels,
  runInference,
} from './utils/mlEngine';
import { generateEDAFindings } from './utils/edaFindings';
import {
  generateAlertsFromPredictions,
  updateAlertStatus,
  addIncidentNote,
  clearStoredAlerts,
} from './utils/alertManager';
import { CheckCircle2 } from 'lucide-react';

import { Header } from './components/Header';
import { Sidebar, NavTab } from './components/Sidebar';
import { SOCGuideModal } from './components/SOCGuideModal';

import { OverviewView } from './components/views/OverviewView';
import { DataManagementView } from './components/views/DataManagementView';
import { PreprocessingView } from './components/views/PreprocessingView';
import { EDAView } from './components/views/EDAView';
import { IntrusionDetectionView } from './components/views/IntrusionDetectionView';
import { ModelEvaluationView } from './components/views/ModelEvaluationView';
import { AlertManagementView } from './components/views/AlertManagementView';
import { IncidentWorkspaceView } from './components/views/IncidentWorkspaceView';
import { ThreatIntelView } from './components/views/ThreatIntelView';
import { ReportGeneratorView } from './components/views/ReportGeneratorView';
import { ToolsIntegrationView } from './components/views/ToolsIntegrationView';
import { PythonCodeView } from './components/views/PythonCodeView';

export default function App() {
  const [activeTab, setActiveTab] = useState<NavTab>('overview');
  const [datasetName, setDatasetName] = useState('Synthetic Demo Dataset (sample_network_traffic.csv)');
  const [isSyntheticData, setIsSyntheticData] = useState(true);
  const [flows, setFlows] = useState<FlowRecord[]>([]);
  const [cleanedFlows, setCleanedFlows] = useState<CleanedFlowRecord[]>([]);
  const [qualityReport, setQualityReport] = useState<DataQualityReport | undefined>(undefined);
  const [prepSummary, setPrepSummary] = useState<PreprocessingSummary | undefined>(undefined);
  const [models, setModels] = useState<TrainedModels | undefined>(undefined);
  const [predictions, setPredictions] = useState<DetectionPrediction[]>([]);
  const [alerts, setAlerts] = useState<SecurityAlert[]>([]);
  const [findings, setFindings] = useState<EDAFinding[]>([]);
  const [selectedAlertId, setSelectedAlertId] = useState<string | undefined>(undefined);
  const [isGuideOpen, setIsGuideOpen] = useState(false);
  const [isMobileMenuOpen, setIsMobileMenuOpen] = useState(false);
  const [notification, setNotification] = useState<string | null>(null);

  const showNotification = (msg: string) => {
    setNotification(msg);
    setTimeout(() => {
      setNotification((curr) => (curr === msg ? null : curr));
    }, 4000);
  };

  // Initialize with built-in demo dataset on first load or on demand
  const loadDemoData = (resetAlerts: boolean = true) => {
    if (resetAlerts) {
      clearStoredAlerts();
    }
    const rawDemo = generateDemoDataset();
    setFlows(rawDemo);
    setDatasetName('Synthetic Demo Dataset (sample_network_traffic.csv)');
    setIsSyntheticData(true);

    const headers = ['Timestamp', 'Source_IP', 'Destination_IP', 'Source_Port', 'Destination_Port', 'Protocol', 'Flow_Duration', 'Packet_Count', 'Byte_Count', 'Flow_Rate', 'Label', 'Attack_Category'];
    const rows = rawDemo.map(r => [
      r.timestamp, r.sourceIp, r.destinationIp, String(r.sourcePort), String(r.destinationPort),
      r.protocol, String(r.flowDuration), String(r.packetCount), String(r.byteCount), String(r.flowRate),
      r.label || 'NORMAL', r.attackCategory || 'Normal'
    ]);
    const { mapping, matchedNames, missingRequired } = detectColumnMapping(headers);
    const qReport = assessDatasetQuality(headers, rows, mapping, matchedNames, missingRequired);
    setQualityReport(qReport);

    const { cleanedRecords, trainRecords, testRecords, summary } = preprocessDataset(rawDemo, 0.75, 42);
    setCleanedFlows(cleanedRecords);
    setPrepSummary(summary);

    const edaFindings = generateEDAFindings(rawDemo);
    setFindings(edaFindings);

    const trained = trainAllModels(trainRecords, testRecords);
    setModels(trained);

    const initialPredictions = runInference(cleanedRecords, trained, 'random_forest');
    setPredictions(initialPredictions);

    const generatedAlerts = generateAlertsFromPredictions(initialPredictions, cleanedRecords);
    setAlerts(generatedAlerts);
    if (generatedAlerts.length > 0) {
      setSelectedAlertId(generatedAlerts[0].id);
    }
    setActiveTab('overview');
    showNotification(
      `Synthetic demo dataset loaded (${rawDemo.length.toLocaleString()} network flows, 4 ML models trained, ${generatedAlerts.length} alerts generated)`
    );
  };

  useEffect(() => {
    loadDemoData(false);
  }, []);

  // Handle CSV File Upload
  const handleFileUpload = (file: File) => {
    try {
      const reader = new FileReader();
      reader.onload = (e) => {
        try {
          const text = e.target?.result as string;
          if (!text || !text.trim()) {
            showNotification('Uploaded file is empty. Please provide a valid CSV or TSV dataset.');
            return;
          }

          const { headers, rows, detectedDelimiter } = parseCSV(text);
          if (headers.length === 0 || rows.length === 0) {
            showNotification('No tabular data rows detected in uploaded file.');
            return;
          }

          const { mapping, matchedNames, missingRequired, synthesizedFields } = detectColumnMapping(headers);
          const qReport = assessDatasetQuality(
            headers,
            rows,
            mapping,
            matchedNames,
            missingRequired,
            detectedDelimiter,
            synthesizedFields
          );
          setQualityReport(qReport);

          const safeRows = rows.length > 3000 ? rows.slice(0, 3000) : rows;
          const parsedFlows = convertRowsToFlowRecords(safeRows, mapping);
          setFlows(parsedFlows);
          setDatasetName(file.name);
          setIsSyntheticData(false);

          clearStoredAlerts();

          const { cleanedRecords, trainRecords, testRecords, summary } = preprocessDataset(parsedFlows, 0.75, 42);
          setCleanedFlows(cleanedRecords);
          setPrepSummary(summary);

          const edaFindings = generateEDAFindings(parsedFlows);
          setFindings(edaFindings);

          const trained = trainAllModels(trainRecords, testRecords);
          setModels(trained);

          const preds = runInference(cleanedRecords, trained, 'random_forest');
          setPredictions(preds);

          const genAlerts = generateAlertsFromPredictions(preds, cleanedRecords);
          setAlerts(genAlerts);
          setSelectedAlertId(genAlerts.length > 0 ? genAlerts[0].id : undefined);

          const detectedCategories = Array.from(new Set(parsedFlows.map(f => f.attackCategory || f.label || 'Normal')));
          const catSummary = detectedCategories.slice(0, 4).join(', ') + (detectedCategories.length > 4 ? ` +${detectedCategories.length - 4} more` : '');
          const rowNote = rows.length > 3000 ? ` (first 3,000 of ${rows.length.toLocaleString()} rows)` : '';

          showNotification(`Ingested "${file.name}"${rowNote}: ${parsedFlows.length} flows loaded [Categories: ${catSummary}].`);
        } catch (err: any) {
          console.error('Error processing uploaded file:', err);
          showNotification(`Failed to process dataset: ${err?.message || 'Unexpected parsing error'}`);
        }
      };

      reader.onerror = () => {
        showNotification('Error reading file from disk. Please try again.');
      };

      reader.readAsText(file);
    } catch (err: any) {
      console.error('File upload initialization error:', err);
      showNotification(`Upload error: ${err?.message || 'Failed to initialize reader'}`);
    }
  };

  // Switch active threat scenario telemetry
  const handleSelectScenario = (scenario: TrafficScenario) => {
    clearStoredAlerts();
    const { flows: newFlows, name } = generateScenarioDataset(scenario);
    setFlows(newFlows);
    setDatasetName(name);
    setIsSyntheticData(true);

    const headers = ['Timestamp', 'Source_IP', 'Destination_IP', 'Source_Port', 'Destination_Port', 'Protocol', 'Flow_Duration', 'Packet_Count', 'Byte_Count', 'Flow_Rate', 'Label', 'Attack_Category'];
    const rows = newFlows.map(r => [
      r.timestamp, r.sourceIp, r.destinationIp, String(r.sourcePort), String(r.destinationPort),
      r.protocol, String(r.flowDuration), String(r.packetCount), String(r.byteCount), String(r.flowRate),
      r.label || 'NORMAL', r.attackCategory || 'Normal'
    ]);
    const { mapping, matchedNames, missingRequired, synthesizedFields } = detectColumnMapping(headers);
    const qReport = assessDatasetQuality(headers, rows, mapping, matchedNames, missingRequired, 'Simulated Telemetry Feed', synthesizedFields);
    setQualityReport(qReport);

    const { cleanedRecords, trainRecords, testRecords, summary } = preprocessDataset(newFlows, 0.75, 42);
    setCleanedFlows(cleanedRecords);
    setPrepSummary(summary);

    const edaFindings = generateEDAFindings(newFlows);
    setFindings(edaFindings);

    const trained = trainAllModels(trainRecords, testRecords);
    setModels(trained);

    const preds = runInference(cleanedRecords, trained, 'random_forest');
    setPredictions(preds);

    const genAlerts = generateAlertsFromPredictions(preds, cleanedRecords);
    setAlerts(genAlerts);
    setSelectedAlertId(genAlerts.length > 0 ? genAlerts[0].id : undefined);

    showNotification(`Simulated Telemetry Switched: ${name} (${newFlows.length} flows loaded).`);
  };

  // Re-run preprocessing with customized ratio/seed
  const handleExecutePreprocessing = (ratio: number, seed: number) => {
    if (flows.length === 0) return;
    const { cleanedRecords, trainRecords, testRecords, summary } = preprocessDataset(flows, ratio, seed);
    setCleanedFlows(cleanedRecords);
    setPrepSummary(summary);

    if (models) {
      const trained = trainAllModels(trainRecords, testRecords);
      setModels(trained);
      const preds = runInference(cleanedRecords, trained, trained.activeAlgorithm);
      setPredictions(preds);
      const genAlerts = generateAlertsFromPredictions(preds, cleanedRecords);
      setAlerts(genAlerts);
      if (genAlerts.length > 0) {
        setSelectedAlertId(genAlerts[0].id);
      }
    }
    showNotification(`Preprocessing completed (${Math.round(ratio * 100)}%/${Math.round((1 - ratio) * 100)}% split, seed ${seed}).`);
  };

  // Train models trigger
  const handleTrainModels = () => {
    if (cleanedFlows.length === 0) return;
    const { trainRecords, testRecords } = preprocessDataset(flows, 0.75, 42);
    const trained = trainAllModels(trainRecords, testRecords);
    setModels(trained);
    showNotification('All 4 ML models re-trained and evaluated on hold-out test split.');
  };

  // Run flow classification inference
  const handleRunInference = (algorithm: ModelAlgorithm) => {
    if (!models || cleanedFlows.length === 0) return;
    const preds = runInference(cleanedFlows, models, algorithm);
    setPredictions(preds);
    const genAlerts = generateAlertsFromPredictions(preds, cleanedFlows);
    setAlerts(genAlerts);
    if (genAlerts.length > 0 && !selectedAlertId) {
      setSelectedAlertId(genAlerts[0].id);
    }
    const susCount = preds.filter(p => p.predictedLabel === 'SUSPICIOUS').length;
    showNotification(`Inference completed with ${algorithm.replace('_', ' ')}: ${susCount} suspicious flows flagged.`);
  };

  // Status and Note Updates
  const handleUpdateStatus = (
    alertId: string,
    newStatus: AlertStatus,
    noteText: string,
    author: string = 'Junior SOC Analyst'
  ) => {
    const updated = updateAlertStatus(alertId, newStatus, noteText, author);
    setAlerts(updated);
  };

  const handleAddNote = (
    alertId: string,
    noteText: string,
    author: string = 'Junior SOC Analyst'
  ) => {
    const updated = addIncidentNote(alertId, noteText, author);
    setAlerts(updated);
  };

  const criticalAlertCount = alerts.filter(a => a.severity === 'CRITICAL').length;
  const normalCount = flows.filter(f => f.label === 'NORMAL').length;
  const suspiciousCount = flows.filter(f => f.label === 'SUSPICIOUS').length;
  const activeMetrics = models ? models.metrics[models.activeAlgorithm] : undefined;

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col font-sans">
      {/* Top Bar Header */}
      <Header
        onLoadDemo={() => loadDemoData(true)}
        onOpenGuide={() => setIsGuideOpen(true)}
        datasetName={datasetName}
        totalFlows={flows.length}
        isSyntheticData={isSyntheticData}
        isMobileMenuOpen={isMobileMenuOpen}
        onToggleMobileMenu={() => setIsMobileMenuOpen(prev => !prev)}
      />

      {/* Toast Notification Banner */}
      {notification && (
        <div className="fixed top-16 right-4 sm:right-6 z-50 max-w-[calc(100vw-2rem)] sm:max-w-md flex items-center gap-2.5 px-4 py-2.5 bg-slate-900 border border-cyan-500/40 text-cyan-200 rounded-lg shadow-xl shadow-cyan-950/40 text-xs font-medium">
          <CheckCircle2 className="w-4 h-4 text-cyan-400 shrink-0" />
          <span>{notification}</span>
        </div>
      )}

      {/* Main Layout: Sidebar + View Content */}
      <div className="flex-1 flex overflow-x-hidden">
        <Sidebar
          activeTab={activeTab}
          onSelectTab={setActiveTab}
          alertCount={alerts.length}
          criticalAlertCount={criticalAlertCount}
          isMobileOpen={isMobileMenuOpen}
          onCloseMobile={() => setIsMobileMenuOpen(false)}
          onOpenGuide={() => setIsGuideOpen(true)}
        />

        <main className="flex-1 min-w-0 p-4 sm:p-6 overflow-y-auto bg-slate-950 min-h-[calc(100vh-53px)]">
          <div className="max-w-7xl mx-auto">
            {activeTab === 'overview' && (
              <OverviewView
                flows={flows}
                alerts={alerts}
                metrics={activeMetrics}
                isSyntheticData={isSyntheticData}
                onLoadDemo={() => loadDemoData(true)}
                onNavigateToTab={setActiveTab}
                onSelectAlert={setSelectedAlertId}
              />
            )}

            {activeTab === 'data_management' && (
              <DataManagementView
                flows={flows}
                qualityReport={qualityReport}
                datasetName={datasetName}
                onFileUpload={handleFileUpload}
                onLoadDemo={() => loadDemoData(true)}
                onSelectScenario={handleSelectScenario}
                onNavigateToTab={setActiveTab}
              />
            )}

            {activeTab === 'preprocessing' && (
              <PreprocessingView
                cleanedFlows={cleanedFlows}
                summary={prepSummary}
                onExecutePreprocessing={handleExecutePreprocessing}
                onNavigateToTab={setActiveTab}
              />
            )}

            {activeTab === 'eda' && (
              <EDAView
                flows={flows}
                findings={findings}
                onNavigateToTab={setActiveTab}
              />
            )}

            {activeTab === 'detection' && (
              <IntrusionDetectionView
                cleanedFlows={cleanedFlows}
                models={models}
                predictions={predictions}
                onTrainModels={handleTrainModels}
                onRunInference={handleRunInference}
                onNavigateToTab={setActiveTab}
                onSelectAlert={setSelectedAlertId}
              />
            )}

            {activeTab === 'evaluation' && (
              <ModelEvaluationView
                metricsRecord={models?.metrics}
                onNavigateToTab={setActiveTab}
              />
            )}

            {activeTab === 'alerts' && (
              <AlertManagementView
                alerts={alerts}
                onUpdateStatus={handleUpdateStatus}
                onSelectAlert={setSelectedAlertId}
                onNavigateToTab={setActiveTab}
              />
            )}

            {activeTab === 'incidents' && (
              <IncidentWorkspaceView
                alerts={alerts}
                selectedAlertId={selectedAlertId}
                onSelectAlert={setSelectedAlertId}
                onUpdateStatus={handleUpdateStatus}
                onAddNote={handleAddNote}
                onNavigateToTab={setActiveTab}
              />
            )}

            {activeTab === 'threat_intel' && (
              <ThreatIntelView
                alerts={alerts}
                flows={flows}
                metrics={activeMetrics}
                onNavigateToTab={setActiveTab}
              />
            )}

            {activeTab === 'reports' && (
              <ReportGeneratorView
                datasetName={datasetName}
                totalFlows={flows.length}
                normalCount={normalCount}
                suspiciousCount={suspiciousCount}
                alerts={alerts}
                cleanedFlows={cleanedFlows}
                metrics={activeMetrics}
                findings={findings}
              />
            )}

            {activeTab === 'integrations' && (
              <ToolsIntegrationView />
            )}

            {activeTab === 'python_export' && (
              <PythonCodeView />
            )}
          </div>
        </main>
      </div>

      {/* Junior SOC Analyst Guide Modal */}
      <SOCGuideModal
        isOpen={isGuideOpen}
        onClose={() => setIsGuideOpen(false)}
        onJumpToTab={setActiveTab}
      />
    </div>
  );
}
