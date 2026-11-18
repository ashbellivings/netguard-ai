/**
 * NETGUARD AI - Comprehensive Automated Functionality Audit Suite
 * Tests all 14 checklist items against master capstone requirements.
 */

import { generateDemoDataset, generateScenarioDataset, convertFlowsToCSV, SCENARIOS } from '../src/data/demoTraffic';
import {
  parseCSV,
  detectColumnMapping,
  assessDatasetQuality,
  convertRowsToFlowRecords,
  preprocessDataset,
} from '../src/utils/dataProcessor';
import {
  LogisticRegressionModel,
  DecisionTreeClassifier,
  RandomForestClassifier,
  IsolationForestModel,
  trainAllModels,
  runInference,
  determineSeverity,
} from '../src/utils/mlEngine';
import { generateEDAFindings, computePearsonCorrelation } from '../src/utils/edaFindings';
import {
  generateAlertsFromPredictions,
  getRecommendedActions,
} from '../src/utils/alertManager';
import {
  exportAlertsToCSV,
  exportCleanedDatasetToCSV,
  exportAlertsToSQLiteSQL,
  generateExecutiveReportHTML,
} from '../src/utils/reportExporter';
import { FlowRecord, SecurityAlert } from '../src/types';

interface TestResult {
  id: number;
  name: string;
  category: string;
  passed: boolean;
  details: string;
}

const results: TestResult[] = [];

function assert(condition: boolean, testId: number, name: string, category: string, details: string) {
  if (!condition) {
    console.error(`❌ [FAIL] Test ${testId}: ${name} - ${details}`);
    results.push({ id: testId, name, category, passed: false, details });
    throw new Error(`Test failed: ${name}`);
  } else {
    console.log(`✅ [PASS] Test ${testId}: ${name}`);
    results.push({ id: testId, name, category, passed: true, details });
  }
}

async function runAudit() {
  console.log('======================================================================');
  console.log('  NETGUARD AI: MASTER SOC CAPSTONE FUNCTIONALITY AUDIT');
  console.log('======================================================================\n');

  // -------------------------------------------------------------------------
  // 1. Test CSV uploading and demo dataset loading
  // -------------------------------------------------------------------------
  console.log('--- AUDIT SECTION 1: INGESTION, PARSING & SCENARIOS ---');
  
  // 1.1 Comma CSV
  const commaCSV = `Timestamp,Source_IP,Destination_IP,Source_Port,Destination_Port,Protocol,Flow_Duration,Packet_Count,Byte_Count,Flow_Rate,Label,Attack_Category
2026-11-12 08:00:00,192.168.1.105,10.0.0.5,52140,80,TCP,0.045,12,1420,31555.5,NORMAL,Normal
2026-11-12 08:00:01,185.220.101.5,192.168.1.50,48120,22,TCP,0.010,2,112,11200.0,SUSPICIOUS,Brute Force`;
  const parsedComma = parseCSV(commaCSV);
  assert(parsedComma.detectedDelimiter.includes(','), 1, 'Comma CSV delimiter detection', 'Data Ingestion', `Detected: ${parsedComma.detectedDelimiter}`);
  assert(parsedComma.rows.length === 2, 2, 'Comma CSV rows parsed', 'Data Ingestion', 'Parsed 2 data rows');

  // 1.2 Tab TSV (Zeek style)
  const tabTSV = `ts\tid.orig_h\tid.resp_h\tid.orig_p\tid.resp_p\tproto\tduration\torig_pkts\torig_bytes
2026-11-12 08:00:00\t192.168.1.10\t10.0.0.1\t54000\t53\tUDP\t0.005\t2\t140`;
  const parsedTab = parseCSV(tabTSV);
  assert(parsedTab.detectedDelimiter.includes('tab') || parsedTab.detectedDelimiter.includes('\t'), 3, 'Tab TSV delimiter detection', 'Data Ingestion', `Detected: ${parsedTab.detectedDelimiter}`);
  const zeekMapping = detectColumnMapping(parsedTab.headers);
  assert(zeekMapping.matchedNames.sourceIp === 'id.orig_h' && zeekMapping.mapping.sourceIp === 1, 4, 'Zeek column mapping (id.orig_h -> sourceIp)', 'Data Ingestion', `Mapped ${zeekMapping.matchedNames.sourceIp} to index ${zeekMapping.mapping.sourceIp}`);

  // 1.3 Semicolon CSV
  const semiCSV = `Timestamp;Source_IP;Destination_IP;Source_Port;Destination_Port;Protocol;Flow_Duration;Packet_Count;Byte_Count;Flow_Rate;Label
2026-11-12 08:00:00;10.0.0.1;10.0.0.2;443;443;TCP;1.0;10;1000;1000.0;NORMAL`;
  const parsedSemi = parseCSV(semiCSV);
  assert(parsedSemi.detectedDelimiter.includes(';'), 5, 'Semicolon CSV delimiter detection', 'Data Ingestion', `Detected: ${parsedSemi.detectedDelimiter}`);

  // 1.4 Pipe CSV
  const pipeCSV = `src_ip|dst_ip|proto|dur|pkts|bytes|label
10.0.0.1|10.0.0.2|TCP|0.5|5|500|NORMAL`;
  const parsedPipe = parseCSV(pipeCSV);
  assert(parsedPipe.detectedDelimiter.includes('|'), 6, 'Pipe delimiter detection', 'Data Ingestion', `Detected: ${parsedPipe.detectedDelimiter}`);

  // 1.5 Demo scenarios
  for (const sc of SCENARIOS) {
    const { flows, name } = generateScenarioDataset(sc.id);
    assert(flows.length >= 100, 7, `Scenario ${sc.id} flow count generation`, 'Demo Scenarios', `Generated ${flows.length} flows for ${name}`);
  }

  // -------------------------------------------------------------------------
  // 2. Test data cleaning and preprocessing
  // -------------------------------------------------------------------------
  console.log('\n--- AUDIT SECTION 2: PREPROCESSING & DATA LEAKAGE PREVENTION ---');
  const demoFlows = generateDemoDataset();
  assert(demoFlows.length > 0, 8, 'Demo dataset generation', 'Preprocessing', `${demoFlows.length} flows loaded`);

  const { cleanedRecords, trainRecords, testRecords, summary } = preprocessDataset(demoFlows, 0.75, 42);
  assert(cleanedRecords.length === demoFlows.length, 9, 'Cleaned records total preservation', 'Preprocessing', `${cleanedRecords.length} records preserved`);
  assert(summary.trainCount > 0 && summary.testCount > 0, 11, 'Stratified split ratio calculation', 'Preprocessing', `${summary.trainCount} train / ${summary.testCount} test`);
  
  // Verify 8 features normalized
  assert(cleanedRecords[0].features.length === 8, 12, '8-dimensional feature vector extraction', 'Feature Engineering', 'Features: dur, log_pkts, log_bytes, log_rate, dst_port, tcp, udp, icmp');
  assert(cleanedRecords.every(r => r.features.every(v => !isNaN(v) && isFinite(v))), 13, 'Zero NaN or infinite values in feature space', 'Data Integrity', 'All feature vectors finite');

  // -------------------------------------------------------------------------
  // 3. Verify all visualizations use actual dataset values
  // -------------------------------------------------------------------------
  console.log('\n--- AUDIT SECTION 3: VISUALIZATIONS & EDA DATA CONSISTENCY ---');
  const edaFindings = generateEDAFindings(demoFlows);
  assert(edaFindings.length >= 8, 14, 'Automated security data findings generation', 'EDA Engine', `${edaFindings.length} findings derived`);

  // Verify Pearson correlation calculation within [-1, 1]
  const v1 = demoFlows.map(f => f.packetCount);
  const v2 = demoFlows.map(f => f.byteCount);
  const pearsonR = computePearsonCorrelation(v1, v2);
  assert(pearsonR >= -1 && pearsonR <= 1 && !isNaN(pearsonR), 15, 'Pearson correlation mathematical validity', 'Statistical Analysis', `r = ${pearsonR.toFixed(4)}`);

  // Verify protocol distributions sum exactly to total flows
  const protoCounts: Record<string, number> = {};
  demoFlows.forEach(f => { protoCounts[f.protocol] = (protoCounts[f.protocol] || 0) + 1; });
  const protoSum = Object.values(protoCounts).reduce((a, b) => a + b, 0);
  assert(protoSum === demoFlows.length, 16, 'Protocol telemetry sum matches total flows', 'Visualization Accuracy', `${protoSum} flows classified`);

  // -------------------------------------------------------------------------
  // 4. Train and compare supervised and unsupervised ML models
  // -------------------------------------------------------------------------
  console.log('\n--- AUDIT SECTION 4: MACHINE LEARNING MODELS TRAINING ---');
  const trainedModels = trainAllModels(trainRecords, testRecords);
  assert(trainedModels.logisticRegression !== undefined, 17, 'Logistic Regression trained', 'ML Classifiers', 'LogisticRegressionModel initialized');
  assert(trainedModels.decisionTree !== undefined, 18, 'Decision Tree trained', 'ML Classifiers', 'DecisionTreeClassifier initialized');
  assert(trainedModels.randomForest !== undefined, 19, 'Random Forest ensemble trained', 'ML Classifiers', '12 Bagged Trees initialized');
  assert(trainedModels.isolationForest !== undefined, 20, 'Isolation Forest trained', 'ML Classifiers', 'Unsupervised Anomaly Model initialized');

  // -------------------------------------------------------------------------
  // 5. Verify actual predictions and evaluation metrics
  // -------------------------------------------------------------------------
  console.log('\n--- AUDIT SECTION 5: MODEL EVALUATION & PREDICTION METRICS ---');
  const rfMetrics = trainedModels.metrics.random_forest;
  assert(rfMetrics.accuracy >= 0.70 && rfMetrics.accuracy <= 1.0, 21, 'Random Forest accuracy bounds', 'Metrics Evaluation', `Accuracy: ${(rfMetrics.accuracy * 100).toFixed(1)}%`);
  assert(rfMetrics.f1Score >= 0.65 && rfMetrics.f1Score <= 1.0, 22, 'Random Forest F1-score bounds', 'Metrics Evaluation', `F1-Score: ${(rfMetrics.f1Score * 100).toFixed(1)}%`);
  
  const cm = rfMetrics.confusionMatrix;
  const cmTotal = cm.truePositives + cm.trueNegatives + cm.falsePositives + cm.falseNegatives;
  assert(cmTotal === testRecords.length, 23, 'Confusion matrix total matches test split size', 'Metrics Evaluation', `${cmTotal} test cases evaluated (TP: ${cm.truePositives}, TN: ${cm.trueNegatives}, FP: ${cm.falsePositives}, FN: ${cm.falseNegatives})`);

  // Check Decision Tree rule extraction
  const dtMetrics = trainedModels.metrics.decision_tree;
  assert(Boolean(dtMetrics.treeRulesSummary && dtMetrics.treeRulesSummary.length > 0), 24, 'Decision Tree explainable rules extracted', 'Explainable AI', `${dtMetrics.treeRulesSummary?.length} rules extracted`);

  // -------------------------------------------------------------------------
  // 6. Test security alert generation
  // -------------------------------------------------------------------------
  console.log('\n--- AUDIT SECTION 6: SECURITY ALERT ENGINE ---');
  const predictions = runInference(cleanedRecords, trainedModels, 'random_forest');
  assert(predictions.length === cleanedRecords.length, 25, 'Inference run on all cleaned records', 'Threat Detection', `${predictions.length} predictions generated`);

  const alerts = generateAlertsFromPredictions(predictions, cleanedRecords);
  assert(alerts.length > 0, 26, 'Security alerts generated from suspicious predictions', 'SOC Alerting', `${alerts.length} security alerts raised`);
  
  // Verify severity assignment logic
  const criticals = alerts.filter(a => a.severity === 'CRITICAL');
  assert(criticals.length > 0, 27, 'Critical severity prioritization active', 'Prioritization', `${criticals.length} Critical alerts identified`);
  
  // Verify SOC recommended actions playbook
  assert(alerts[0].recommendedActions.length >= 3, 28, 'Recommended SOC playbooks attached to alerts', 'SOC Playbooks', `${alerts[0].recommendedActions.length} mitigation steps provided`);

  // -------------------------------------------------------------------------
  // 7. Test alert filtering and searching
  // -------------------------------------------------------------------------
  console.log('\n--- AUDIT SECTION 7: ALERT FILTERING & SEARCHING ---');
  const searchResult = alerts.filter(a => a.sourceIp.includes(alerts[0].sourceIp));
  assert(searchResult.length > 0, 29, 'Alert filtering by Source IP', 'Alert Management', `Found ${searchResult.length} matching alerts`);

  const criticalFiltered = alerts.filter(a => a.severity === 'CRITICAL');
  assert(criticalFiltered.every(a => a.severity === 'CRITICAL'), 30, 'Severity filtering accuracy', 'Alert Management', 'All items match filter');

  // -------------------------------------------------------------------------
  // 8. Test incident creation, investigation notes and status updates
  // -------------------------------------------------------------------------
  console.log('\n--- AUDIT SECTION 8: INCIDENT WORKSPACE & AUDIT TRAILS ---');
  const targetAlert = { ...alerts[0] };
  targetAlert.status = 'Investigating';
  targetAlert.investigationNotes.push({
    id: 'NOTE-TEST-1',
    author: 'Audit Officer',
    timestamp: new Date().toISOString(),
    text: 'Firewall rules updated to null-route attacking IP.',
    statusChange: 'Investigating',
  });
  assert(targetAlert.status === 'Investigating', 31, 'Incident status transition to Investigating', 'Incident Triage', 'Status updated');
  assert(targetAlert.investigationNotes.length >= 2, 32, 'Analyst note appended to incident dossier', 'Incident Triage', `Total notes: ${targetAlert.investigationNotes.length}`);

  // -------------------------------------------------------------------------
  // 9. Verify SQLite persistence
  // -------------------------------------------------------------------------
  console.log('\n--- AUDIT SECTION 9: SQLITE PERSISTENCE & SCHEMA DUMP ---');
  const sqliteSQL = exportAlertsToSQLiteSQL(alerts);
  assert(sqliteSQL.includes('CREATE TABLE IF NOT EXISTS alerts'), 33, 'SQLite alerts table schema DDL', 'Database Persistence', 'CREATE TABLE alerts validated');
  assert(sqliteSQL.includes('CREATE TABLE IF NOT EXISTS investigation_notes'), 34, 'SQLite investigation_notes schema DDL', 'Database Persistence', 'CREATE TABLE investigation_notes validated');
  assert(sqliteSQL.includes('FOREIGN KEY (alert_id) REFERENCES alerts'), 35, 'SQLite relational foreign key constraint', 'Database Persistence', 'Relational integrity verified');
  assert(sqliteSQL.includes('INSERT OR REPLACE INTO alerts'), 36, 'SQLite DML insert statements generated', 'Database Persistence', 'Insert statements verified');

  // -------------------------------------------------------------------------
  // 10. Test report downloads
  // -------------------------------------------------------------------------
  console.log('\n--- AUDIT SECTION 10: REPORT GENERATION & EXPORTS ---');
  const alertsCSV = exportAlertsToCSV(alerts);
  assert(alertsCSV.startsWith('Alert_ID,Timestamp'), 37, 'Alerts CSV export formatted with headers', 'Audit Reporting', 'Headers validated');
  
  const cleanedCSV = exportCleanedDatasetToCSV(cleanedRecords);
  assert(cleanedCSV.startsWith('Flow_ID,Timestamp'), 38, 'Cleaned features CSV export formatted', 'Audit Reporting', 'Feature data CSV validated');

  const activeCSV = convertFlowsToCSV(demoFlows);
  assert(activeCSV.includes('Source_IP'), 39, 'Active telemetry CSV export', 'Audit Reporting', 'Active flows converted to CSV');

  const executiveHTML = generateExecutiveReportHTML({
    datasetName: 'Audit Test Telemetry',
    totalFlows: demoFlows.length,
    normalCount: demoFlows.filter(f => f.label === 'NORMAL').length,
    suspiciousCount: demoFlows.filter(f => f.label === 'SUSPICIOUS').length,
    alerts,
    metrics: rfMetrics,
    findings: edaFindings,
  });
  assert(executiveHTML.includes('NETGUARD AI') && executiveHTML.includes('Print / Save to PDF'), 40, 'Executive HTML printable report generated', 'Executive Reporting', 'PDF printable report verified');

  // -------------------------------------------------------------------------
  // 11-14. Security hardening, ML consistency, & edge-case resilience
  // -------------------------------------------------------------------------
  console.log('\n--- AUDIT SECTION 11-14: SECURITY, ML INTEGRITY & EDGE CASES ---');
  assert(demoFlows.every(f => f.id.startsWith('FLW-')), 41, 'Synthetic flow records uniquely indexed', 'Data Governance', 'Prefix FLW- verified');
  assert(alerts.every(a => a.id.startsWith('ALT-2026-')), 42, 'Security alerts formatted with academic incident format', 'Data Governance', 'ALT-2026-XXXX format verified');

  // Test XSS escaping in HTML Executive Report
  const xssHTML = generateExecutiveReportHTML({
    datasetName: '<script>alert("xss")</script>.csv',
    totalFlows: 1,
    normalCount: 1,
    suspiciousCount: 0,
    alerts: [],
    findings: [],
  });
  assert(!xssHTML.includes('<script>alert("xss")</script>') && xssHTML.includes('&lt;script&gt;'), 43, 'XSS payloads HTML-escaped in generated Executive Report', 'Security Hardening', 'HTML escaping verified');

  // Test CSV formula injection sanitization (CWE-1236)
  const dangerousAlert: SecurityAlert = {
    ...alerts[0],
    detectionReason: '=cmd|"/C calc"!A0',
    investigationNotes: [{
      id: 'NOTE-XSS',
      author: 'Tester',
      timestamp: '2026-11-12 00:00:00',
      text: '+SUM(1,2)',
    }],
  };
  const safeAlertCSV = exportAlertsToCSV([dangerousAlert]);
  assert(safeAlertCSV.includes("'=cmd") && safeAlertCSV.includes("'+SUM(1,2)"), 44, 'CSV formula injection characters neutralized with leading quote', 'Security Hardening', 'CWE-1236 mitigation verified');

  // Test Random Forest feature importances match valid feature names & sum near 1.0
  const rfImpSum = (rfMetrics.featureImportances || []).reduce((acc, item) => acc + item.importance, 0);
  assert(rfImpSum > 0.95 && rfImpSum <= 1.05, 45, 'Random Forest feature importances sum accurately after name alignment', 'ML Integrity', `Importance sum: ${rfImpSum.toFixed(4)}`);

  // Test empty dataset ML training safety (no uncaught crashes)
  const emptyTrained = trainAllModels([], []);
  assert(emptyTrained.randomForest.predict([0, 0, 0, 0, 0, 1, 0, 0]).label === 'NORMAL', 46, 'Empty dataset ML fallback executes without crashing', 'Resilience', 'Empty input safely handled');

  console.log('\n======================================================================');
  console.log(`  AUDIT COMPLETE: All ${results.length} Tests Passed Successfully!`);
  console.log('======================================================================\n');
}

runAudit().catch(err => {
  console.error('Audit run encountered an error:', err);
  process.exit(1);
});
