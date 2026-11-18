/**
 * Data structures and types for NETGUARD AI Network Intrusion Detection System
 */

export type ProtocolType = 'TCP' | 'UDP' | 'ICMP' | 'OTHER';

export type TrafficLabel = 'NORMAL' | 'SUSPICIOUS';

export type AttackCategory = 
  | 'Normal'
  | 'Port Scan'
  | 'DoS / DDoS'
  | 'Brute Force'
  | 'Web Attack'
  | 'Botnet / C2'
  | 'Unknown Anomaly';

export type SeverityLevel = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';

export type AlertStatus = 'New' | 'Investigating' | 'Resolved' | 'False Positive';

export interface FlowRecord {
  id: string;
  timestamp: string;
  sourceIp: string;
  destinationIp: string;
  sourcePort: number;
  destinationPort: number;
  protocol: ProtocolType;
  flowDuration: number; // in seconds
  packetCount: number;
  byteCount: number;
  flowRate: number; // bytes per second
  label?: TrafficLabel;
  attackCategory?: AttackCategory;
  // Raw additional fields if present in CSV
  rawRowIndex?: number;
}

export interface CleanedFlowRecord extends FlowRecord {
  normalizedDuration: number;
  normalizedPackets: number;
  normalizedBytes: number;
  normalizedRate: number;
  protocolEncoded: [number, number, number]; // [isTCP, isUDP, isICMP]
  features: number[];
}

export interface DataQualityReport {
  totalRows: number;
  totalColumns: number;
  missingValuesCount: number;
  duplicateCount: number;
  invalidNumericCount: number;
  inconsistentLabelsCount: number;
  columnDataTypes: Record<string, string>;
  detectedColumns: string[];
  missingRequiredColumns: string[];
  qualityScore: number; // 0-100%
  columnMapping: Record<string, string>;
  detectedDelimiter?: string;
  synthesizedFields?: string[];
}

export interface PreprocessingSummary {
  missingValuesHandled: number;
  duplicatesRemoved: number;
  invalidValuesCorrected: number;
  labelsStandardized: number;
  encodingStrategy: string;
  scalingStrategy: string;
  classDistribution: {
    normal: number;
    suspicious: number;
    imbalanceRatio: number;
  };
  trainCount: number;
  testCount: number;
  featuresUsed: string[];
  dataLeakageSafeguards: string[];
}

export interface EDAFinding {
  id: string;
  title: string;
  metric: string;
  description: string;
  severity: 'info' | 'warning' | 'critical';
  category: string;
}

export type ModelAlgorithm = 'logistic_regression' | 'decision_tree' | 'random_forest' | 'isolation_forest';

export interface ModelMetrics {
  algorithm: ModelAlgorithm;
  algorithmName: string;
  modelType: 'supervised' | 'unsupervised';
  accuracy: number;
  precision: number;
  recall: number;
  f1Score: number;
  falsePositiveRate: number;
  falseNegativeRate: number;
  trainingTimeMs: number;
  confusionMatrix: {
    truePositives: number;
    trueNegatives: number;
    falsePositives: number;
    falseNegatives: number;
  };
  featureImportances?: { feature: string; importance: number }[];
  treeRulesSummary?: string[];
}

export interface DetectionPrediction {
  flowId: string;
  predictedLabel: TrafficLabel;
  predictedCategory: AttackCategory;
  confidence: number; // 0-1
  anomalyScore?: number; // for isolation forest
  modelUsed: ModelAlgorithm;
  modelName: string;
  severity: SeverityLevel;
  severityReason: string;
  detectionTimestamp: string;
}

export interface SecurityAlert {
  id: string; // e.g. ALT-2026-0041
  flowId: string;
  timestamp: string;
  sourceIp: string;
  destinationIp: string;
  sourcePort: number;
  destinationPort: number;
  protocol: ProtocolType;
  detectionReason: string;
  predictedCategory: AttackCategory;
  severity: SeverityLevel;
  status: AlertStatus;
  confidence: number;
  flowDuration: number;
  packetCount: number;
  byteCount: number;
  flowRate: number;
  investigationNotes: IncidentNote[];
  recommendedActions: string[];
  resolutionSummary?: string;
  resolvedAt?: string;
}

export interface IncidentNote {
  id: string;
  author: string;
  timestamp: string;
  text: string;
  statusChange?: AlertStatus;
}

export interface TrainedModels {
  logisticRegression: any;
  decisionTree: any;
  randomForest: any;
  isolationForest: any;
  metrics: Record<ModelAlgorithm, ModelMetrics>;
  activeAlgorithm: ModelAlgorithm;
}
