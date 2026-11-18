import { CleanedFlowRecord, ModelAlgorithm, ModelMetrics, DetectionPrediction, SeverityLevel, AttackCategory, TrafficLabel } from '../types';

/**
 * Feature names matching CleanedFlowRecord.features:
 * 0: Flow Duration
 * 1: Packet Count (log1p)
 * 2: Byte Count (log1p)
 * 3: Flow Rate (log1p)
 * 4: Destination Port
 * 5: Protocol_TCP
 * 6: Protocol_UDP
 * 7: Protocol_ICMP
 */
export const FEATURE_NAMES = [
  'Flow Duration',
  'Packet Count (Log)',
  'Byte Count (Log)',
  'Flow Rate (Log)',
  'Destination Port',
  'Protocol TCP',
  'Protocol UDP',
  'Protocol ICMP',
];

function createSeededRandom(seed: number): () => number {
  let s = Math.abs(Math.floor(seed)) % 233280 || 42;
  return () => {
    s = (s * 9301 + 49297) % 233280;
    return s / 233280;
  };
}

// -------------------------------------------------------------
// 1. Logistic Regression Model Implementation
// -------------------------------------------------------------
export class LogisticRegressionModel {
  weights: number[] = [];
  bias: number = 0;
  learningRate: number = 0.08;
  epochs: number = 120;

  train(trainData: CleanedFlowRecord[], seed: number = 42): void {
    const nFeatures = 8;
    const rand = createSeededRandom(seed);
    this.weights = new Array(nFeatures).fill(0).map(() => (rand() - 0.5) * 0.1);
    this.bias = 0;

    if (trainData.length === 0) return;

    const X = trainData.map(r => r.features);
    const y = trainData.map(r => (r.label === 'SUSPICIOUS' ? 1 : 0));
    const m = X.length;

    for (let epoch = 0; epoch < this.epochs; epoch++) {
      const gradW = new Array(nFeatures).fill(0);
      let gradB = 0;

      for (let i = 0; i < m; i++) {
        const xi = X[i];
        const yi = y[i];

        // Linear combination
        let z = this.bias;
        for (let j = 0; j < nFeatures; j++) {
          z += this.weights[j] * xi[j];
        }

        // Sigmoid
        const yHat = 1 / (1 + Math.exp(-Math.max(-15, Math.min(15, z))));
        const error = yHat - yi;

        for (let j = 0; j < nFeatures; j++) {
          gradW[j] += error * xi[j];
        }
        gradB += error;
      }

      // Update weights with L2 regularization
      for (let j = 0; j < nFeatures; j++) {
        this.weights[j] -= (this.learningRate * (gradW[j] / m + 0.001 * this.weights[j]));
      }
      this.bias -= (this.learningRate * (gradB / m));
    }
  }

  predictProba(features: number[]): number {
    let z = this.bias;
    for (let j = 0; j < features.length; j++) {
      z += this.weights[j] * features[j];
    }
    return 1 / (1 + Math.exp(-Math.max(-15, Math.min(15, z))));
  }

  predict(features: number[]): { label: TrafficLabel; confidence: number } {
    const prob = this.predictProba(features);
    const label: TrafficLabel = prob >= 0.5 ? 'SUSPICIOUS' : 'NORMAL';
    const confidence = prob >= 0.5 ? prob : 1 - prob;
    return { label, confidence };
  }
}

// -------------------------------------------------------------
// 2. Decision Tree Classifier Implementation
// -------------------------------------------------------------
interface TreeNode {
  isLeaf: boolean;
  prediction?: TrafficLabel;
  probability?: number;
  splitFeature?: number;
  splitThreshold?: number;
  left?: TreeNode;
  right?: TreeNode;
  samples?: number;
}

export class DecisionTreeClassifier {
  root: TreeNode | null = null;
  maxDepth: number = 6;
  minSamplesSplit: number = 4;
  rulesSummary: string[] = [];
  featureImportances: { feature: string; importance: number }[] = [];

  train(trainData: CleanedFlowRecord[]): void {
    if (trainData.length === 0) {
      this.root = { isLeaf: true, prediction: 'NORMAL', probability: 0.5, samples: 0 };
      this.featureImportances = FEATURE_NAMES.map(name => ({ feature: name, importance: 0 }));
      this.rulesSummary = ['No training records available.'];
      return;
    }

    const X = trainData.map(r => r.features);
    const y = trainData.map(r => (r.label === 'SUSPICIOUS' ? 1 : 0));
    const importances = new Array(8).fill(0);

    this.root = this.buildTree(X, y, 0, importances);

    // Normalize importances
    const totalImp = importances.reduce((a, b) => a + b, 0) || 1;
    this.featureImportances = FEATURE_NAMES.map((name, i) => ({
      feature: name,
      importance: parseFloat((importances[i] / totalImp).toFixed(4)),
    })).sort((a, b) => b.importance - a.importance);

    // Generate human-readable rules
    this.rulesSummary = this.extractRules(this.root);
  }

  private gini(y: number[]): number {
    if (y.length === 0) return 0;
    const p1 = y.filter(val => val === 1).length / y.length;
    const p0 = 1 - p1;
    return 1 - (p0 * p0 + p1 * p1);
  }

  private buildTree(X: number[][], y: number[], depth: number, importances: number[]): TreeNode {
    const nSamples = y.length;
    const nSus = y.filter(val => val === 1).length;
    const probSus = nSamples > 0 ? nSus / nSamples : 0;

    // Base cases
    if (nSamples === 0 || !X[0] || depth >= this.maxDepth || nSamples < this.minSamplesSplit || probSus === 0 || probSus === 1) {
      return {
        isLeaf: true,
        prediction: probSus >= 0.5 ? 'SUSPICIOUS' : 'NORMAL',
        probability: probSus >= 0.5 ? probSus : 1 - probSus,
        samples: nSamples,
      };
    }

    const currentGini = this.gini(y);
    let bestGain = 0;
    let bestFeature = -1;
    let bestThreshold = 0;
    let bestLeftIndices: number[] = [];
    let bestRightIndices: number[] = [];

    const nFeatures = X[0].length;
    for (let f = 0; f < nFeatures; f++) {
      // Find candidate thresholds
      const vals = X.map(x => x[f]);
      const uniqueVals = Array.from(new Set(vals)).sort((a, b) => a - b);
      
      const step = Math.max(1, Math.floor(uniqueVals.length / 10));
      for (let k = 0; k < uniqueVals.length - 1; k += step) {
        const threshold = (uniqueVals[k] + uniqueVals[k + 1]) / 2;
        const leftIdx: number[] = [];
        const rightIdx: number[] = [];

        for (let i = 0; i < nSamples; i++) {
          if (X[i][f] <= threshold) leftIdx.push(i);
          else rightIdx.push(i);
        }

        if (leftIdx.length === 0 || rightIdx.length === 0) continue;

        const leftY = leftIdx.map(i => y[i]);
        const rightY = rightIdx.map(i => y[i]);
        const gain = currentGini - (leftIdx.length / nSamples) * this.gini(leftY) - (rightIdx.length / nSamples) * this.gini(rightY);

        if (gain > bestGain) {
          bestGain = gain;
          bestFeature = f;
          bestThreshold = threshold;
          bestLeftIndices = leftIdx;
          bestRightIndices = rightIdx;
        }
      }
    }

    if (bestGain <= 0.001 || bestFeature === -1) {
      return {
        isLeaf: true,
        prediction: probSus >= 0.5 ? 'SUSPICIOUS' : 'NORMAL',
        probability: probSus >= 0.5 ? probSus : 1 - probSus,
        samples: nSamples,
      };
    }

    importances[bestFeature] += bestGain * nSamples;

    const leftX = bestLeftIndices.map(i => X[i]);
    const leftY = bestLeftIndices.map(i => y[i]);
    const rightX = bestRightIndices.map(i => X[i]);
    const rightY = bestRightIndices.map(i => y[i]);

    return {
      isLeaf: false,
      splitFeature: bestFeature,
      splitThreshold: bestThreshold,
      samples: nSamples,
      left: this.buildTree(leftX, leftY, depth + 1, importances),
      right: this.buildTree(rightX, rightY, depth + 1, importances),
    };
  }

  private extractRules(node: TreeNode | null, path: string = ''): string[] {
    if (!node) return [];
    if (node.isLeaf) {
      return [
        `${path || 'All flows'} => ${node.prediction} (Confidence: ${Math.round((node.probability || 0.5) * 100)}%, Samples: ${node.samples})`,
      ];
    }
    const featName = FEATURE_NAMES[node.splitFeature!];
    const thresh = node.splitThreshold!.toFixed(3);
    const leftRules = this.extractRules(node.left || null, path ? `${path} AND ${featName} <= ${thresh}` : `IF ${featName} <= ${thresh}`);
    const rightRules = this.extractRules(node.right || null, path ? `${path} AND ${featName} > ${thresh}` : `IF ${featName} > ${thresh}`);
    return [...leftRules, ...rightRules].slice(0, 8); // Top 8 clear rules
  }

  predict(features: number[]): { label: TrafficLabel; confidence: number } {
    let curr = this.root;
    while (curr && !curr.isLeaf) {
      if (features[curr.splitFeature!] <= curr.splitThreshold!) {
        curr = curr.left || null;
      } else {
        curr = curr.right || null;
      }
    }
    const label = curr?.prediction || 'NORMAL';
    const confidence = curr?.probability || 0.85;
    return { label, confidence };
  }
}

// -------------------------------------------------------------
// 3. Random Forest Classifier Implementation
// -------------------------------------------------------------
export class RandomForestClassifier {
  trees: DecisionTreeClassifier[] = [];
  nEstimators: number = 12;
  featureImportances: { feature: string; importance: number }[] = [];

  train(trainData: CleanedFlowRecord[], seed: number = 42): void {
    this.trees = [];
    const n = trainData.length;
    const accumulatedImportances = new Array(8).fill(0);

    if (n === 0) {
      this.featureImportances = FEATURE_NAMES.map(name => ({ feature: name, importance: 0 }));
      return;
    }

    const rand = createSeededRandom(seed + 101);

    for (let t = 0; t < this.nEstimators; t++) {
      // Bootstrap sample with replacement
      const bootstrapSample: CleanedFlowRecord[] = [];
      for (let i = 0; i < n; i++) {
        const randIdx = Math.floor(rand() * n);
        bootstrapSample.push(trainData[randIdx]);
      }

      const tree = new DecisionTreeClassifier();
      tree.maxDepth = 5;
      tree.minSamplesSplit = 4;
      tree.train(bootstrapSample);
      this.trees.push(tree);

      // Accumulate importances strictly by matching feature name (tree.featureImportances is sorted)
      tree.featureImportances.forEach((fi) => {
        const featIdx = FEATURE_NAMES.indexOf(fi.feature);
        if (featIdx !== -1) {
          accumulatedImportances[featIdx] += fi.importance;
        }
      });
    }

    const total = accumulatedImportances.reduce((a, b) => a + b, 0) || 1;
    this.featureImportances = FEATURE_NAMES.map((name, i) => ({
      feature: name,
      importance: parseFloat((accumulatedImportances[i] / total).toFixed(4)),
    })).sort((a, b) => b.importance - a.importance);
  }

  predict(features: number[]): { label: TrafficLabel; confidence: number } {
    if (this.trees.length === 0) {
      return { label: 'NORMAL', confidence: 0.5 };
    }

    let susVotes = 0;

    for (const tree of this.trees) {
      const res = tree.predict(features);
      if (res.label === 'SUSPICIOUS') {
        susVotes++;
      }
    }

    const probSus = susVotes / this.trees.length;
    const label: TrafficLabel = probSus >= 0.5 ? 'SUSPICIOUS' : 'NORMAL';
    const confidence = label === 'SUSPICIOUS' ? Math.max(0.65, probSus) : Math.max(0.65, 1 - probSus);
    return { label, confidence: parseFloat(confidence.toFixed(4)) };
  }
}

// -------------------------------------------------------------
// 4. Isolation Forest (Unsupervised Anomaly Detection)
// -------------------------------------------------------------
interface IsolationTreeNode {
  isLeaf: boolean;
  size: number;
  splitFeature?: number;
  splitValue?: number;
  left?: IsolationTreeNode;
  right?: IsolationTreeNode;
}

export class IsolationForestModel {
  trees: IsolationTreeNode[] = [];
  nTrees: number = 15;
  subsampleSize: number = 64;
  maxTreeHeight: number = 6;

  train(trainData: CleanedFlowRecord[], seed: number = 42): void {
    this.trees = [];
    const X = trainData.map(r => r.features);
    const n = X.length;
    if (n === 0) return;

    const rand = createSeededRandom(seed + 202);

    for (let t = 0; t < this.nTrees; t++) {
      // Subsample without replacement
      const sampleSize = Math.min(n, this.subsampleSize);
      const sampledX: number[][] = [];
      const used = new Set<number>();
      while (sampledX.length < sampleSize) {
        const idx = Math.floor(rand() * n);
        if (!used.has(idx)) {
          used.add(idx);
          sampledX.push(X[idx]);
        }
      }
      this.trees.push(this.buildITree(sampledX, 0, rand));
    }
  }

  private buildITree(X: number[][], currentHeight: number, rand: () => number): IsolationTreeNode {
    if (currentHeight >= this.maxTreeHeight || X.length <= 1 || !X[0]) {
      return { isLeaf: true, size: X.length };
    }

    // Pick random feature
    const nFeatures = X[0].length;
    const q = Math.floor(rand() * nFeatures);

    const values = X.map(x => x[q]);
    const min = Math.min(...values);
    const max = Math.max(...values);

    if (min === max) {
      return { isLeaf: true, size: X.length };
    }

    // Pick uniform random split between min and max
    const p = min + rand() * (max - min);

    const leftX = X.filter(x => x[q] < p);
    const rightX = X.filter(x => x[q] >= p);

    return {
      isLeaf: false,
      size: X.length,
      splitFeature: q,
      splitValue: p,
      left: this.buildITree(leftX, currentHeight + 1, rand),
      right: this.buildITree(rightX, currentHeight + 1, rand),
    };
  }

  private pathLength(x: number[], node: IsolationTreeNode, currentLength: number): number {
    if (node.isLeaf) {
      return currentLength + this.c(node.size);
    }
    if (x[node.splitFeature!] < node.splitValue!) {
      return this.pathLength(x, node.left || { isLeaf: true, size: 1 }, currentLength + 1);
    } else {
      return this.pathLength(x, node.right || { isLeaf: true, size: 1 }, currentLength + 1);
    }
  }

  private c(n: number): number {
    if (n <= 1) return 0;
    if (n === 2) return 1;
    // Euler-Mascheroni constant ≈ 0.5772156649
    return 2 * (Math.log(n - 1) + 0.5772156649) - (2 * (n - 1) / n);
  }

  anomalyScore(features: number[]): number {
    if (this.trees.length === 0) return 0.5;
    let totalPath = 0;
    for (const tree of this.trees) {
      totalPath += this.pathLength(features, tree, 0);
    }
    const avgPath = totalPath / this.trees.length;
    const cN = this.c(this.subsampleSize);
    if (cN === 0) return 0.5;
    const score = Math.pow(2, -(avgPath / cN));
    return parseFloat(score.toFixed(4));
  }

  predict(features: number[]): { label: TrafficLabel; confidence: number; anomalyScore: number } {
    const score = this.anomalyScore(features);
    // Unsupervised anomaly threshold typically ~0.55-0.60
    const isAnomaly = score >= 0.58;
    const label: TrafficLabel = isAnomaly ? 'SUSPICIOUS' : 'NORMAL';
    return {
      label,
      confidence: isAnomaly ? score : parseFloat((1 - score).toFixed(4)),
      anomalyScore: score,
    };
  }
}

// -------------------------------------------------------------
// Model Evaluation Metrics Calculator
// -------------------------------------------------------------
export function calculateModelMetrics(
  algorithm: ModelAlgorithm,
  algorithmName: string,
  modelType: 'supervised' | 'unsupervised',
  testRecords: CleanedFlowRecord[],
  predictor: (features: number[]) => { label: TrafficLabel; confidence: number },
  startTimeMs: number,
  featureImportances?: { feature: string; importance: number }[],
  treeRulesSummary?: string[]
): ModelMetrics {
  let tp = 0; // True Positive: Actual Suspicious, Predicted Suspicious
  let tn = 0; // True Negative: Actual Normal, Predicted Normal
  let fp = 0; // False Positive: Actual Normal, Predicted Suspicious
  let fn = 0; // False Negative: Actual Suspicious, Predicted Normal

  testRecords.forEach(record => {
    const pred = predictor(record.features);
    const actual = record.label;

    if (actual === 'SUSPICIOUS' && pred.label === 'SUSPICIOUS') tp++;
    else if (actual === 'NORMAL' && pred.label === 'NORMAL') tn++;
    else if (actual === 'NORMAL' && pred.label === 'SUSPICIOUS') fp++;
    else if (actual === 'SUSPICIOUS' && pred.label === 'NORMAL') fn++;
  });

  const total = testRecords.length || 1;
  const accuracy = (tp + tn) / total;
  const precision = (tp + fp) > 0 ? tp / (tp + fp) : 0;
  const recall = (tp + fn) > 0 ? tp / (tp + fn) : 0;
  const f1Score = (precision + recall) > 0 ? (2 * precision * recall) / (precision + recall) : 0;
  const falsePositiveRate = (fp + tn) > 0 ? fp / (fp + tn) : 0;
  const falseNegativeRate = (fn + tp) > 0 ? fn / (fn + tp) : 0;
  const trainingTimeMs = Math.round(performance.now() - startTimeMs);

  return {
    algorithm,
    algorithmName,
    modelType,
    accuracy: parseFloat(accuracy.toFixed(4)),
    precision: parseFloat(precision.toFixed(4)),
    recall: parseFloat(recall.toFixed(4)),
    f1Score: parseFloat(f1Score.toFixed(4)),
    falsePositiveRate: parseFloat(falsePositiveRate.toFixed(4)),
    falseNegativeRate: parseFloat(falseNegativeRate.toFixed(4)),
    trainingTimeMs,
    confusionMatrix: {
      truePositives: tp,
      trueNegatives: tn,
      falsePositives: fp,
      falseNegatives: fn,
    },
    featureImportances,
    treeRulesSummary,
  };
}

// -------------------------------------------------------------
// Severity Calculation Rules (Explainable Cyber Prioritization)
// -------------------------------------------------------------
export function determineSeverity(
  flow: CleanedFlowRecord,
  predCategory: AttackCategory,
  confidence: number
): { severity: SeverityLevel; reason: string } {
  // CRITICAL: High-volume DoS attacks or direct Brute Force on root ports
  if (predCategory === 'DoS / DDoS' || flow.flowRate > 500000 || flow.packetCount > 500) {
    return {
      severity: 'CRITICAL',
      reason: `Massive traffic volume: ${flow.packetCount} packets with flow rate ${(flow.flowRate / 1024).toFixed(1)} KB/s indicating active service disruption attempt.`,
    };
  }

  if (predCategory === 'Botnet / C2' || flow.destinationPort === 4444) {
    return {
      severity: 'CRITICAL',
      reason: `Potential Command & Control communication detected on port ${flow.destinationPort} from internal asset ${flow.sourceIp}.`,
    };
  }

  // HIGH: Brute Force on SSH (22) / RDP (3389) or SQLi probe
  if (predCategory === 'Brute Force' || [22, 3389, 445].includes(flow.destinationPort)) {
    return {
      severity: 'HIGH',
      reason: `Credential attack targeting administrative service on port ${flow.destinationPort} (${flow.destinationPort === 22 ? 'SSH' : flow.destinationPort === 3389 ? 'RDP' : 'SMB'}).`,
    };
  }

  if (predCategory === 'Web Attack' || (flow.byteCount > 10000 && [80, 443, 8080].includes(flow.destinationPort))) {
    return {
      severity: 'HIGH',
      reason: `Abnormal HTTP payload size (${(flow.byteCount / 1024).toFixed(1)} KB) on port ${flow.destinationPort} indicative of web vulnerability exploitation.`,
    };
  }

  // MEDIUM: Port Scanning
  if (predCategory === 'Port Scan' || (flow.packetCount <= 3 && flow.flowDuration < 0.05)) {
    return {
      severity: 'MEDIUM',
      reason: `Rapid single-packet connection probe targeting port ${flow.destinationPort}, consistent with host/port enumeration reconnaissance.`,
    };
  }

  // Default prioritization
  if (confidence > 0.8) {
    return {
      severity: 'MEDIUM',
      reason: `High ML model confidence (${Math.round(confidence * 100)}%) detecting anomalous traffic signature.`,
    };
  }

  return {
    severity: 'LOW',
    reason: `Minor flow deviation from normal baseline (Confidence: ${Math.round(confidence * 100)}%).`,
  };
}

// -------------------------------------------------------------
// Complete Detection Suite Runner
// -------------------------------------------------------------
export interface TrainedModels {
  logisticRegression: LogisticRegressionModel;
  decisionTree: DecisionTreeClassifier;
  randomForest: RandomForestClassifier;
  isolationForest: IsolationForestModel;
  metrics: Record<ModelAlgorithm, ModelMetrics>;
  activeAlgorithm: ModelAlgorithm;
}

export function trainAllModels(
  trainRecords: CleanedFlowRecord[],
  testRecords: CleanedFlowRecord[]
): TrainedModels {
  // 1. Logistic Regression
  let t0 = performance.now();
  const lr = new LogisticRegressionModel();
  lr.train(trainRecords);
  const lrMetrics = calculateModelMetrics(
    'logistic_regression',
    'Logistic Regression',
    'supervised',
    testRecords,
    f => lr.predict(f),
    t0
  );

  // 2. Decision Tree
  t0 = performance.now();
  const dt = new DecisionTreeClassifier();
  dt.train(trainRecords);
  const dtMetrics = calculateModelMetrics(
    'decision_tree',
    'Decision Tree',
    'supervised',
    testRecords,
    f => dt.predict(f),
    t0,
    dt.featureImportances,
    dt.rulesSummary
  );

  // 3. Random Forest
  t0 = performance.now();
  const rf = new RandomForestClassifier();
  rf.train(trainRecords);
  const rfMetrics = calculateModelMetrics(
    'random_forest',
    'Random Forest (Ensemble)',
    'supervised',
    testRecords,
    f => rf.predict(f),
    t0,
    rf.featureImportances
  );

  // 4. Isolation Forest (Unsupervised)
  t0 = performance.now();
  const iforest = new IsolationForestModel();
  iforest.train(trainRecords);
  const ifMetrics = calculateModelMetrics(
    'isolation_forest',
    'Isolation Forest (Anomaly)',
    'unsupervised',
    testRecords,
    f => iforest.predict(f),
    t0
  );

  const metrics: Record<ModelAlgorithm, ModelMetrics> = {
    logistic_regression: lrMetrics,
    decision_tree: dtMetrics,
    random_forest: rfMetrics,
    isolation_forest: ifMetrics,
  };

  // Default to best model based on F1-score
  let activeAlgorithm: ModelAlgorithm = 'random_forest';
  if (rfMetrics.f1Score >= dtMetrics.f1Score && rfMetrics.f1Score >= lrMetrics.f1Score) {
    activeAlgorithm = 'random_forest';
  } else if (dtMetrics.f1Score >= lrMetrics.f1Score) {
    activeAlgorithm = 'decision_tree';
  } else {
    activeAlgorithm = 'logistic_regression';
  }

  return {
    logisticRegression: lr,
    decisionTree: dt,
    randomForest: rf,
    isolationForest: iforest,
    metrics,
    activeAlgorithm,
  };
}

/**
 * Run intrusion detection inference on a set of cleaned flows
 */
export function runInference(
  flows: CleanedFlowRecord[],
  models: TrainedModels,
  algorithm: ModelAlgorithm
): DetectionPrediction[] {
  return flows.map(flow => {
    let predLabel: TrafficLabel = 'NORMAL';
    let confidence = 0.5;
    let anomalyScore: number | undefined = undefined;
    let modelName = 'Random Forest';

    if (algorithm === 'logistic_regression') {
      modelName = 'Logistic Regression';
      const res = models.logisticRegression.predict(flow.features);
      predLabel = res.label;
      confidence = res.confidence;
    } else if (algorithm === 'decision_tree') {
      modelName = 'Decision Tree';
      const res = models.decisionTree.predict(flow.features);
      predLabel = res.label;
      confidence = res.confidence;
    } else if (algorithm === 'random_forest') {
      modelName = 'Random Forest';
      const res = models.randomForest.predict(flow.features);
      predLabel = res.label;
      confidence = res.confidence;
    } else if (algorithm === 'isolation_forest') {
      modelName = 'Isolation Forest';
      const res = models.isolationForest.predict(flow.features);
      predLabel = res.label;
      confidence = res.confidence;
      anomalyScore = res.anomalyScore;
    }

    // Determine category
    const category: AttackCategory = predLabel === 'NORMAL' 
      ? 'Normal' 
      : (flow.attackCategory && flow.attackCategory !== 'Normal' ? flow.attackCategory : 'Unknown Anomaly');

    const { severity, reason } = determineSeverity(flow, category, confidence);

    return {
      flowId: flow.id,
      predictedLabel: predLabel,
      predictedCategory: category,
      confidence,
      anomalyScore,
      modelUsed: algorithm,
      modelName,
      severity,
      severityReason: reason,
      detectionTimestamp: new Date().toISOString().replace('T', ' ').substring(0, 19),
    };
  });
}
