import React, { useState } from 'react';
import { CleanedFlowRecord, DetectionPrediction, ModelAlgorithm, TrainedModels } from '../../types';
import { Bot, Play, CheckCircle2, AlertTriangle, ArrowRight, Filter } from 'lucide-react';

interface IntrusionDetectionViewProps {
  cleanedFlows: CleanedFlowRecord[];
  models?: TrainedModels;
  predictions: DetectionPrediction[];
  onTrainModels: () => void;
  onRunInference: (algorithm: ModelAlgorithm) => void;
  onNavigateToTab: (tab: any) => void;
  onSelectAlert?: (alertId: string) => void;
}

export const IntrusionDetectionView: React.FC<IntrusionDetectionViewProps> = ({
  cleanedFlows,
  models,
  predictions,
  onTrainModels,
  onRunInference,
  onNavigateToTab,
}) => {
  const [selectedAlgo, setSelectedAlgo] = useState<ModelAlgorithm>('random_forest');
  const [filterClass, setFilterClass] = useState<'ALL' | 'NORMAL' | 'SUSPICIOUS'>('ALL');
  const [searchIP, setSearchIP] = useState('');
  const [isTraining, setIsTraining] = useState(false);
  const [isDetecting, setIsDetecting] = useState(false);

  const handleTrain = () => {
    setIsTraining(true);
    setTimeout(() => {
      onTrainModels();
      setIsTraining(false);
    }, 400);
  };

  const handleDetect = () => {
    setIsDetecting(true);
    setTimeout(() => {
      onRunInference(selectedAlgo);
      setIsDetecting(false);
    }, 300);
  };

  const flowMap = new Map(cleanedFlows.map(f => [f.id, f]));

  const filteredPredictions = predictions.filter(p => {
    if (filterClass !== 'ALL' && p.predictedLabel !== filterClass) return false;
    const flow = flowMap.get(p.flowId);
    if (searchIP && flow) {
      return flow.sourceIp.includes(searchIP) || flow.destinationIp.includes(searchIP);
    }
    return true;
  });

  const susCount = predictions.filter(p => p.predictedLabel === 'SUSPICIOUS').length;
  const normalCount = predictions.filter(p => p.predictedLabel === 'NORMAL').length;

  if (cleanedFlows.length === 0) {
    return (
      <div className="p-10 rounded-lg bg-slate-900/90 border border-slate-800 text-center space-y-3">
        <p className="text-sm text-slate-200 font-semibold">No Preprocessed Traffic Flows Available</p>
        <p className="text-xs text-slate-400">Load a dataset in Traffic Data Management first to train models and classify network flows.</p>
        <button
          type="button"
          onClick={() => onNavigateToTab('data_management')}
          className="px-4 py-2 bg-cyan-500 hover:bg-cyan-400 text-slate-950 rounded text-xs font-semibold transition-colors cursor-pointer"
        >
          Open Traffic Data Management
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
            <span>AI-Based Intrusion Detection Engine</span>
          </h1>
          <p className="text-xs text-slate-400 mt-0.5">
            Train supervised and unsupervised machine learning algorithms, run real-time inference, and assign severity.
          </p>
        </div>

        {predictions.length > 0 && (
          <button
            onClick={() => onNavigateToTab('alerts')}
            className="px-3.5 py-1.5 bg-cyan-500 hover:bg-cyan-400 text-slate-950 rounded text-xs font-semibold transition-colors flex items-center gap-1.5 self-start sm:self-auto"
          >
            <span>Triage Alerts ({susCount})</span>
            <ArrowRight className="w-3.5 h-3.5" />
          </button>
        )}
      </div>

      {/* Control Strip & Model Selection */}
      <div className="grid grid-cols-1 lg:grid-cols-4 gap-4">
        {/* Model 1: Random Forest */}
        <div
          onClick={() => setSelectedAlgo('random_forest')}
          className={`p-4 rounded-lg border cursor-pointer transition-all ${
            selectedAlgo === 'random_forest'
              ? 'bg-slate-900 border-cyan-500 ring-1 ring-cyan-500/30'
              : 'bg-slate-950/70 border-slate-800 hover:border-slate-700'
          }`}
        >
          <div className="flex items-center justify-between text-xs mb-1">
            <span className="font-bold text-slate-200">Random Forest</span>
            <span className="text-[10px] uppercase font-mono px-1.5 py-0.2 rounded bg-cyan-950 text-cyan-400 border border-cyan-800">
              Ensemble
            </span>
          </div>
          <p className="text-[11px] text-slate-400 leading-snug">
            12 randomized decision trees with bagging. Optimal for complex, non-linear flow patterns.
          </p>
          <div className="text-[10px] text-cyan-400 font-mono mt-2">
            {models ? `Accuracy: ${(models.metrics.random_forest.accuracy * 100).toFixed(1)}%` : 'Ready to train'}
          </div>
        </div>

        {/* Model 2: Decision Tree */}
        <div
          onClick={() => setSelectedAlgo('decision_tree')}
          className={`p-4 rounded-lg border cursor-pointer transition-all ${
            selectedAlgo === 'decision_tree'
              ? 'bg-slate-900 border-cyan-500 ring-1 ring-cyan-500/30'
              : 'bg-slate-950/70 border-slate-800 hover:border-slate-700'
          }`}
        >
          <div className="flex items-center justify-between text-xs mb-1">
            <span className="font-bold text-slate-200">Decision Tree</span>
            <span className="text-[10px] uppercase font-mono px-1.5 py-0.2 rounded bg-blue-950 text-blue-400 border border-blue-800">
              Explainable
            </span>
          </div>
          <p className="text-[11px] text-slate-400 leading-snug">
            Single transparent tree. Generates human-readable IF-THEN rules for analyst auditing.
          </p>
          <div className="text-[10px] text-blue-400 font-mono mt-2">
            {models ? `Accuracy: ${(models.metrics.decision_tree.accuracy * 100).toFixed(1)}%` : 'Ready to train'}
          </div>
        </div>

        {/* Model 3: Logistic Regression */}
        <div
          onClick={() => setSelectedAlgo('logistic_regression')}
          className={`p-4 rounded-lg border cursor-pointer transition-all ${
            selectedAlgo === 'logistic_regression'
              ? 'bg-slate-900 border-cyan-500 ring-1 ring-cyan-500/30'
              : 'bg-slate-950/70 border-slate-800 hover:border-slate-700'
          }`}
        >
          <div className="flex items-center justify-between text-xs mb-1">
            <span className="font-bold text-slate-200">Logistic Regression</span>
            <span className="text-[10px] uppercase font-mono px-1.5 py-0.2 rounded bg-slate-800 text-slate-400">
              Baseline
            </span>
          </div>
          <p className="text-[11px] text-slate-400 leading-snug">
            Linear classifier benchmark with logistic sigmoid and L2 gradient descent optimization.
          </p>
          <div className="text-[10px] text-slate-300 font-mono mt-2">
            {models ? `Accuracy: ${(models.metrics.logistic_regression.accuracy * 100).toFixed(1)}%` : 'Ready to train'}
          </div>
        </div>

        {/* Model 4: Isolation Forest */}
        <div
          onClick={() => setSelectedAlgo('isolation_forest')}
          className={`p-4 rounded-lg border cursor-pointer transition-all ${
            selectedAlgo === 'isolation_forest'
              ? 'bg-slate-900 border-cyan-500 ring-1 ring-cyan-500/30'
              : 'bg-slate-950/70 border-slate-800 hover:border-slate-700'
          }`}
        >
          <div className="flex items-center justify-between text-xs mb-1">
            <span className="font-bold text-slate-200">Isolation Forest</span>
            <span className="text-[10px] uppercase font-mono px-1.5 py-0.2 rounded bg-purple-950 text-purple-400 border border-purple-800">
              Unsupervised
            </span>
          </div>
          <p className="text-[11px] text-slate-400 leading-snug">
            Calculates anomaly path lengths in random partitions. Operates without prior attack labels.
          </p>
          <div className="text-[10px] text-purple-400 font-mono mt-2">
            {models ? `Anomaly Acc: ${(models.metrics.isolation_forest.accuracy * 100).toFixed(1)}%` : 'Ready to train'}
          </div>
        </div>
      </div>

      {/* Action Strip */}
      <div className="flex flex-wrap items-center justify-between gap-4 p-4 rounded-lg bg-slate-900/90 border border-slate-800">
        <div className="flex items-center gap-3">
          <button
            onClick={handleTrain}
            disabled={isTraining}
            className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-100 rounded text-xs font-semibold transition-colors flex items-center gap-1.5 border border-slate-700"
          >
            <Bot className="w-4 h-4 text-cyan-400" />
            <span>{isTraining ? 'Training Models...' : 'Train All 4 Models'}</span>
          </button>

          <button
            onClick={handleDetect}
            disabled={!models || isDetecting}
            className="px-4 py-2 bg-cyan-500 hover:bg-cyan-400 disabled:opacity-50 text-slate-950 rounded text-xs font-semibold transition-colors flex items-center gap-1.5"
          >
            <Play className="w-4 h-4" />
            <span>{isDetecting ? 'Running Classification...' : `Run Inference (${selectedAlgo.replace('_', ' ')})`}</span>
          </button>
        </div>

        <div className="flex items-center gap-4 text-xs font-mono">
          <span className="text-slate-400">Classified:</span>
          <span className="text-emerald-400 font-bold">{normalCount} Normal</span>
          <span className="text-slate-600">·</span>
          <span className="text-red-400 font-bold">{susCount} Suspicious</span>
        </div>
      </div>

      {/* Detection Results Table */}
      <div className="p-5 rounded-lg bg-slate-900/90 border border-slate-800">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 mb-4">
          <div>
            <h3 className="text-sm font-bold text-slate-100">
              Flow Classification & Threat Prioritization Results
            </h3>
            <p className="text-xs text-slate-400">
              Showing {filteredPredictions.length} predictions using {selectedAlgo.replace('_', ' ')}
            </p>
          </div>

          <div className="flex items-center gap-2">
            <div className="flex items-center bg-slate-950 p-1 rounded border border-slate-800 text-xs">
              <button
                onClick={() => setFilterClass('ALL')}
                className={`px-2.5 py-1 rounded text-xs font-medium ${
                  filterClass === 'ALL' ? 'bg-slate-800 text-cyan-300' : 'text-slate-400'
                }`}
              >
                All
              </button>
              <button
                onClick={() => setFilterClass('SUSPICIOUS')}
                className={`px-2.5 py-1 rounded text-xs font-medium ${
                  filterClass === 'SUSPICIOUS' ? 'bg-red-950/60 text-red-400 border border-red-500/30' : 'text-slate-400 hover:text-red-400'
                }`}
              >
                Suspicious ({susCount})
              </button>
              <button
                onClick={() => setFilterClass('NORMAL')}
                className={`px-2.5 py-1 rounded text-xs font-medium ${
                  filterClass === 'NORMAL' ? 'bg-emerald-950/60 text-emerald-400 border border-emerald-500/30' : 'text-slate-400 hover:text-emerald-400'
                }`}
              >
                Normal
              </button>
            </div>

            <input
              type="text"
              placeholder="Filter IP address..."
              value={searchIP}
              onChange={(e) => setSearchIP(e.target.value)}
              className="px-3 py-1.5 bg-slate-950 border border-slate-800 rounded text-xs text-slate-200 placeholder:text-slate-600 focus:outline-none focus:border-cyan-500 font-mono"
            />
          </div>
        </div>

        <div className="overflow-x-auto max-h-[460px] overflow-y-auto">
          <table className="w-full text-left text-xs border-collapse">
            <thead className="sticky top-0 bg-slate-950 z-10">
              <tr className="border-b border-slate-800 text-slate-400 uppercase font-mono text-[10px] tracking-wider">
                <th className="py-2.5 px-3">Flow ID</th>
                <th className="py-2.5 px-3">Timestamp</th>
                <th className="py-2.5 px-3">Source IP</th>
                <th className="py-2.5 px-3">Target IP:Port</th>
                <th className="py-2.5 px-3">Protocol</th>
                <th className="py-2.5 px-3">Prediction</th>
                <th className="py-2.5 px-3">Confidence</th>
                <th className="py-2.5 px-3">Severity</th>
                <th className="py-2.5 px-3">Detection Rationale</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-850 font-mono">
              {filteredPredictions.map((pred) => {
                const flow = flowMap.get(pred.flowId);
                if (!flow) return null;

                let sevBadge = 'text-red-400 bg-red-950/40 border-red-500/30';
                if (pred.severity === 'HIGH') sevBadge = 'text-orange-400 bg-orange-950/40 border-orange-500/30';
                else if (pred.severity === 'MEDIUM') sevBadge = 'text-amber-400 bg-amber-950/40 border-amber-500/30';
                else if (pred.severity === 'LOW') sevBadge = 'text-emerald-400 bg-emerald-950/40 border-emerald-500/30';

                return (
                  <tr key={pred.flowId} className="hover:bg-slate-850/40 transition-colors">
                    <td className="py-2.5 px-3 text-slate-400 font-bold">{pred.flowId}</td>
                    <td className="py-2.5 px-3 text-slate-400">{flow.timestamp}</td>
                    <td className="py-2.5 px-3 text-slate-200">{flow.sourceIp}</td>
                    <td className="py-2.5 px-3 text-slate-300">
                      {flow.destinationIp}:{flow.destinationPort}
                    </td>
                    <td className="py-2.5 px-3 text-cyan-400">{flow.protocol}</td>
                    <td className="py-2.5 px-3 font-sans">
                      <span
                        className={`inline-block px-2 py-0.5 rounded text-[10px] font-bold border ${
                          pred.predictedLabel === 'SUSPICIOUS'
                            ? 'bg-red-950/50 text-red-400 border-red-500/30'
                            : 'bg-emerald-950/50 text-emerald-400 border-emerald-500/30'
                        }`}
                      >
                        {pred.predictedLabel}
                      </span>
                    </td>
                    <td className="py-2.5 px-3 text-slate-200">
                      {(pred.confidence * 100).toFixed(1)}%
                    </td>
                    <td className="py-2.5 px-3">
                      <span className={`inline-block px-1.5 py-0.5 rounded text-[10px] font-bold border ${sevBadge}`}>
                        {pred.severity}
                      </span>
                    </td>
                    <td className="py-2.5 px-3 font-sans text-slate-400 max-w-xs truncate" title={pred.severityReason}>
                      {pred.severityReason}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
