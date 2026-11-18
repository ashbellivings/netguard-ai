import React, { useState } from 'react';
import { ModelMetrics, ModelAlgorithm } from '../../types';
import { Scale, CheckCircle2, AlertTriangle, HelpCircle, ArrowRight } from 'lucide-react';

interface ModelEvaluationViewProps {
  metricsRecord?: Record<ModelAlgorithm, ModelMetrics>;
  onNavigateToTab: (tab: any) => void;
}

export const ModelEvaluationView: React.FC<ModelEvaluationViewProps> = ({
  metricsRecord,
  onNavigateToTab,
}) => {
  const [selectedAlgo, setSelectedAlgo] = useState<ModelAlgorithm>('random_forest');

  if (!metricsRecord) {
    return (
      <div className="p-8 text-center text-slate-400">
        No models trained yet. Please visit the "AI Intrusion Detection" tab and click "Train All 4 Models".
      </div>
    );
  }

  const selectedMetrics = metricsRecord[selectedAlgo] || metricsRecord.random_forest;
  const cm = selectedMetrics.confusionMatrix;

  return (
    <div className="space-y-6">
      {/* Title */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-2 border-b border-slate-850">
        <div>
          <h1 className="text-xl font-bold tracking-tight text-slate-100 flex items-center gap-2">
            <span>Model Performance Evaluation</span>
          </h1>
          <p className="text-xs text-slate-400 mt-0.5">
            Hold-out test set verification, confusion matrix diagnostics, and supervised classification benchmarks.
          </p>
        </div>

        <button
          onClick={() => onNavigateToTab('alerts')}
          className="px-3.5 py-1.5 bg-cyan-500 hover:bg-cyan-400 text-slate-950 rounded text-xs font-semibold transition-colors flex items-center gap-1.5 self-start sm:self-auto"
        >
          <span>Investigate Triggered Alerts</span>
          <ArrowRight className="w-3.5 h-3.5" />
        </button>
      </div>

      {/* Model Comparison Table */}
      <div className="p-5 rounded-lg bg-slate-900/90 border border-slate-800">
        <h3 className="text-sm font-bold text-slate-100 mb-3">
          Cross-Model Performance Benchmark Matrix
        </h3>
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs border-collapse">
            <thead>
              <tr className="border-b border-slate-800 text-slate-400 uppercase font-mono text-[10px] tracking-wider">
                <th className="py-2.5 px-3">Algorithm</th>
                <th className="py-2.5 px-3">Type</th>
                <th className="py-2.5 px-3">Accuracy</th>
                <th className="py-2.5 px-3">Precision</th>
                <th className="py-2.5 px-3">Recall</th>
                <th className="py-2.5 px-3">F1-Score</th>
                <th className="py-2.5 px-3">False Positive Rate</th>
                <th className="py-2.5 px-3">False Negative Rate</th>
                <th className="py-2.5 px-3 text-right">Inspect</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-850 font-mono">
              {(Object.keys(metricsRecord) as ModelAlgorithm[]).map((algoKey) => {
                const m = metricsRecord[algoKey];
                const isSelected = selectedAlgo === algoKey;
                return (
                  <tr
                    key={algoKey}
                    onClick={() => setSelectedAlgo(algoKey)}
                    className={`cursor-pointer transition-colors ${
                      isSelected ? 'bg-cyan-950/20 text-cyan-200' : 'hover:bg-slate-850/40 text-slate-300'
                    }`}
                  >
                    <td className="py-2.5 px-3 font-bold font-sans flex items-center gap-2">
                      <span className={`w-2 h-2 rounded-full ${isSelected ? 'bg-cyan-400' : 'bg-slate-600'}`} />
                      <span>{m.algorithmName}</span>
                    </td>
                    <td className="py-2.5 px-3 uppercase text-[10px] text-slate-500">{m.modelType}</td>
                    <td className="py-2.5 px-3 text-cyan-400 font-bold">{(m.accuracy * 100).toFixed(1)}%</td>
                    <td className="py-2.5 px-3">{(m.precision * 100).toFixed(1)}%</td>
                    <td className="py-2.5 px-3">{(m.recall * 100).toFixed(1)}%</td>
                    <td className="py-2.5 px-3 text-emerald-400 font-bold">{(m.f1Score * 100).toFixed(1)}%</td>
                    <td className="py-2.5 px-3 text-amber-400">{(m.falsePositiveRate * 100).toFixed(1)}%</td>
                    <td className="py-2.5 px-3 text-red-400">{(m.falseNegativeRate * 100).toFixed(1)}%</td>
                    <td className="py-2.5 px-3 text-right">
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          setSelectedAlgo(algoKey);
                        }}
                        className="px-2 py-1 rounded bg-slate-800 text-[11px] font-sans hover:bg-slate-700"
                      >
                        Inspect
                      </button>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>

      {/* Selected Model Deep Dive & Confusion Matrix */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
        {/* Confusion Matrix Visualizer */}
        <div className="p-5 rounded-lg bg-slate-900/90 border border-slate-800">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h3 className="text-sm font-bold text-slate-100">
                Confusion Matrix: {selectedMetrics.algorithmName}
              </h3>
              <p className="text-xs text-slate-400">
                Ground Truth vs. Predicted Classifications on Hold-Out Test Split
              </p>
            </div>
            <span className="text-[10px] uppercase font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-400">
              Test Set
            </span>
          </div>

          <div className="grid grid-cols-2 gap-3 mb-4">
            {/* True Positive */}
            <div className="p-4 rounded-lg bg-emerald-950/30 border border-emerald-500/30">
              <div className="flex justify-between items-center text-xs text-emerald-400 font-semibold mb-1">
                <span>True Positive (TP)</span>
                <CheckCircle2 className="w-4 h-4 text-emerald-400" />
              </div>
              <div className="text-2xl font-bold font-mono text-emerald-300">
                {cm.truePositives}
              </div>
              <div className="text-[11px] text-slate-400 mt-1 leading-snug">
                Actual attacks successfully identified and flagged as SUSPICIOUS.
              </div>
            </div>

            {/* False Positive */}
            <div className="p-4 rounded-lg bg-amber-950/30 border border-amber-500/30">
              <div className="flex justify-between items-center text-xs text-amber-400 font-semibold mb-1">
                <span>False Positive (FP)</span>
                <AlertTriangle className="w-4 h-4 text-amber-400" />
              </div>
              <div className="text-2xl font-bold font-mono text-amber-300">
                {cm.falsePositives}
              </div>
              <div className="text-[11px] text-slate-400 mt-1 leading-snug">
                Benign traffic incorrectly flagged (analyst triage noise).
              </div>
            </div>

            {/* False Negative */}
            <div className="p-4 rounded-lg bg-red-950/30 border border-red-500/30">
              <div className="flex justify-between items-center text-xs text-red-400 font-semibold mb-1">
                <span>False Negative (FN)</span>
                <AlertTriangle className="w-4 h-4 text-red-400" />
              </div>
              <div className="text-2xl font-bold font-mono text-red-300">
                {cm.falseNegatives}
              </div>
              <div className="text-[11px] text-slate-400 mt-1 leading-snug">
                Actual malicious attacks missed by the model (critical security risk).
              </div>
            </div>

            {/* True Negative */}
            <div className="p-4 rounded-lg bg-slate-950/70 border border-slate-800">
              <div className="flex justify-between items-center text-xs text-slate-300 font-semibold mb-1">
                <span>True Negative (TN)</span>
                <CheckCircle2 className="w-4 h-4 text-slate-400" />
              </div>
              <div className="text-2xl font-bold font-mono text-slate-200">
                {cm.trueNegatives}
              </div>
              <div className="text-[11px] text-slate-400 mt-1 leading-snug">
                Normal traffic correctly recognized as NORMAL.
              </div>
            </div>
          </div>

          <div className="grid grid-cols-2 gap-3 text-xs pt-3 border-t border-slate-800/80">
            <div>
              <span className="text-slate-400">False Positive Rate (FPR): </span>
              <strong className="text-amber-400 font-mono">
                {(selectedMetrics.falsePositiveRate * 100).toFixed(2)}%
              </strong>
            </div>
            <div>
              <span className="text-slate-400">False Negative Rate (FNR): </span>
              <strong className="text-red-400 font-mono">
                {(selectedMetrics.falseNegativeRate * 100).toFixed(2)}%
              </strong>
            </div>
          </div>
        </div>

        {/* Explainability / Decision Rules / Feature Importances */}
        <div className="p-5 rounded-lg bg-slate-900/90 border border-slate-800 flex flex-col justify-between">
          <div>
            <h3 className="text-sm font-bold text-slate-100 mb-1">
              Model Interpretability & Feature Importances
            </h3>
            <p className="text-xs text-slate-400 mb-4">
              Relative contribution of network attributes towards intrusion classification decisions
            </p>

            {selectedMetrics.featureImportances && selectedMetrics.featureImportances.length > 0 ? (
              <div className="space-y-2.5">
                {selectedMetrics.featureImportances.slice(0, 5).map((fi) => (
                  <div key={fi.feature} className="text-xs space-y-1">
                    <div className="flex justify-between">
                      <span className="text-slate-300 font-medium">{fi.feature}</span>
                      <span className="font-mono text-cyan-400">
                        {(fi.importance * 100).toFixed(1)}%
                      </span>
                    </div>
                    <div className="w-full h-1.5 bg-slate-950 rounded-full overflow-hidden">
                      <div
                        className="h-full bg-cyan-500"
                        style={{ width: `${fi.importance * 100}%` }}
                      />
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <div className="text-xs text-slate-400 leading-relaxed space-y-2">
                <p>
                  Linear weights and intercept determine classification threshold in Logistic Regression.
                </p>
                <p>
                  Isolation Forest partitions feature space recursively without computing feature gain.
                </p>
              </div>
            )}

            {selectedMetrics.treeRulesSummary && selectedMetrics.treeRulesSummary.length > 0 && (
              <div className="mt-4 pt-3 border-t border-slate-800/80">
                <div className="text-xs font-semibold text-slate-300 mb-2">
                  Sample Decision Rules:
                </div>
                <div className="p-2.5 rounded bg-slate-950 font-mono text-[10px] text-cyan-300 space-y-1 max-h-24 overflow-y-auto border border-slate-850">
                  {selectedMetrics.treeRulesSummary.slice(0, 4).map((rule, idx) => (
                    <div key={idx} className="truncate" title={rule}>
                      {rule}
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>

          <div className="mt-4 pt-3 border-t border-slate-800/80 text-[11px] text-slate-400">
            Training Execution Latency: <span className="font-mono text-slate-300">{selectedMetrics.trainingTimeMs} ms</span>
          </div>
        </div>
      </div>

      {/* Academic Definitions Guide */}
      <div className="p-5 rounded-lg bg-slate-900/90 border border-slate-800">
        <h3 className="text-sm font-bold text-slate-100 flex items-center gap-2 mb-3">
          <HelpCircle className="w-4 h-4 text-cyan-400" />
          Academic Cybersecurity Evaluation Metric Definitions
        </h3>
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3.5 text-xs">
          <div className="p-3 rounded bg-slate-950/60 border border-slate-850">
            <strong className="text-cyan-400">Accuracy:</strong>
            <p className="text-slate-400 mt-1">
              Proportion of total network flows correctly predicted: (TP + TN) / (TP + TN + FP + FN).
            </p>
          </div>
          <div className="p-3 rounded bg-slate-950/60 border border-slate-850">
            <strong className="text-cyan-400">Precision:</strong>
            <p className="text-slate-400 mt-1">
              Of all flows flagged as attacks, what proportion were genuine threats: TP / (TP + FP). Minimizes alert fatigue.
            </p>
          </div>
          <div className="p-3 rounded bg-slate-950/60 border border-slate-850">
            <strong className="text-cyan-400">Recall (Sensitivity):</strong>
            <p className="text-slate-400 mt-1">
              Proportion of actual malicious attacks successfully caught: TP / (TP + FN). High recall ensures stealth attacks aren't missed.
            </p>
          </div>
          <div className="p-3 rounded bg-slate-950/60 border border-slate-850">
            <strong className="text-cyan-400">F1-Score:</strong>
            <p className="text-slate-400 mt-1">
              Harmonic mean of precision and recall: 2 * (P * R) / (P + R). The primary metric for imbalanced cybersecurity datasets.
            </p>
          </div>
          <div className="p-3 rounded bg-slate-950/60 border border-slate-850">
            <strong className="text-cyan-400">False Positive Rate (FPR):</strong>
            <p className="text-slate-400 mt-1">
              Ratio of benign traffic incorrectly flagged as threats: FP / (FP + TN). Critical for preventing SOC analyst burnout.
            </p>
          </div>
          <div className="p-3 rounded bg-slate-950/60 border border-slate-850">
            <strong className="text-cyan-400">False Negative Rate (FNR):</strong>
            <p className="text-slate-400 mt-1">
              Ratio of actual cyberattacks missed by the system: FN / (FN + TP). High FNR represents unacceptable security breach risk.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
};
