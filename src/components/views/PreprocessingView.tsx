import React, { useState } from 'react';
import { CleanedFlowRecord, PreprocessingSummary } from '../../types';
import { Cpu, CheckCircle2, ShieldCheck, ArrowRight, Download, RefreshCw } from 'lucide-react';
import { triggerDownload, exportCleanedDatasetToCSV } from '../../utils/reportExporter';

interface PreprocessingViewProps {
  cleanedFlows: CleanedFlowRecord[];
  summary?: PreprocessingSummary;
  onExecutePreprocessing: (ratio: number, seed: number) => void;
  onNavigateToTab: (tab: any) => void;
}

export const PreprocessingView: React.FC<PreprocessingViewProps> = ({
  cleanedFlows,
  summary,
  onExecutePreprocessing,
  onNavigateToTab,
}) => {
  const [splitRatio, setSplitRatio] = useState(0.75);
  const [seed, setSeed] = useState(42);
  const [isProcessing, setIsProcessing] = useState(false);

  const handleRun = () => {
    setIsProcessing(true);
    setTimeout(() => {
      onExecutePreprocessing(splitRatio, seed);
      setIsProcessing(false);
    }, 250);
  };

  if (cleanedFlows.length === 0) {
    return (
      <div className="p-10 rounded-lg bg-slate-900/90 border border-slate-800 text-center space-y-3">
        <p className="text-sm text-slate-200 font-semibold">No Dataset Available for Preprocessing</p>
        <p className="text-xs text-slate-400">Load the synthetic demonstration dataset or upload a CSV flow file first.</p>
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
            <span>Data Preprocessing & Feature Pipeline</span>
          </h1>
          <p className="text-xs text-slate-400 mt-0.5">
            Deterministic feature normalization, categorical protocol encoding, and leak-free stratified train/test partitioning.
          </p>
        </div>

        {cleanedFlows.length > 0 && (
          <button
            onClick={() => triggerDownload(exportCleanedDatasetToCSV(cleanedFlows), 'netguard_cleaned_traffic.csv')}
            className="px-3 py-1.5 bg-slate-900 hover:bg-slate-800 text-slate-200 border border-slate-750 rounded text-xs font-medium transition-colors flex items-center gap-1.5 self-start sm:self-auto"
          >
            <Download className="w-3.5 h-3.5" />
            <span>Export Cleaned Dataset (CSV)</span>
          </button>
        )}
      </div>

      {/* Configuration & Controls */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
        <div className="p-5 rounded-lg bg-slate-900/90 border border-slate-800 space-y-4">
          <h3 className="text-sm font-bold text-slate-100 flex items-center gap-2">
            <Cpu className="w-4 h-4 text-cyan-400" />
            Pipeline Parameters
          </h3>

          <div>
            <div className="flex justify-between text-xs mb-1.5">
              <span className="text-slate-400">Train / Test Ratio</span>
              <span className="font-mono text-cyan-400 font-bold">
                {Math.round(splitRatio * 100)}% Train / {Math.round((1 - splitRatio) * 100)}% Test
              </span>
            </div>
            <input
              type="range"
              min="0.5"
              max="0.85"
              step="0.05"
              value={splitRatio}
              onChange={(e) => setSplitRatio(parseFloat(e.target.value))}
              className="w-full accent-cyan-500 cursor-pointer"
            />
          </div>

          <div>
            <label className="block text-xs text-slate-400 mb-1">
              Reproducible Random Seed
            </label>
            <input
              type="number"
              value={seed}
              onChange={(e) => setSeed(parseInt(e.target.value, 10) || 42)}
              className="w-full px-3 py-1.5 bg-slate-950 border border-slate-800 rounded text-xs text-slate-200 font-mono focus:outline-none focus:border-cyan-500"
            />
            <span className="text-[10px] text-slate-500 mt-1 block">
              Enforces deterministic stratified splits for academic reproducibility.
            </span>
          </div>

          <button
            onClick={handleRun}
            disabled={isProcessing}
            className="w-full py-2 bg-cyan-500 hover:bg-cyan-400 disabled:opacity-50 text-slate-950 rounded text-xs font-semibold transition-colors flex items-center justify-center gap-2 shadow-sm"
          >
            {isProcessing ? (
              <>
                <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                <span>Processing Pipeline...</span>
              </>
            ) : (
              <>
                <Cpu className="w-3.5 h-3.5" />
                <span>Execute Preprocessing</span>
              </>
            )}
          </button>
        </div>

        {/* Data Leakage Safeguards Box */}
        <div className="lg:col-span-2 p-5 rounded-lg bg-slate-900/90 border border-slate-800 flex flex-col justify-between">
          <div>
            <div className="flex items-center gap-2 text-xs font-semibold text-emerald-400 mb-2">
              <ShieldCheck className="w-4 h-4 text-emerald-400" />
              <span>Strict Data Leakage Prevention Architecture</span>
            </div>
            <h4 className="text-sm font-bold text-slate-100">
              Scikit-learn Standard Evaluation Protocol
            </h4>
            <p className="text-xs text-slate-400 mt-1 leading-relaxed">
              In academic cybersecurity research, calculating scaling parameters (min/max or mean/std) across the entire dataset before splitting causes information leakage, resulting in falsely inflated accuracy.
            </p>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5 mt-3.5 text-xs">
              <div className="p-2.5 rounded bg-slate-950/60 border border-slate-850 flex items-start gap-2">
                <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 shrink-0 mt-0.5" />
                <div>
                  <strong className="text-slate-200">Isolated Fit:</strong> Scalers fit strictly on training flows; test flows are transformed blindly.
                </div>
              </div>
              <div className="p-2.5 rounded bg-slate-950/60 border border-slate-850 flex items-start gap-2">
                <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 shrink-0 mt-0.5" />
                <div>
                  <strong className="text-slate-200">Stratified Ratio:</strong> Preserves exact attack/normal proportions in both splits.
                </div>
              </div>
              <div className="p-2.5 rounded bg-slate-950/60 border border-slate-850 flex items-start gap-2">
                <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 shrink-0 mt-0.5" />
                <div>
                  <strong className="text-slate-200">Log1p Scaling:</strong> Compresses high-skew packet/byte volumes without clipping anomalies.
                </div>
              </div>
              <div className="p-2.5 rounded bg-slate-950/60 border border-slate-850 flex items-start gap-2">
                <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 shrink-0 mt-0.5" />
                <div>
                  <strong className="text-slate-200">Metadata Isolation:</strong> IPs and timestamps excluded from ML feature matrix.
                </div>
              </div>
            </div>
          </div>

          <div className="pt-3 border-t border-slate-800/80 mt-4 flex justify-between items-center text-xs">
            <span className="text-slate-400">Class Balance:</span>
            <span className="font-mono text-cyan-400 font-bold">
              {summary ? `${summary.classDistribution.imbalanceRatio} : 1 (Normal:Suspicious)` : '7.0 : 1'}
            </span>
          </div>
        </div>
      </div>

      {/* Preprocessing Summary Grid */}
      {summary && (
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs">
          <div className="p-4 rounded bg-slate-900/90 border border-slate-800">
            <div className="text-slate-500 font-medium">Training Flows</div>
            <div className="text-xl font-bold font-mono text-cyan-400 mt-1">
              {summary.trainCount.toLocaleString()}
            </div>
            <div className="text-[10px] text-slate-500 mt-0.5">Model fitting partition</div>
          </div>

          <div className="p-4 rounded bg-slate-900/90 border border-slate-800">
            <div className="text-slate-500 font-medium">Testing Flows</div>
            <div className="text-xl font-bold font-mono text-cyan-400 mt-1">
              {summary.testCount.toLocaleString()}
            </div>
            <div className="text-[10px] text-slate-500 mt-0.5">Hold-out evaluation</div>
          </div>

          <div className="p-4 rounded bg-slate-900/90 border border-slate-800">
            <div className="text-slate-500 font-medium">Duplicates Deduplicated</div>
            <div className="text-xl font-bold font-mono text-slate-200 mt-1">
              {summary.duplicatesRemoved}
            </div>
            <div className="text-[10px] text-slate-500 mt-0.5">Identical 5-tuple flows</div>
          </div>

          <div className="p-4 rounded bg-slate-900/90 border border-slate-800">
            <div className="text-slate-500 font-medium">Features in Vector</div>
            <div className="text-xl font-bold font-mono text-slate-200 mt-1">
              {summary.featuresUsed.length}
            </div>
            <div className="text-[10px] text-slate-500 mt-0.5">Engineered inputs</div>
          </div>
        </div>
      )}

      {/* Feature Vector Inspection Table */}
      <div className="p-5 rounded-lg bg-slate-900/90 border border-slate-800">
        <div className="flex items-center justify-between mb-4">
          <div>
            <h3 className="text-sm font-bold text-slate-100">
              Normalized Feature Vectors (First 15 Rows)
            </h3>
            <p className="text-xs text-slate-400">
              Values scaled between 0.000 and 1.000 for gradient and tree split stability
            </p>
          </div>
          <button
            onClick={() => onNavigateToTab('eda')}
            className="px-3.5 py-1.5 bg-cyan-500 hover:bg-cyan-400 text-slate-950 rounded text-xs font-semibold transition-colors flex items-center gap-1.5"
          >
            <span>Proceed to Exploratory Analysis</span>
            <ArrowRight className="w-3.5 h-3.5" />
          </button>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs border-collapse">
            <thead>
              <tr className="border-b border-slate-800 text-slate-400 uppercase font-mono text-[10px] tracking-wider">
                <th className="py-2 px-3">Flow ID</th>
                <th className="py-2 px-3">Norm Duration</th>
                <th className="py-2 px-3">Log Packets</th>
                <th className="py-2 px-3">Log Bytes</th>
                <th className="py-2 px-3">Log Flow Rate</th>
                <th className="py-2 px-3">TCP</th>
                <th className="py-2 px-3">UDP</th>
                <th className="py-2 px-3">ICMP</th>
                <th className="py-2 px-3">Target Label</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-850 font-mono">
              {cleanedFlows.slice(0, 15).map((f) => (
                <tr key={f.id} className="hover:bg-slate-850/40 transition-colors">
                  <td className="py-2 px-3 font-bold text-slate-300">{f.id}</td>
                  <td className="py-2 px-3 text-cyan-300">{f.normalizedDuration.toFixed(4)}</td>
                  <td className="py-2 px-3 text-slate-300">{f.normalizedPackets.toFixed(4)}</td>
                  <td className="py-2 px-3 text-slate-300">{f.normalizedBytes.toFixed(4)}</td>
                  <td className="py-2 px-3 text-slate-300">{f.normalizedRate.toFixed(4)}</td>
                  <td className="py-2 px-3 text-slate-400">{f.protocolEncoded[0]}</td>
                  <td className="py-2 px-3 text-slate-400">{f.protocolEncoded[1]}</td>
                  <td className="py-2 px-3 text-slate-400">{f.protocolEncoded[2]}</td>
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
