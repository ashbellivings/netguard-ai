import React from 'react';
import { X, CheckCircle2, ShieldAlert, ArrowRight } from 'lucide-react';

interface SOCGuideModalProps {
  isOpen: boolean;
  onClose: () => void;
  onJumpToTab: (tab: any) => void;
}

export const SOCGuideModal: React.FC<SOCGuideModalProps> = ({
  isOpen,
  onClose,
  onJumpToTab,
}) => {
  if (!isOpen) return null;

  const steps = [
    {
      num: '01',
      title: 'Load Telemetry Dataset',
      desc: 'Click "Load Demo Dataset" or upload a custom CSV capture (supports CIC-IDS2017, UNSW-NB15, Suricata, or Zeek).',
      tab: 'data_management',
    },
    {
      num: '02',
      title: 'Audit Data Quality & Types',
      desc: 'Review column mappings, detect missing values, duplicates, and check quality score before feeding data to ML.',
      tab: 'data_management',
    },
    {
      num: '03',
      title: 'Execute Leak-Free Preprocessing',
      desc: 'Encode categorical protocols (TCP/UDP/ICMP), apply MinMax/Log1p feature scaling strictly on the train split, and verify class balance.',
      tab: 'preprocessing',
    },
    {
      num: '04',
      title: 'Exploratory Security Analysis',
      desc: 'Examine 8+ security visualizations (duration, packet bursts, byte volume, port heatmaps) and 10 automated analytical findings.',
      tab: 'eda',
    },
    {
      num: '05',
      title: 'Train Machine Learning Models',
      desc: 'Train Logistic Regression, Decision Tree, Random Forest, and Isolation Forest models on the prepared feature matrices.',
      tab: 'detection',
    },
    {
      num: '06',
      title: 'Run Real-Time Flow Inference',
      desc: 'Classify traffic into NORMAL and SUSPICIOUS, calculate confidence scores, and assign explainable severity rankings.',
      tab: 'detection',
    },
    {
      num: '07',
      title: 'Benchmark Model Performance',
      desc: 'Review Accuracy, Precision, Recall, F1-scores, and Confusion Matrices on the held-out test dataset.',
      tab: 'evaluation',
    },
    {
      num: '08',
      title: 'Triage Security Alerts',
      desc: 'Filter alerts by severity (Critical, High, Medium, Low), search targeted IPs, and manage operational status.',
      tab: 'alerts',
    },
    {
      num: '09',
      title: 'Investigate Incidents & Add Notes',
      desc: 'Open the SOC Incident Workspace to review step-by-step playbooks, append forensic notes, and resolve security tickets.',
      tab: 'incidents',
    },
    {
      num: '10',
      title: 'Export Audit Reports & Python Code',
      desc: 'Download CSV alert records, generate printable executive SOC incident reports, or export the full Python Streamlit project.',
      tab: 'reports',
    },
  ];

  return (
    <div className="fixed inset-0 z-50 bg-slate-950/80 backdrop-blur-sm flex items-center justify-center p-4">
      <div className="bg-slate-900 border border-slate-800 rounded-lg max-w-3xl w-full max-h-[90vh] flex flex-col shadow-2xl">
        <div className="flex items-center justify-between p-5 border-b border-slate-800">
          <div>
            <h2 className="text-lg font-bold text-slate-100 flex items-center gap-2">
              <ShieldAlert className="w-5 h-5 text-cyan-400" />
              Junior SOC Analyst Workflow Guide
            </h2>
            <p className="text-xs text-slate-400 mt-0.5">
              Step-by-step operational procedure for demonstration and B.Sc. project defense.
            </p>
          </div>
          <button
            onClick={onClose}
            className="p-1 rounded text-slate-400 hover:text-slate-100 hover:bg-slate-800 transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        <div className="p-6 overflow-y-auto space-y-3.5">
          {steps.map((s) => (
            <div
              key={s.num}
              className="flex items-start gap-4 p-3.5 bg-slate-950/60 border border-slate-800/80 rounded hover:border-slate-700 transition-colors"
            >
              <div className="font-mono text-sm font-bold text-cyan-400 shrink-0 mt-0.5">
                {s.num}
              </div>
              <div className="flex-1">
                <div className="text-sm font-semibold text-slate-200">
                  {s.title}
                </div>
                <div className="text-xs text-slate-400 mt-1 leading-relaxed">
                  {s.desc}
                </div>
              </div>
              <button
                onClick={() => {
                  onJumpToTab(s.tab);
                  onClose();
                }}
                className="text-xs text-cyan-400 hover:text-cyan-300 font-medium flex items-center gap-1 shrink-0 pt-1"
              >
                <span>Open</span>
                <ArrowRight className="w-3.5 h-3.5" />
              </button>
            </div>
          ))}
        </div>

        <div className="p-4 border-t border-slate-800 flex justify-between items-center text-xs text-slate-400 bg-slate-950/40">
          <span>All detection algorithms execute real Scikit-learn equivalent mathematical logic.</span>
          <button
            onClick={onClose}
            className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-100 font-medium rounded transition-colors text-xs"
          >
            Close Guide
          </button>
        </div>
      </div>
    </div>
  );
};
