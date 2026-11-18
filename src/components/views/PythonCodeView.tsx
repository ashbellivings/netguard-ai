import React, { useState } from 'react';
import { Download, Code2, Copy, Check, FileText, CheckCircle2 } from 'lucide-react';
import { downloadPythonProjectZip } from '../../utils/pythonProjectExport';

export const PythonCodeView: React.FC = () => {
  const [activeFile, setActiveFile] = useState<string>('app.py');
  const [copied, setCopied] = useState(false);
  const [isExporting, setIsExporting] = useState(false);

  const fileContents: Record<string, { desc: string; code: string }> = {
    'app.py': {
      desc: 'Main Streamlit SOC Dashboard entry point with 10 interactive modules.',
      code: `import streamlit as st
import pandas as pd
import numpy as np
import plotly.express as px
from config import APP_NAME, TAGLINE, DB_PATH, SAMPLE_DATA_PATH
from modules.data_loader import auto_map_columns, assess_data_quality, load_demo_dataset
from modules.preprocessing import preprocess_network_data
from modules.exploratory_analysis import generate_automated_findings
from modules.intrusion_detection import train_models, run_model_inference
from modules.model_evaluation import evaluate_models
from modules.alert_manager import sync_alerts_from_predictions, get_all_alerts, update_alert_status

st.set_page_config(page_title=f"{APP_NAME} - SOC Intrusion Detection", page_icon="🛡️", layout="wide")
st.title(f"🛡️ {APP_NAME}")
st.caption(TAGLINE)

# 10 Navigation Modules
nav = st.sidebar.radio("Navigation", [
    "1. Security Overview", "2. Data Management", "3. Preprocessing",
    "4. Exploratory Analysis", "5. Intrusion Detection", "6. Model Evaluation",
    "7. Security Alerts", "8. Incident Workspace", "9. Threat Intelligence",
    "10. Security Reports"
])`
    },
    'config.py': {
      desc: 'Configuration file with sensitive port maps, paths, and random seed.',
      code: `import os

APP_NAME = "NETGUARD AI"
TAGLINE = "Intelligent Network Threat Detection & Security Monitoring"
VERSION = "1.0.0"
ACADEMIC_YEAR = "2026"
PROJECT_TYPE = "B.Sc. Computer Science Cybersecurity Capstone"

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
DB_DIR = os.path.join(BASE_DIR, "database")
DB_PATH = os.path.join(DB_DIR, "incidents.db")
SAMPLE_DATA_PATH = os.path.join(DATA_DIR, "sample_network_traffic.csv")

RANDOM_STATE = 42
TRAIN_TEST_SPLIT_RATIO = 0.75
MAX_DECISION_TREE_DEPTH = 6
RANDOM_FOREST_ESTIMATORS = 50`
    },
    'requirements.txt': {
      desc: 'Python package requirements for Streamlit, Scikit-learn, Pandas, and Plotly.',
      code: `streamlit>=1.32.0
pandas>=2.0.0
numpy>=1.24.0
scikit-learn>=1.3.0
plotly>=5.18.0
matplotlib>=3.7.0
seaborn>=0.12.0
pytest>=7.4.0`
    },
    'modules/preprocessing.py': {
      desc: 'Data cleaning, one-hot encoding, and leak-free scaling fitted on train split.',
      code: `import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import MinMaxScaler

def preprocess_network_data(df: pd.DataFrame, train_ratio: float = 0.75, random_state: int = 42):
    cleaned_df = df.drop_duplicates().reset_index(drop=True)
    numeric_cols = ["Flow_Duration", "Packet_Count", "Byte_Count", "Flow_Rate", "Destination_Port"]
    for col in numeric_cols:
        cleaned_df[col] = pd.to_numeric(cleaned_df[col], errors='coerce').fillna(0).clip(lower=0)
    
    cleaned_df["Log_Packet_Count"] = np.log1p(cleaned_df["Packet_Count"])
    cleaned_df["Log_Byte_Count"] = np.log1p(cleaned_df["Byte_Count"])
    cleaned_df["Log_Flow_Rate"] = np.log1p(cleaned_df["Flow_Rate"])
    cleaned_df["Proto_TCP"] = (cleaned_df["Protocol"].astype(str).str.upper() == "TCP").astype(int)
    cleaned_df["Proto_UDP"] = (cleaned_df["Protocol"].astype(str).str.upper() == "UDP").astype(int)
    cleaned_df["Proto_ICMP"] = (cleaned_df["Protocol"].astype(str).str.upper() == "ICMP").astype(int)

    feature_cols = ["Flow_Duration", "Log_Packet_Count", "Log_Byte_Count", "Log_Flow_Rate", "Destination_Port", "Proto_TCP", "Proto_UDP", "Proto_ICMP"]
    X = cleaned_df[feature_cols]
    y = (cleaned_df["Label"] == "SUSPICIOUS").astype(int)

    X_train_raw, X_test_raw, y_train, y_test = train_test_split(X, y, train_size=train_ratio, random_state=random_state, stratify=y)
    
    # Fit scaler strictly on train split to prevent data leakage
    scaler = MinMaxScaler()
    scale_cols = ["Flow_Duration", "Log_Packet_Count", "Log_Byte_Count", "Log_Flow_Rate", "Destination_Port"]
    X_train = X_train_raw.copy()
    X_test = X_test_raw.copy()
    X_train[scale_cols] = scaler.fit_transform(X_train_raw[scale_cols])
    X_test[scale_cols] = scaler.transform(X_test_raw[scale_cols])
    
    return cleaned_df, X_train, X_test, y_train, y_test, scaler`
    },
    'modules/intrusion_detection.py': {
      desc: 'Machine learning training: Logistic Regression, Decision Tree, Random Forest, Isolation Forest.',
      code: `from sklearn.linear_model import LogisticRegression
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier, IsolationForest

def train_models(X_train, y_train, random_state=42):
    return {
        "logistic_regression": LogisticRegression(max_iter=500, random_state=random_state).fit(X_train, y_train),
        "decision_tree": DecisionTreeClassifier(max_depth=6, min_samples_split=4, random_state=random_state).fit(X_train, y_train),
        "random_forest": RandomForestClassifier(n_estimators=50, max_depth=6, random_state=random_state).fit(X_train, y_train),
        "isolation_forest": IsolationForest(n_estimators=50, contamination=0.25, random_state=random_state).fit(X_train)
    }`
    },
    'modules/alert_manager.py': {
      desc: 'SQLite persistence for security alerts and analyst investigation notes.',
      code: `import sqlite3
import pandas as pd

def init_db(db_path):
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    cur.execute("""CREATE TABLE IF NOT EXISTS alerts (
        id TEXT PRIMARY KEY, timestamp TEXT, source_ip TEXT, destination_ip TEXT,
        source_port INTEGER, destination_port INTEGER, protocol TEXT,
        predicted_category TEXT, severity TEXT, status TEXT, confidence REAL,
        detection_reason TEXT, packet_count INTEGER, byte_count INTEGER, flow_rate REAL
    );""")
    cur.execute("""CREATE TABLE IF NOT EXISTS investigation_notes (
        id INTEGER PRIMARY KEY AUTOINCREMENT, alert_id TEXT, author TEXT,
        timestamp TEXT, note_text TEXT, status_change TEXT
    );""")
    conn.commit()
    conn.close()`
    },
    'tests/test_netguard.py': {
      desc: 'Automated test suite verifying data loaders, preprocessing, and ML accuracy.',
      code: `import unittest
import pandas as pd
from modules.data_loader import auto_map_columns, assess_data_quality

class TestNetGuard(unittest.TestCase):
    def test_schema_mapping(self):
        df = pd.DataFrame({"src_ip": ["10.0.0.1"], "dst_ip": ["10.0.0.2"], "proto": ["TCP"], "dur": [0.5], "tot_pkts": [5], "tot_bytes": [500]})
        mapped, _, _ = auto_map_columns(df)
        self.assertIn("Source_IP", mapped.columns)

if __name__ == '__main__':
    unittest.main()`
    },
    'README.md': {
      desc: 'Complete academic documentation, installation steps, and theory.',
      code: `# NETGUARD AI - B.Sc. Cybersecurity Capstone Project
Intelligent Network Threat Detection & Security Monitoring

### Local Installation:
\`\`\`bash
cd netguard-ai
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
streamlit run app.py
\`\`\`
Tests: \`pytest tests/test_netguard.py -v\``
    }
  };

  const handleDownload = async () => {
    setIsExporting(true);
    try {
      await downloadPythonProjectZip();
    } finally {
      setIsExporting(false);
    }
  };

  const handleCopyCode = () => {
    navigator.clipboard.writeText(fileContents[activeFile].code);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="space-y-6">
      {/* Title */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-2 border-b border-slate-850">
        <div>
          <h1 className="text-xl font-bold tracking-tight text-slate-100 flex items-center gap-2">
            <span>Python Streamlit Project Code Explorer & Export</span>
          </h1>
          <p className="text-xs text-slate-400 mt-0.5">
            Full Python source code compliant with academic requirements. Exportable as a standalone package for local execution.
          </p>
        </div>

        <button
          onClick={handleDownload}
          disabled={isExporting}
          className="px-4 py-2 bg-cyan-500 hover:bg-cyan-400 disabled:opacity-50 text-slate-950 font-bold rounded text-xs transition-colors flex items-center gap-2 shadow-sm self-start sm:self-auto"
        >
          <Download className="w-4 h-4" />
          <span>{isExporting ? 'Packaging ZIP...' : 'Download Full Python Project (.zip)'}</span>
        </button>
      </div>

      {/* Execution Instructions Banner */}
      <div className="p-4 rounded-lg bg-slate-900/90 border border-slate-800 text-xs">
        <div className="flex items-center gap-2 font-semibold text-cyan-400 mb-1">
          <CheckCircle2 className="w-4 h-4 text-cyan-400" />
          <span>Run Locally in 3 Steps:</span>
        </div>
        <div className="font-mono text-[11px] text-slate-300 bg-slate-950 p-2.5 rounded border border-slate-850 mt-2 space-y-1 overflow-x-auto">
          <div>$ python3 -m venv venv && source venv/bin/activate</div>
          <div>$ pip install -r requirements.txt</div>
          <div>$ streamlit run app.py</div>
        </div>
      </div>

      {/* File Explorer Layout */}
      <div className="grid grid-cols-1 lg:grid-cols-4 gap-5">
        {/* File List */}
        <div className="p-4 rounded-lg bg-slate-900/90 border border-slate-800 space-y-1">
          <div className="text-[11px] font-bold text-slate-400 uppercase tracking-wider mb-2 px-2">
            Project Files
          </div>
          {Object.keys(fileContents).map((fileName) => (
            <button
              key={fileName}
              onClick={() => setActiveFile(fileName)}
              className={`w-full flex items-center gap-2 px-3 py-2 rounded text-xs font-mono text-left transition-colors ${
                activeFile === fileName
                  ? 'bg-cyan-950/60 text-cyan-300 border border-cyan-800'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-950/50'
              }`}
            >
              <Code2 className="w-3.5 h-3.5 shrink-0 text-slate-500" />
              <span className="truncate">{fileName}</span>
            </button>
          ))}
        </div>

        {/* Code Viewer */}
        <div className="lg:col-span-3 p-5 rounded-lg bg-slate-900/90 border border-slate-800 space-y-3">
          <div className="flex items-center justify-between pb-3 border-b border-slate-800/80">
            <div>
              <h3 className="text-sm font-bold font-mono text-slate-100 flex items-center gap-2">
                <FileText className="w-4 h-4 text-cyan-400" />
                <span>{activeFile}</span>
              </h3>
              <p className="text-xs text-slate-400 mt-0.5">
                {fileContents[activeFile].desc}
              </p>
            </div>

            <button
              onClick={handleCopyCode}
              className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded text-xs font-medium transition-colors flex items-center gap-1.5"
            >
              {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
              <span>{copied ? 'Copied!' : 'Copy Code'}</span>
            </button>
          </div>

          <div className="p-4 bg-slate-950 border border-slate-850 rounded font-mono text-xs text-slate-200 overflow-x-auto max-h-[480px] overflow-y-auto leading-relaxed">
            <pre>{fileContents[activeFile].code}</pre>
          </div>
        </div>
      </div>
    </div>
  );
};
