# NETGUARD AI — Intelligent Network Intrusion Detection & SOC Monitoring System

**NETGUARD AI** is an interactive Security Operations Center (SOC) analytics dashboard and Machine Learning Network Intrusion Detection System (NIDS). Designed for cybersecurity analysts and capstone evaluation, it ingests network flow telemetry (custom CSV/TSV/Zeek/Wireshark captures or built-in synthetic threat scenarios), executes leak-free data preprocessing, trains and benchmarks multiple ML classifiers, raises prioritized security alerts, and supports end-to-end incident triage and reporting.

> **Important Scope & Simulation Notice:**
> Because web browsers cannot open privileged raw kernel packet sockets (`AF_PACKET` / `libpcap`), the React web application operates on **uploaded network flow exports (CSV/TSV/Zeek/Suricata)** and clearly labeled **synthetic SOC demonstration datasets**. Alerts and analyst notes in the browser are persisted to `localStorage` and exportable as SQLite `.sql` scripts. For local Python execution with native `scikit-learn` and real `sqlite3` database persistence (`database/incidents.db`), a complete companion **Python + Streamlit** project is included under `python_project/`.

---

## Key Features

- **Universal Network Telemetry Ingestion (`Traffic Data Management`)**
  - Upload `.csv`, `.tsv`, `.txt`, or Zeek `#fields` connection logs via drag-and-drop or file picker.
  - Auto-detects delimiters (`,`, `;`, `\t`, `|`), strips UTF-8 BOM, and fuzzy-maps column aliases across **CIC-IDS2017**, **UNSW-NB15**, **KDD-99/NSL-KDD**, **Zeek `conn.log`**, **Suricata EVE**, and **Wireshark CSV** exports.
  - Data quality scoring (missing values, 5-tuple duplicates, negative/NaN numerics, label standardization) with downloadable audit reports.
  - 5 reproducible synthetic SOC threat scenarios: **Enterprise Baseline**, **Volumetric DDoS**, **Subnet Port Scan**, **SSH/RDP Brute Force**, and **Botnet C2 Beaconing**.
- **Leak-Free Data Preprocessing Pipeline (`Data Preprocessing`)**
  - Deduplicates identical 5-tuple flows, imputes invalid numerical attributes, applies `log1p` + Min-Max normalization (`0.0–1.0`), and one-hot encodes transport protocols (`TCP`, `UDP`, `ICMP`).
  - Performs stratified Train/Test splitting **before** fitting normalization statistics to prevent data leakage.
- **Exploratory Security Data Analysis (`Exploratory Analysis`)**
  - Generates 10 automated security findings and 7+ data-driven visualizations including Attack Taxonomy Breakdown, Protocol Distribution, Flow Duration/Packet/Byte Histograms, Top Service Ports, and a Pearson Correlation Heatmap Matrix.
- **Machine Learning Intrusion Detection & Evaluation (`AI Intrusion Detection` & `Model Evaluation`)**
  - Deterministic browser implementations of **Random Forest (12 bagged decision trees)**, **Decision Tree (explainable IF-THEN rules)**, **Logistic Regression (L2 gradient descent)**, and **Isolation Forest (unsupervised anomaly detection)**.
  - Side-by-side hold-out test benchmarking: Accuracy, Precision, Recall, F1-Score, FPR, FNR, Confusion Matrices (`TP/TN/FP/FN`), and Feature Importances.
- **SOC Alert Queue, Incident Workspace & Threat Intelligence**
  - Multi-filter alert triage (Severity, Operational Status, Protocol, IP/Category search).
  - Incident Forensic Workspace with 5-tuple telemetry breakdown, category-specific SOC containment playbooks, custom analyst identifier tracking, and persistent case audit logs.
  - Attacker IP infrastructure profiling and False Positive vs. False Negative operational trade-off diagnostics.
- **Audit Reporting & Companion Python Project**
  - Export CSV Alerts (CWE-1236 formula-injection safe), Cleaned Feature CSVs, SQLite `.sql` DDL/DML dumps, Plain-Text Reports, and XSS-safe Printable HTML/PDF Executive Dossiers.
  - Built-in **Python Streamlit Project Explorer & ZIP Downloader** bundling the full Python codebase from `python_project/`.

---

## Technology Stack

### Web Application (Primary Frontend SPA)
- **Framework:** React 19 + TypeScript
- **Build Tool:** Vite 8
- **Styling:** Tailwind CSS v4
- **Icons:** Lucide React
- **Packaging:** JSZip (client-side Python project bundle export)

### Companion Python SOC Application (`python_project/`)
- **Dashboard:** Streamlit
- **Data Processing:** Pandas, NumPy
- **Machine Learning:** Scikit-learn (`LogisticRegression`, `DecisionTreeClassifier`, `RandomForestClassifier`, `IsolationForest`)
- **Visualization:** Plotly, Matplotlib, Seaborn
- **Database:** SQLite3 (`database/incidents.db`)

---

## Project Structure

```text
netguard-ai/
├── index.html                    # HTML entry point & SEO metadata
├── package.json                  # Node/Vite dependencies and scripts
├── vite.config.ts                # Vite configuration
├── tsconfig.json                 # TypeScript compiler configuration
├── vercel.json                   # Vercel SPA rewrite & security headers config
├── .env.example                  # Placeholder environment variable template
├── .gitignore                    # Git exclusion rules (.env, dist, *.db, venv)
├── src/
│   ├── App.tsx                   # Main SOC console state & pipeline orchestration
│   ├── main.tsx                  # React root with ErrorBoundary recovery
│   ├── index.css                 # Tailwind CSS v4 theme tokens & scrollbars
│   ├── types/index.ts            # TypeScript interfaces for flows, ML, and alerts
│   ├── data/demoTraffic.ts       # Seeded synthetic network traffic & scenario generators
│   ├── components/
│   │   ├── Header.tsx            # Top bar with mobile drawer toggle & dataset badge
│   │   ├── Sidebar.tsx           # Responsive 12-module SOC navigation drawer
│   │   ├── SOCGuideModal.tsx     # 10-step SOC analyst workflow guide
│   │   └── views/                # 12 modular SOC views (Overview -> Python Export)
│   └── utils/
│       ├── dataProcessor.ts      # Universal CSV/TSV/Zeek parser & leak-free preprocessor
│       ├── mlEngine.ts           # Deterministic LR, DT, RF & Isolation Forest engine
│       ├── edaFindings.ts        # Statistical EDA findings & Pearson correlation
│       ├── alertManager.ts       # Alert prioritization, playbooks & localStorage sync
│       ├── reportExporter.ts     # Safe CSV, SQLite .sql & escaped HTML report exporter
│       └── pythonProjectExport.ts# Complete ZIP packager for python_project/
├── tests/
│   └── test_audit_suite.ts       # Automated TypeScript audit & security test suite
└── python_project/               # Standalone Python + Streamlit + SQLite implementation
    ├── app.py
    ├── config.py
    ├── requirements.txt
    ├── modules/
    └── tests/
```

---

## Installation & Local Setup

### Option A: React + Vite Web Application

#### Prerequisites
- **Node.js 18+** (or 20+ LTS) and **npm**

#### Steps
```bash
# 1. Install dependencies
npm install

# 2. (Optional) Copy environment template
cp .env.example .env

# 3. Start development server on http://localhost:3000
npm run dev

# 4. Type-check and build for production
npm run lint
npm run build
```

---

### Option B: Companion Python + Streamlit + SQLite Application

#### Prerequisites
- **Python 3.10 or 3.11+**

#### Steps
```bash
cd python_project
python3 -m venv venv

# Activate virtual environment:
# macOS / Linux:
source venv/bin/activate
# Windows (PowerShell):
# venv\Scripts\Activate.ps1

pip install -r requirements.txt
streamlit run app.py
```

---

## Environment Variables

The web application runs completely client-side in the browser and does **not** require private API keys or database credentials. See `.env.example`:

| Variable | Required | Description | Default |
| :--- | :--- | :--- | :--- |
| `VITE_APP_NAME` | No | Display title override | `"NETGUARD AI"` |
| `VITE_APP_ENV` | No | Environment label | `"production"` |

> Never commit real `.env` files or credentials. `.gitignore` excludes `.env` and `.env.*` automatically.

---

## Testing

Run the automated audit suite, TypeScript compiler check, and Python SQLite persistence tests:

```bash
# TypeScript type-checking
npm run lint

# Full Web SOC Pipeline, Security & ML Test Suite
npx tsx tests/test_audit_suite.ts

# Production build verification
npm run build

# Python SQLite persistence & syntax tests
python3 python_project/tests/test_sqlite_persistence.py
python3 -m py_compile python_project/app.py python_project/config.py python_project/modules/*.py
```

---

## Screenshots

> Add your screenshots to a `docs/screenshots/` folder after capturing them from your live deployment and update the links below:

- **SOC Security Overview:** `![Security Overview](docs/screenshots/overview.png)`
- **Traffic Data Management & CSV Ingestion:** `![Data Management](docs/screenshots/data-management.png)`
- **AI Intrusion Detection & Model Evaluation:** `![Model Evaluation](docs/screenshots/model-evaluation.png)`
- **Incident Investigation Workspace:** `![Incident Workspace](docs/screenshots/incident-workspace.png)`

---

## Deployment Instructions

Because the frontend is a static React + Vite single-page application (`npm run build` -> `dist/`), it deploys effortlessly to **Vercel**, **Netlify**, or **Render Static Sites** with zero server maintenance:

### Deploy Web App on Vercel (Recommended)
1. Push this repository to GitHub.
2. Import the repository at [vercel.com/new](https://vercel.com/new).
3. Vercel automatically detects `vercel.json`:
   - **Framework Preset:** `Vite`
   - **Build Command:** `npm run build`
   - **Output Directory:** `dist`
4. Click **Deploy**.

### Deploy Web App on Render (Static Site)
1. Create a **New Static Site** in Render connected to your GitHub repo.
2. Set **Build Command:** `npm install && npm run build`
3. Set **Publish Directory:** `dist`
4. Add a Rewrite rule `/* -> /index.html`.

### Deploy Companion Python App (`python_project/`) on Streamlit Community Cloud
1. Connect the same GitHub repository at [share.streamlit.io](https://share.streamlit.io).
2. Set **Main file path** to `python_project/app.py`.
3. Note that Streamlit Cloud uses ephemeral container storage for `incidents.db` across restarts.
