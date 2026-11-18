# NETGUARD AI
## AI-Based Network Intrusion Detection & Security Monitoring System
### Final-Year B.Sc. Computer Science Cybersecurity Capstone Project

**Tagline:** *Intelligent Network Threat Detection & Security Monitoring*  
**Role Simulation:** *Junior Security Analyst in a Security Operations Center (SOC)*  
**Author:** Academic Capstone Candidate  
**Academic Year:** 2026

---

## 1. Project Introduction & Problem Statement
Modern enterprise networks exchange massive volumes of telemetry data across local subnets, cloud environments, and internet-facing perimeters. Security teams frequently face targeted threats including:
- Unauthorized reconnaissance port sweeps (SYN scans).
- High-frequency brute force credential guessing (SSH, RDP).
- Volumetric Denial-of-Service (DoS / DDoS) attacks.
- Web application vulnerability probes (SQLi, XSS).
- Low-and-slow command-and-control (C2) botnet beaconing.

Traditional rule-based intrusion detection systems often produce high false-positive rates and struggle with evolving traffic patterns. **NETGUARD AI** applies supervised machine learning and unsupervised anomaly detection to classify network flow records, prioritize threats with explainable severity rankings, generate actionable alerts, and assist Junior SOC Analysts through structured incident response workflows.

---

## 2. Technology Stack & Architecture
- **Programming Language:** Python 3.10 / 3.11+
- **Interactive SOC Dashboard:** Streamlit
- **Data Engineering:** Pandas, NumPy
- **Machine Learning Engine:** Scikit-learn (Logistic Regression, Decision Tree, Random Forest, Isolation Forest)
- **Visualizations:** Plotly Interactive Charts
- **Database & Persistence:** SQLite3 (`database/incidents.db`)
- **Dataset Support:** CSV flow records (CIC-IDS2017, UNSW-NB15, CSE-CIC-IDS2018, Zeek `conn.log`, Suricata `eve.json`)

```
netguard-ai/
│
├── app.py                      # Main Streamlit SOC dashboard application
├── requirements.txt            # Python dependencies
├── README.md                   # Complete academic documentation
├── config.py                   # Centralized application parameters and port maps
│
├── modules/
│   ├── data_loader.py          # CSV loading, schema mapping, and quality checks
│   ├── preprocessing.py        # Leak-free cleaning, scaling, and train/test split
│   ├── exploratory_analysis.py # 8+ visualizations and 10+ automated findings
│   ├── intrusion_detection.py  # 4 ML models (LR, DT, RF, Isolation Forest)
│   ├── model_evaluation.py     # Accuracy, Precision, Recall, F1, Confusion Matrix
│   ├── alert_manager.py        # SQLite alert generation and deduplication
│   ├── incident_manager.py     # SOC analyst investigation playbooks and notes
│   └── report_generator.py     # Executive report builder and CSV exporter
│
├── database/
│   └── incidents.db            # Persistent SQLite database for SOC investigations
│
├── data/
│   └── sample_network_traffic.csv # Built-in demonstration dataset (500+ flows)
│
└── tests/
    └── test_netguard.py        # Automated test suite for data, ML, and database
```

---

## 3. Installation & Local Execution Instructions

### Prerequisites
- Python 3.10 or 3.11 installed.
- Git or extracted ZIP package.

### Step 1: Create a Virtual Environment
```bash
# Navigate to project directory
cd netguard-ai

# Create virtual environment
python3 -m venv venv

# Activate virtual environment
# On Linux / macOS:
source venv/bin/activate

# On Windows (cmd.exe):
venv\Scripts\activate.bat
# On Windows (PowerShell):
venv\Scripts\Activate.ps1
```

### Step 2: Install Required Dependencies
```bash
pip install --upgrade pip
pip install -r requirements.txt
```

### Step 3: Run the Streamlit SOC Application
```bash
streamlit run app.py
```
Open your browser at `http://localhost:8501` to access NETGUARD AI.

### Step 4: Run Automated Tests
```bash
pytest tests/test_netguard.py -v
```

---

## 4. Machine Learning Algorithms & Mathematical Foundations

### 1. Logistic Regression (Benchmark)
- Models the log-odds of a flow being malicious via the logistic sigmoid function:
  $$\sigma(z) = \frac{1}{1 + e^{-z}}, \quad z = w^T X + b$$
- Optimized using binary cross-entropy loss with L2 regularization.

### 2. Decision Tree Classifier (Explainable AI)
- Recursively partitions flow features using the Gini Impurity metric:
  $$I_G(p) = 1 - \sum_{i=1}^{C} p_i^2$$
- Yields human-interpretable conditional rules (e.g., `IF Flow_Rate > 500 KB/s AND Protocol == TCP THEN SUSPICIOUS`).

### 3. Random Forest Classifier (Ensemble)
- Combines $B$ randomized decision trees trained on bootstrap samples (bagging).
- Mitigates single-tree overfitting and evaluates feature importance via mean decrease in impurity.

### 4. Isolation Forest (Unsupervised Anomaly Detection)
- Isolates anomalous flows in randomized decision trees.
- Anomalies have shorter average path lengths $h(x)$ from root to leaf, scored by:
  $$s(x, n) = 2^{-\frac{E(h(x))}{c(n)}}$$

---

## 5. SOC Analyst Workflow Guide (How to Use)
1. **Load Telemetry:** Click **⚡ Load Demo Dataset** in the sidebar or upload your own CSV capture.
2. **Review Data Quality:** Navigate to **2. Traffic Data Management** to inspect row counts, missing values, and column mapping.
3. **Preprocess Flows:** Go to **3. Data Preprocessing**, set the train/test split ratio (default 75%), and run leak-free normalization.
4. **Explore Trends:** Open **4. Exploratory Analysis** to review automated security findings, packet burst histograms, and port distributions.
5. **Train & Detect:** In **5. AI Intrusion Detection**, train all models and classify network traffic flows.
6. **Benchmark Metrics:** Compare Accuracy, Precision, Recall, F1, and Confusion Matrices in **6. Model Evaluation**.
7. **Triage Alerts:** In **7. Security Alerts**, filter alerts by severity (Critical, High, Medium, Low) and protocol.
8. **Investigate Incidents:** In **8. Incident Workspace**, review step-by-step SOC playbooks, append forensic notes, and update statuses.
9. **Export Audit Reports:** In **10. Security Reports**, download CSV alert audits and formatted Executive Incident Reports.

---

## 6. System Limitations & Future Work
- **Payload Encryption:** Flow metadata inspection does not inspect TLS-encrypted packet contents.
- **Concept Drift:** Zero-day attack vectors require scheduled retraining.
- **Future Enhancements:** Direct integration with live Zeek clusters and automated Kafka event streaming.
