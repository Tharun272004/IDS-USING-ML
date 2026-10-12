# Real-Time Intrusion Detection System (IDS)

An enterprise-grade, real-time Network Intrusion Detection System (IDS) that monitors your network traffic to detect cyber attacks as they happen. It uses Machine Learning (Random Forest) along with advanced behavioral detectors to identify hidden and complex threats.

---

## 🚀 Key Features

* **Real-Time Packet Sniffing:** Captures live network traffic and processes it instantly using `scapy`.
* **Machine Learning Classification:** Uses a trained Random Forest model to distinguish between normal traffic and anomalous/malicious traffic based on the NSL-KDD dataset.
* **Specialized Threat Detectors:**
  * **C2 (Command & Control) Beaconing:** Detects periodic, robotic communication patterns typical of malware communicating with attackers.
  * **DNS Tunneling Detection:** Analyzes DNS queries to find hidden data (using Shannon entropy and length analysis) that attackers try to sneak out.
  * **Data Exfiltration Monitor:** Identifies sudden bursts of upload-heavy traffic, preventing data theft.
* **Unified Risk Scoring Engine:** Correlates multiple alerts into a single 0-100 risk score, drastically reducing false positives.
* **Modern Web Dashboard:** A sleek, dark-themed UI with live charts, threat alerts, and packet history.
* **Reporting System:** Generate professional PDF reports or export CSV data for any selected time range.

## Evaluation Before Novelty Claims

For complete Windows setup, execution, architecture flow, troubleshooting, and evaluation instructions, see [readmerun.md](readmerun.md).

Run the reproducible evaluation from the repository root:

```powershell
python evaluation\evaluate_ids.py
```

The journal-facing research-status matrix is available in [reports/research_status.md](reports/research_status.md).

The runner writes `reports/evaluation_results.json` and covers:

* A majority baseline, logistic regression, decision tree, the production-style Random Forest, and a two-hidden-layer MLP neural baseline. All use the same five live-compatible features and official KDDTest+ evaluation data.
* Reproduction of the production 80/20 split and experimental full-KDDTrain+ Random Forest policies, including confusion matrices and threshold trade-offs. Threshold sweeps are descriptive; no KDDTest+ threshold is selected.
* Independent controlled cases for C2 beaconing, DNS tunneling, and exfiltration, including precision, recall, F1, false-positive rate, and detection delay.
* Risk-engine ablation for ML-only, ML plus detector scores, and full risk scoring, including false-positive rate, prioritization, and hidden-genuine-attack counts.
* Runtime telemetry from the actual flow path. During live capture, each completed flow appends capture-to-alert and prediction-processing measurements to `data/live_latency.csv`.
* Live session telemetry in `data/live_runtime.csv` records elapsed time, packets per second, predicted flows, CPU percentage, and resident memory. Packet loss is not currently exposed by the Scapy capture loop.
* A 1,000-iteration synthetic flow benchmark reporting throughput, per-flow wall time, process CPU time, and peak Python allocations. It excludes packet capture, flow timeout, network I/O, and OS scheduling effects.

An external contemporary dataset can be supplied with `--external-csv` only when it has the columns `duration`, `protocol_type`, `src_bytes`, `dst_bytes`, `count`, and `label`. Results remain separate from NSL-KDD.

### Interpretation Limits

NSL-KDD is an offline benchmark, not representative live packet capture. The live pipeline reduces traffic to five aggregate flow fields and now derives `count` from destination-host connections observed in the prior two seconds, matching the intended NSL-KDD connection-context definition. This semantic alignment still requires validation under real traffic. Offline test performance does not establish real-world detection performance. The controlled detector fixtures validate logic and known examples; they do not estimate production prevalence, traffic drift, or operational false-alarm rates. Live latency is not available until a capture session has generated telemetry. No CNN-LSTM or second-dataset result is claimed by this evaluation.

---

## 📂 Project Structure

```text
IDS_Project/
|-- app.py                          # Main Flask application and API routes
|-- requirements.txt                # Python package dependencies
|-- README.md                       # Project documentation
|
|-- ml/                             # Machine Learning & Detection Engines
|   |-- c2_detector.py              # Detects malware C2 beaconing
|   |-- dns_tunneling.py            # Detects covert DNS tunnels
|   |-- exfiltration_detector.py    # Detects massive data uploads
|   |-- risk_engine.py              # Calculates overall threat severity
|
|-- packet_capture/                 # Network Traffic Processing
|   |-- live_predictor.py           # Real-time packet sniffer & flow classifier
|
|-- models/                         # Pre-trained ML Models
|   |-- live_ids_model.pkl          # Random Forest classifier
|   |-- protocol_encoder.pkl        # Protocol string-to-number converter
|   |-- attack_threshold.pkl        # Decision threshold configuration
|
|-- data/                           # Application Data
|   |-- live_predictions.csv        # Log of all captured and analyzed flows
|
|-- report/                         # PDF Generation
|   |-- generate_report.py          # Builds PDF forensic reports
|
|-- templates/                      # HTML Views
|   |-- index.html                  # Landing page
|   |-- dashboard.html              # Main real-time analytics dashboard
|   |-- overview.html               # Project architecture & ML details
|   |-- reports.html                # Report generation and export page
|   |-- live_monitoring.html        # Scanner start/stop controls & live stream
|   |-- attack_details.html         # Flow investigation view
|
|-- static/                         # CSS & JS Assets
    |-- css/                        # Styling for the web app
    |-- js/                         # Frontend logic and API integration
```

---

## 🖥️ Web Interface Navigation

1. **Dashboard (`/dashboard`):** Provides a high-level overview of live network health. Features donut charts, bar charts, attack rate counters, and recent alerts.
2. **Overview (`/overview`):** Explains how the ML models and threat detectors work under the hood. Great for understanding the technical architecture.
3. **Reports (`/reports`):** Select a specific time frame (e.g., "Last 24 Hours") to download a forensic **PDF Report** or a **CSV Export** of the scanned data.
4. **Live Monitoring (`/live-monitoring`):** The operational console where you can **Start**, **Stop**, or **Continue** the packet scanner. It displays a live stream of captured network flows and their assigned threat severity.

---

## ⚙️ Installation & Setup

### Prerequisites
* **Python 3.10+** (Tested on Python 3.14)
* **Npcap / WinPcap (Windows Only):** If you are on Windows, you must install [Npcap](https://npcap.com/) to capture live packets. Make sure to check *"Install Npcap in WinPcap API-compatible Mode"* during installation. (On Linux, install `libpcap`).

### Step-by-Step Setup

1. **Open your terminal or command prompt** and navigate to the project directory:
   ```powershell
   cd C:\Users\Tharun\.vscode\work\IDS_Project
   ```

2. **Create and activate a virtual environment:**
   ```powershell
   python -m venv venv
   .\venv\Scripts\Activate.ps1
   ```

3. **Install the required dependencies:**
   ```powershell
   pip install -r requirements.txt
   ```

4. **Run the Application:**
   ```powershell
   python app.py
   ```

5. **Access the Web Dashboard:**
   Open your web browser and go to:
   ```text
   http://127.0.0.1:5000
   ```

---

## 🎯 How to Use

1. **Start Scanning:** Navigate to the **Live Monitoring** tab and click **"Start Scanner"**. The system will immediately begin analyzing network traffic.
2. **Monitor Traffic:** Watch the live stream table fill up with network packets. Malicious flows will be flagged with a Red/High severity badge.
3. **Analyze Trends:** Go to the **Dashboard** to see visual charts of protocol distributions and attack trends.
4. **Generate a Report:** When you are done monitoring, go to the **Reports** tab, choose your time period, and click "Download PDF Report" to get a clean summary of your network's security posture.

---

## 🧪 Testing the Detectors

If you want to manually verify that the detection logic works, you can run the following test script in your terminal (while the virtual environment is active):

```powershell
python -c "
from ml.dns_tunneling import analyze_dns_query
from ml.exfiltration_detector import analyze_data_exfiltration

print('DNS Tunneling Test (Malicious):', analyze_dns_query('aHR0cHM6Ly9leGFtcGxlLmNvbS9tYWxpY2lvdXM.evil-c2.com'))
print('Exfiltration Test (Malicious):', analyze_data_exfiltration('10.0.0.5', '1.2.3.4', 3000000, 500, 2.0))
"
```
*This will output the detection results, confirming the advanced threat engines are correctly classifying attacks.*