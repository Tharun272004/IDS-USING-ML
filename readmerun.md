# IDS Project: Complete Run Guide

This guide explains how to install, run, evaluate, and understand the Real-Time Network Intrusion Detection System.

## 1. Project Purpose

The project monitors network traffic and combines:

- Scapy packet capture
- Flow-level feature extraction
- Random Forest classification
- C2 beacon detection
- DNS tunneling detection
- Data exfiltration detection
- Unified risk scoring
- Flask dashboard monitoring
- CSV and PDF reporting
- Offline research evaluation

The system has two operating modes:

1. Live monitoring mode for packet capture and alerts.
2. Evaluation mode for reproducible model and detector experiments.

## 2. Requirements

### Software

- Windows 10 or Windows 11
- Python 3.10 or newer
- Npcap for Windows packet capture
- PowerShell
- Administrative permission if required by Npcap

### Python dependencies

Dependencies are listed in `requirements.txt`. Important packages include:

- Flask: web dashboard and API
- Scapy: packet capture
- pandas and numpy: data processing
- scikit-learn: machine-learning models and metrics
- joblib: model loading
- psutil: CPU and memory telemetry
- ReportLab: PDF report generation

## 3. Open the Project

Open PowerShell and move to the project directory:

```powershell
cd C:\Users\Tharun\.vscode\work\IDS_Project
```

## 4. Create a Virtual Environment

Create the environment once:

```powershell
python -m venv .venv
```

Activate it:

```powershell
.\.venv\Scripts\Activate.ps1
```

If PowerShell blocks activation, run:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned
.\.venv\Scripts\Activate.ps1
```

When activation succeeds, the terminal prompt normally shows `(.venv)`.

## 5. Install Dependencies

Install the project dependencies:

```powershell
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

Verify the important packages:

```powershell
python -c "import flask, scapy, sklearn, pandas, psutil; print('Dependencies OK')"
```

## 6. Configure Npcap and the Network Interface

Install Npcap with WinPcap compatibility enabled if the project needs that mode.

The active capture interface is configured in:

`packet_capture/live_predictor.py`

The setting is named:

```python
NETWORK_INTERFACE
```

If Scapy reports that the interface cannot be opened, identify the correct Npcap interface and update this setting.

The interface must be available before starting live capture.

## 7. Start the Flask Dashboard

From the project root, run:

```powershell
python app.py
```

Open the dashboard in a browser:

```text
http://127.0.0.1:5000
```

Keep this terminal running while using the dashboard.

## 8. Start Live Monitoring

In the dashboard:

1. Open the Live Monitoring page.
2. Click Start Scanner.
3. Allow the scanner to observe traffic.
4. Watch the live flow table and alerts.
5. Open the dashboard pages to review traffic statistics and threat categories.

The scanner captures packets in short intervals. Completed flows are periodically evaluated. When the scanner is stopped, remaining flows are finalized and evaluated.

## 9. Stop Live Monitoring

Use the Stop Scanner control in the dashboard.

The scanner finalizes active flows before stopping so that pending traffic is not discarded.

Do not close the Flask terminal before stopping the scanner.

## 10. End-to-End Processing Flow

The project processes traffic through the following sequence:

```text
Network packet
    |
    v
Scapy capture
    |
    v
Packet callback
    |
    v
Flow key and flow aggregation
    |
    v
Protocol, duration, byte, and connection-context features
    |
    v
Random Forest attack probability
    |
    +--> C2 beacon detector
    |
    +--> DNS tunneling detector
    |
    +--> Data exfiltration detector
    |
    v
Unified risk engine
    |
    v
Threat type, severity, risk score, and final prediction
    |
    +--> Dashboard API
    |
    +--> live_predictions.csv
    |
    +--> live_latency.csv
    |
    +--> live_runtime.csv
```

## 11. Live Feature Flow

For each completed flow, the live predictor calculates:

- `duration`: elapsed flow time
- `protocol_type`: broad protocol encoding compatible with the model
- `src_bytes`: bytes sent from the source direction
- `dst_bytes`: bytes sent from the destination direction
- `count`: recent connections to the same destination host within a two-second context window

The live `count` feature is intentionally separated from packet count. Packet count is retained as an operational flow statistic but is not used as the NSL-KDD `count` feature.

## 12. Machine-Learning Prediction

The Random Forest receives the five live-compatible features and produces an attack probability.

The configured threshold converts the probability into an initial normal or attack decision.

The final result can be changed by the risk engine when behavioral detectors or host history provide additional evidence.

## 13. Behavioral Detection

### C2 detector

Checks for repeated connections with:

- Regular timing
- Low jitter
- Recurring connections
- Small heartbeat-like payloads

### DNS tunneling detector

Checks DNS names for:

- High entropy
- Excessive length
- Long labels
- Hex, Base32, or Base64-like patterns
- Suspicious subdomain structure

### Exfiltration detector

Checks for:

- Large outbound transfers
- Upload-to-download imbalance
- High transfer velocity
- Cumulative outbound bursts

## 14. Risk Engine

The risk engine combines:

- Random Forest probability
- Behavioral detector confidence
- Repeated suspicious observations
- Source and destination traffic volume
- Packet count
- Host history

It produces:

- Risk score from 0 to 100
- Severity level
- Threat type
- Final prediction
- Explanatory details

## 15. Generated Data Files

### Prediction log

```text
data/live_predictions.csv
```

Contains flow predictions, confidence, threat type, severity, and risk score.

### Latency log

```text
data/live_latency.csv
```

Contains:

- Capture-to-alert latency
- Prediction-processing latency

This file is created after completed live flows are evaluated.

### Runtime log

```text
data/live_runtime.csv
```

Contains:

- Session elapsed time
- Packets seen
- Flows predicted
- Packets per second
- CPU usage
- Resident memory usage

This file is created during a live scanner session.

## 16. Run the Research Evaluation

Run the evaluation from the project root:

```powershell
python evaluation\evaluate_ids.py --output reports\evaluation_results.json
```

The evaluator performs:

- Majority baseline comparison
- Logistic Regression comparison
- Decision Tree comparison
- Random Forest comparison
- MLP neural baseline comparison
- Production versus experimental Random Forest reproduction
- Threshold analysis from 0.30 to 0.60
- C2 detector evaluation
- DNS tunneling evaluation
- Exfiltration evaluation
- Risk-engine ablation
- Synthetic runtime benchmark
- Live latency summary, when available
- Live CPU, memory, packet-rate, and flow summary, when available

The report is written to:

```text
reports/evaluation_results.json
```

## 17. Optional External Dataset Evaluation

An external CSV can be evaluated if it contains these columns:

```text
duration, protocol_type, src_bytes, dst_bytes, count, label
```

Run:

```powershell
python evaluation\evaluate_ids.py --external-csv path\to\external_dataset.csv
```

The external dataset must have compatible feature meanings and labels. A dataset with incompatible features must not be presented as a directly comparable benchmark.

## 18. Generate a PDF Report

The report generator reads the live prediction log and creates a PDF report.

Run:

```powershell
python report\generate_report.py
```

Generated reports are stored under:

```text
reports\generated
```

## 19. Research Status

The research status matrix is available at:

```text
reports/research_status.md
```

It documents:

- What has been implemented
- What was evaluated offline
- What was tested only in controlled fixtures
- What still requires real network evidence
- Which research claims are currently supported
- Which novelty or superiority claims must be avoided

## 20. Current Evidence Boundaries

The project currently supports:

- An implemented real-time IDS architecture
- Random Forest evaluation on NSL-KDD
- Conventional and neural baseline comparisons
- Controlled detector tests
- Controlled risk-engine ablation
- Synthetic processing benchmarks
- Live telemetry instrumentation

The project does not yet prove:

- Production-level detector accuracy
- Real-world live-network accuracy
- Sustained production throughput
- Packet-loss performance under load
- Generalization to a contemporary dataset
- Superiority over CNN-LSTM
- Statistical significance of the small experimental RF improvement

Offline NSL-KDD results must remain separate from live-network performance claims.

## 21. Recommended Run Order

For a complete evaluation session:

1. Activate `.venv`.
2. Install dependencies.
3. Verify Npcap and the configured interface.
4. Start `app.py`.
5. Open `http://127.0.0.1:5000`.
6. Start Live Monitoring.
7. Generate representative traffic during the capture session.
8. Stop Live Monitoring.
9. Confirm that `data/live_latency.csv` and `data/live_runtime.csv` contain samples.
10. Run `evaluation\evaluate_ids.py`.
11. Review `reports\evaluation_results.json`.
12. Record the capture duration, traffic rate, interface, CPU, memory, latency, and sample count in the research paper.

## 22. Troubleshooting

### Flask page does not open

Check that `app.py` is still running and open:

```text
http://127.0.0.1:5000
```

### Scapy interface error

Update `NETWORK_INTERFACE` in `packet_capture/live_predictor.py` to the correct Npcap interface.

### Permission error during capture

Run PowerShell with appropriate permissions and verify that Npcap is installed.

### No live CSV files are created

Confirm that:

- The scanner was started from the dashboard.
- The configured interface received traffic.
- The scanner ran long enough for flows to complete.
- The scanner was stopped normally so active flows could be finalized.

### No latency or runtime samples

The evaluation script cannot invent live measurements. It reports no samples until an actual capture session writes telemetry.

## 23. Stop Everything

Stop the scanner from the dashboard first.

Then stop Flask in PowerShell with:

```text
CTRL+C
```

Deactivate the virtual environment:

```powershell
deactivate
```
