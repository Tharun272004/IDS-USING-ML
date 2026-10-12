# Research Status: Real-Time Network Intrusion Detection System

This status separates implemented capabilities, offline benchmark results, controlled experiments, and evidence from real network traffic. It is intended to prevent unsupported novelty or superiority claims.

## Status Matrix

| Experiment | Current status | Evidence available | Does demonstrate | Does not demonstrate | Next action |
|---|---|---|---|---|---|
| Majority-class baseline | Implemented | `evaluation_results.json` | Simple reference baseline | Improvement over meaningful ML baselines | Report identical test-set metrics |
| Logistic Regression | Implemented | `evaluation_results.json` | Linear-classifier comparison | Statistical superiority of RF | Report all metrics on the same split |
| Decision Tree | Implemented | `evaluation_results.json` | Single-tree comparison | That an ensemble is necessarily better | Report all metrics under the same threshold policy |
| Two-hidden-layer MLP | Implemented | `evaluation_results.json` | Basic neural comparison | Superiority over CNN-LSTM | Report reproducible metrics; add CNN-LSTM only if required |
| Production Random Forest | Reproduced | Accuracy 75.59%, precision 95.94%, recall 59.64%, F1 73.56%; confusion matrix [[9387, 324], [5179, 7654]] | Reproduction of the offline NSL-KDD baseline | Live accuracy, unseen-environment performance, or model superiority | Preserve the official test protocol |
| Experimental Random Forest | Reproduced | Accuracy 75.66%, precision 95.95%, recall 59.76%, F1 73.65% | Small improvement over the reported baseline | Meaningful or statistically significant improvement | Repeat across seeds if significance is claimed |
| Threshold analysis | Implemented | Thresholds 0.30 through 0.60 with precision, recall, F1, FPR, and confusion matrices | Precision-recall trade-offs | That a threshold is optimal in deployment | Select using validation data only |
| C2 detector | Limited controlled fixtures | Precision 1.00, recall 1.00, F1 1.00, FPR 0.00; detection delay 20 seconds | Correct behavior on supplied beacon and irregular-traffic cases | General C2 accuracy or production false-alarm rate | Expand varied beacon intervals and labeled traffic |
| DNS tunneling detector | Limited controlled fixtures | Precision 1.00, recall 1.00, F1 1.00, FPR 0.00 | Correct behavior on supplied tunnel and ordinary-query cases | Reliable detection across diverse DNS traffic | Test legitimate long and encoded domains |
| Exfiltration detector | Limited controlled fixtures | Precision 1.00, recall 1.00, F1 1.00, FPR 0.00 | Correct behavior on supplied high-volume and browsing cases | Detection of slow or low-volume exfiltration | Add varied transfer sizes, rates, and benign backups |
| Risk-engine ablation | Preliminary controlled result | ML-only FPR 0.50; full risk-engine FPR 0.00; hidden genuine attacks 0 | Selected-case prioritization and dampening behavior | Operational false-positive reduction | Expand identical labeled cases across all modes |
| Synthetic runtime benchmark | Completed controlled benchmark | Approximately 10 flow evaluations/second; median approximately 99 ms/flow | Processing performance in the benchmark setup | End-to-end live capacity or real-time guarantee | Test realistic packet loads and resource usage |
| Live capture-to-alert latency | Real measurements collected; session isolation pending | 722 latency rows; capture-to-alert p50 5722.72 ms, p95 7207.46 ms, p99 9736.47 ms; processing p50 24.68 ms, p95 88.76 ms | Shows observed latency in live operation | A clean single-session latency target or service guarantee | Add session IDs, isolate a controlled run, and report traffic conditions |
| Live CPU and memory use | Real measurements collected; session isolation pending | 2,173 runtime rows; CPU p50 1.50%, p95 12.00%, max 92.80%; RSS p50 221.75 MB, max 225.09 MB; packet-rate p95 152.59 packets/s | Shows observed resource use and traffic rate | Resource requirements under a clean controlled load | Add session IDs and measure packet loss under a documented load |
| External-dataset generalization | Not evaluated | Optional compatible CSV input is supported | Evaluation framework can accept labeled external data | Cross-dataset robustness or distribution-shift performance | Evaluate a contemporary labeled dataset |
| Feature compatibility | Implementation validation passed; live validation pending | Automated packet-path check observed connection counts `[1, 1, 2]` for the two-second context and packet counts `[1, 1, 1]`; live `count` tracks destination-host connections | Removes the documented packet-count substitution and verifies expiry behavior | That semantic alignment alone proves live-model validity | Validate the feature under controlled real traffic and compare with NSL-KDD expectations |
| CNN-LSTM comparison | Not implemented | No CNN-LSTM result | Direct comparison is unavailable | Superiority over a CNN-LSTM paper | Implement a fair baseline or scope claims accordingly |
| Dashboard, CSV storage, and reports | Implemented | Flask endpoints, prediction storage, and report generation | Monitoring and investigation functionality | Algorithm accuracy or improved analyst outcomes | Test reliability and data integrity separately |

## Evidence Maturity

### Implemented capabilities

Random Forest inference, Scapy packet processing, C2/DNS/exfiltration detectors, risk scoring, Flask monitoring, CSV storage, and report generation are implemented.

### Offline NSL-KDD evaluation

The production and experimental Random Forest metrics have been reproduced. Attack recall remains approximately 60%, so missed attacks remain an important weakness. These are offline benchmark results, not live-network detection accuracy.

### Controlled experiments

Small detector fixtures, risk-engine ablation cases, and synthetic runtime measurements provide preliminary evidence that selected components behave as intended. They do not estimate production prevalence, traffic drift, or operational false-alarm rates.

### Real-world validation

Real capture-to-alert measurements and resource telemetry have now been collected. The current files contain records from multiple sessions between 17:23 and 22:10, so the reported percentiles are observed live-system measurements across the collected records, not results from one controlled 30-second benchmark. Clean isolated benchmarking, packet-loss measurement, broad detector evaluation, and external-dataset validation remain pending.

## Updated Research Status

| Research area | Updated status |
|---|---|
| IDS architecture and components | Implemented |
| NSL-KDD model evaluation | Completed for the reported configurations |
| Live feature-count correction | Validated through packet-processing tests |
| Controlled detector and risk-engine tests | Completed on limited fixtures |
| Synthetic runtime benchmark | Completed |
| Real live latency and resource telemetry | Collected |
| Clean, isolated live benchmark | Pending |
| Packet-loss measurement | Pending |
| Independent contemporary dataset | Pending |
| CNN-LSTM comparison | Pending |

## Live Telemetry Limitations

- The telemetry files are append-only and combine records from multiple sessions between 17:23 and 22:10.
- Current percentiles describe observed live-system behavior across collected records, not one controlled 30-second test.
- Packet loss has not been reliably measured by the current Scapy capture loop.
- Low median CPU does not rule out transient bottlenecks; the maximum observed CPU value was 92.8%.
- A clean benchmark requires session identifiers or rotated telemetry files before capture begins.

## Priority Actions

1. Clear or rotate telemetry files before a new capture run.
2. Run several isolated sessions with documented duration, interface, and traffic load.
3. Measure packet loss using a reliable capture-drop counter or independent method.
4. Separate flow-aggregation delay, prediction-processing time, and total capture-to-alert latency.
5. Repeat under different traffic loads and report each session's sample count and percentiles.
6. Evaluate an independent contemporary labeled dataset with documented feature mapping and class definitions.

## Claim Boundary

The current evidence supports describing the implemented architecture and reporting the reproduced offline Random Forest benchmark. It does not support claims that the complete system has higher real-world recall, reduces operational false positives, meets a real-time service target, generalizes to another dataset, or outperforms CNN-LSTM.
