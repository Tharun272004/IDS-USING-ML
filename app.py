from flask import (
    Flask,
    render_template,
    jsonify,
    request,
    send_file
)

import os
import csv
import json
import sys
import subprocess
import threading
import time
import io
from datetime import datetime

from report.generate_report import generate_report


# ============================================================
# FLASK APPLICATION
# ============================================================

app = Flask(__name__)


# ============================================================
# PROJECT PATHS
# ============================================================

BASE_DIR = os.path.dirname(
    os.path.abspath(__file__)
)

DATA_DIR = os.path.join(
    BASE_DIR,
    "data"
)

LIVE_DATA_FILE = os.path.join(
    DATA_DIR,
    "live_predictions.csv"
)

CONTROL_FILE = os.path.join(
    DATA_DIR,
    "ids_control.txt"
)

SCANNER_SCRIPT = os.path.join(
    BASE_DIR,
    "packet_capture",
    "live_predictor.py"
)


# ============================================================
# SCANNER STATE
# ============================================================

scanner_process = None

live_session_start_index = None

scanner_lock = threading.Lock()


# ============================================================
# HELPER FUNCTIONS
# ============================================================

def scanner_is_running():

    global scanner_process

    with scanner_lock:

        if scanner_process is None:
            return False

        try:

            if scanner_process.poll() is None:
                return True

        except Exception:
            pass

        scanner_process = None

        return False


def clear_control_file():

    os.makedirs(
        DATA_DIR,
        exist_ok=True
    )

    try:

        if os.path.exists(
            CONTROL_FILE
        ):

            os.remove(
                CONTROL_FILE
            )

        return True, None

    except OSError as error:

        return False, str(error)


def read_csv_rows():

    if not os.path.exists(
        LIVE_DATA_FILE
    ):

        return []

    rows = []

    try:

        with open(
            LIVE_DATA_FILE,
            "r",
            encoding="utf-8",
            newline=""
        ) as file:

            reader = csv.DictReader(
                file
            )

            for row in reader:
                # Handle extra columns placed under key None by DictReader
                extra = row.pop(None, None)

                sanitized = {}
                for k, v in row.items():
                    if k is not None:
                        sanitized[str(k)] = v if v is not None else ""

                # If extra columns exist from 14-column format:
                if extra and isinstance(extra, list):
                    if len(extra) >= 1 and not sanitized.get("threat_type"):
                        sanitized["threat_type"] = extra[0]
                    if len(extra) >= 2 and not sanitized.get("severity"):
                        sanitized["severity"] = extra[1]
                    if len(extra) >= 3 and not sanitized.get("risk_score"):
                        sanitized["risk_score"] = extra[2]

                # Provide defaults for new columns when missing from old data
                if not sanitized.get("threat_type"):
                    sanitized["threat_type"] = (
                        "ANOMALOUS_FLOW"
                        if sanitized.get("prediction") == "ATTACK"
                        else "NORMAL"
                    )
                if not sanitized.get("severity"):
                    sanitized["severity"] = (
                        "HIGH"
                        if sanitized.get("prediction") == "ATTACK"
                        else "LOW"
                    )
                if not sanitized.get("risk_score"):
                    sanitized["risk_score"] = sanitized.get(
                        "attack_probability", "0"
                    )
                rows.append(sanitized)

    except (
        OSError,
        csv.Error
    ):

        return []

    return rows


def matches_attack_type(row, attack_type):

    selected_type = attack_type.strip().lower()
    prediction = row.get("prediction", "").strip().lower()
    threat_type = row.get("threat_type", "").strip().lower()

    if selected_type in ("normal", "normal_traffic"):
        return prediction == "normal"
    if selected_type in ("attack", "attacks"):
        return prediction == "attack"

    return threat_type == selected_type


# ============================================================
# HOME
# ============================================================

@app.route("/")
def home():

    return render_template(
        "index.html"
    )


# ============================================================
# DASHBOARD
# ============================================================

@app.route("/dashboard")
def dashboard():

    return render_template(
        "dashboard.html"
    )


# ============================================================
# LIVE MONITORING PAGE
# ============================================================

@app.route("/live-monitoring")
@app.route("/scanner")
def live_monitoring():

    return render_template(
        "live_monitoring.html"
    )


# ============================================================
# OVERVIEW PAGE (ML Models, Comparisons, Training Details)
# ============================================================

@app.route("/overview")
@app.route("/model-performance")
def overview():

    performance_file = os.path.join(
        BASE_DIR,
        "models",
        "model_metrics.json"
    )

    performance = {}

    if os.path.exists(
        performance_file
    ):

        try:

            with open(
                performance_file,
                "r",
                encoding="utf-8"
            ) as file:

                performance = json.load(
                    file
                )

        except (
            json.JSONDecodeError,
            OSError
        ):

            performance = {}

    return render_template(
        "overview.html",
        performance=performance
    )


# ============================================================
# REPORTS PAGE
# ============================================================

@app.route("/reports")
def reports_page():

    return render_template(
        "reports.html"
    )


# ============================================================
# ATTACK DETAILS
# ============================================================

@app.route("/attack-details")
def attack_details():

    attack_time = request.args.get(
        "time"
    )

    attack_source = request.args.get(
        "source"
    )

    attack = None

    if (
        attack_time
        and
        attack_source
        and
        os.path.exists(
            LIVE_DATA_FILE
        )
    ):

        rows = read_csv_rows()

        for row in rows:

            if (
                row.get("prediction") == "ATTACK"
                and
                row.get("time") == attack_time
                and
                row.get("source") == attack_source
            ):

                attack = row

                break

    return render_template(
        "attack_details.html",
        attack=attack
    )


# ============================================================
# LIVE PREDICTIONS API
# ============================================================

@app.route("/api/predictions")
def predictions():

    rows = read_csv_rows()

    start_index = request.args.get("start_index", type=int)
    if start_index is not None:
        rows = rows[max(0, start_index):] if start_index >= 0 else []

    return jsonify(
        rows[-50:]
    )


# ============================================================
# STATISTICS API
# ============================================================

@app.route("/api/stats")
def stats():

    rows = read_csv_rows()

    start_index = request.args.get("start_index", type=int)
    if start_index is not None:
        rows = rows[max(0, start_index):] if start_index >= 0 else []

    normal = 0
    attack = 0

    for row in rows:

        prediction = row.get(
            "prediction",
            ""
        )

        if prediction == "NORMAL":

            normal += 1

        elif prediction == "ATTACK":

            attack += 1

    total = normal + attack

    attack_rate = 0

    if total > 0:

        attack_rate = (
            attack / total
        ) * 100

    return jsonify({

        "normal": normal,

        "attack": attack,

        "total": total,

        "attack_rate": round(
            attack_rate,
            2
        )

    })


@app.route("/api/live-monitoring")
def live_monitoring_data():

    rows = read_csv_rows()
    start_index = request.args.get("start_index", type=int)

    if start_index is not None:
        rows = rows[max(0, start_index):] if start_index >= 0 else []

    normal = sum(1 for row in rows if row.get("prediction") == "NORMAL")
    attack = sum(1 for row in rows if row.get("prediction") == "ATTACK")
    total = normal + attack

    return jsonify({
        "normal": normal,
        "attack": attack,
        "total": total,
        "attack_rate": round((attack / total * 100), 2) if total else 0,
        "predictions": rows[-50:]
    })


# ============================================================
# CHART DATA API
# ============================================================

@app.route("/api/chart-data")
def chart_data():

    rows = read_csv_rows()

    normal = 0
    attack = 0

    protocol_counts = {}
    threat_type_counts = {}
    attack_timeline = {}

    for row in rows:

        prediction = row.get(
            "prediction",
            ""
        )

        protocol = row.get(
            "protocol",
            "other"
        )

        if not protocol:
            protocol = "other"

        protocol = protocol.lower()

        # ----------------------------------------------------
        # NORMAL / ATTACK
        # ----------------------------------------------------

        if prediction == "NORMAL":

            normal += 1

        elif prediction == "ATTACK":

            attack += 1

            threat_type = row.get("threat_type", "ANOMALOUS_FLOW")
            if not threat_type or threat_type == "NORMAL":
                threat_type = "ANOMALOUS_FLOW"
            threat_type_counts[threat_type] = (
                threat_type_counts.get(threat_type, 0) + 1
            )

            attack_time = row.get(
                "time",
                ""
            )

            if attack_time:

                minute = attack_time[:16]

                attack_timeline[
                    minute
                ] = (
                    attack_timeline.get(
                        minute,
                        0
                    ) + 1
                )

        # ----------------------------------------------------
        # PROTOCOL
        # ----------------------------------------------------

        protocol_counts[
            protocol
        ] = (
            protocol_counts.get(
                protocol,
                0
            ) + 1
        )

    timeline = []

    for time_value, count in sorted(
        attack_timeline.items()
    ):

        timeline.append({

            "time": time_value,

            "attacks": count

        })

    return jsonify({

        "normal": normal,

        "attack": attack,

        "protocols": protocol_counts,

        "threat_types": threat_type_counts,

        "timeline": timeline[-20:]

    })


# ============================================================
# SCANNER DATA API
# ============================================================

@app.route("/api/scanner")
def scanner_api():

    rows = read_csv_rows()

    results = []

    normal = 0
    attack = 0

    for row in rows:

        prediction = row.get(
            "prediction",
            ""
        )

        if prediction == "NORMAL":

            normal += 1

        elif prediction == "ATTACK":

            attack += 1

        results.append({

            "time": row.get(
                "time",
                ""
            ),

            "prediction": prediction,

            "source": row.get(
                "source",
                ""
            ),

            "destination": row.get(
                "destination",
                ""
            ),

            "protocol": row.get(
                "protocol",
                ""
            ),

            "duration": row.get(
                "duration",
                ""
            ),

            "src_bytes": row.get(
                "src_bytes",
                ""
            ),

            "dst_bytes": row.get(
                "dst_bytes",
                ""
            ),

            "packet_count": row.get(
                "packet_count",
                ""
            ),

            "confidence": row.get(
                "confidence",
                ""
            ),

            "attack_probability": row.get(
                "attack_probability",
                ""
            )

        })

    return jsonify({

        "normal": normal,

        "attack": attack,

        "total": normal + attack,

        "results": results[-20:]

    })


# ============================================================
# PACKET HISTORY
# ============================================================

@app.route("/api/packet-history")
def packet_history():

    rows = read_csv_rows()

    return jsonify({

        "total": len(rows),

        "packets": rows

    })


# ============================================================
# PACKET HISTORY - LATEST
# ============================================================

@app.route("/api/packet-history/latest")
def latest_packet_history():

    limit = request.args.get(
        "limit",
        default=100,
        type=int
    )

    limit = max(
        1,
        min(
            limit,
            1000
        )
    )

    rows = read_csv_rows()

    start_index = request.args.get("start_index", type=int)
    if start_index is not None:
        rows = rows[max(0, start_index):] if start_index >= 0 else []

    return jsonify({

        "total": len(rows),

        "packets": rows[-limit:]

    })


# ============================================================
# SECURITY REPORT (PDF Download with optional date filter)
# ============================================================

@app.route("/generate-report")
def generate_security_report():

    start_time = request.args.get("start_time", "").strip() or None
    end_time = request.args.get("end_time", "").strip() or None
    attack_type = request.args.get("attack_type", "").strip() or None

    try:

        report_path = generate_report(
            start_time=start_time,
            end_time=end_time,
            attack_type=attack_type
        )

        return send_file(

            report_path,

            as_attachment=True,

            download_name=os.path.basename(
                report_path
            ),

            mimetype="application/pdf"

        )

    except Exception as error:

        print(
            "Report generation error:",
            error
        )

        return jsonify({

            "success": False,

            "message": str(error)

        }), 500


# ============================================================
# EXPORT SCANNED CSV DATA (Filtered by date range)
# ============================================================

@app.route("/api/export-csv")
def export_scanned_csv():

    start_time = request.args.get("start_time", "").strip() or None
    end_time = request.args.get("end_time", "").strip() or None
    attack_type = request.args.get("attack_type", "").strip().lower() or None

    rows = read_csv_rows()

    filtered_rows = []
    for row in rows:
        row_time = row.get("time", "").strip()
        if start_time and row_time and row_time < start_time:
            continue
        if end_time and row_time and row_time > end_time:
            continue
        if attack_type and not matches_attack_type(row, attack_type):
            continue
        filtered_rows.append(row)

    if not filtered_rows:
        fieldnames = [
            "time", "source", "destination", "protocol",
            "duration", "src_bytes", "dst_bytes", "packet_count",
            "prediction", "confidence", "attack_probability",
            "threat_type", "severity", "risk_score"
        ]
    else:
        fieldnames = list(filtered_rows[0].keys())

    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=fieldnames)
    writer.writeheader()
    for r in filtered_rows:
        writer.writerow(r)

    csv_data = output.getvalue()
    output.close()

    filename = f"IDS_Scanned_Data_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"

    return send_file(
        io.BytesIO(csv_data.encode("utf-8")),
        mimetype="text/csv",
        as_attachment=True,
        download_name=filename
    )


# ============================================================
# REPORT PREVIEW STATS (Filtered by date range)
# ============================================================

@app.route("/api/report-stats")
def report_stats():

    start_time = request.args.get("start_time", "").strip() or None
    end_time = request.args.get("end_time", "").strip() or None
    attack_type = request.args.get("attack_type", "").strip().lower() or None

    rows = read_csv_rows()

    total = 0
    normal = 0
    attack = 0
    threat_counts = {}
    protocol_counts = {}

    for row in rows:
        row_time = row.get("time", "").strip()
        if start_time and row_time and row_time < start_time:
            continue
        if end_time and row_time and row_time > end_time:
            continue
        if attack_type and not matches_attack_type(row, attack_type):
            continue

        total += 1
        pred = row.get("prediction", "")
        if pred == "ATTACK":
            attack += 1
            t_type = row.get("threat_type", "ANOMALOUS_FLOW") or "ANOMALOUS_FLOW"
            threat_counts[t_type] = threat_counts.get(t_type, 0) + 1
        elif pred == "NORMAL":
            normal += 1

        proto = row.get("protocol", "other") or "other"
        protocol_counts[proto] = protocol_counts.get(proto, 0) + 1

    attack_rate = round((attack / total * 100), 2) if total > 0 else 0.0

    return jsonify({
        "total": total,
        "normal": normal,
        "attack": attack,
        "attack_rate": attack_rate,
        "threat_types": threat_counts,
        "protocols": protocol_counts,
        "start_time": start_time or "Earliest",
        "end_time": end_time or "Latest"
    })


# ============================================================
# ATTACK ALERT API
# ============================================================

@app.route("/api/alerts")
def alerts():

    rows = read_csv_rows()

    attack_rows = []

    for row in rows:

        if row.get(
            "prediction"
        ) == "ATTACK":

            attack_rows.append(
                row
            )

    return jsonify(
        attack_rows[-20:]
    )


# ============================================================
# SCANNER STATUS
# ============================================================

@app.route("/api/scanner/status")
def scanner_status():

    active = scanner_is_running()

    return jsonify({

        "active": active,

        "resumable": live_session_start_index is not None,

        "session_start_index": (
            live_session_start_index
            if live_session_start_index is not None
            else -1
        ),

        "status":
            "SCANNING"
            if active
            else
            "STOPPED"

    })


# ============================================================
# START SCANNING
# ============================================================

@app.route(
    "/api/scanner/start",
    methods=["POST"]
)
def start_scanning(reset_session=True):

    global scanner_process
    global live_session_start_index

    # --------------------------------------------------------
    # LOCK
    #
    # Prevent two simultaneous HTTP requests from creating
    # two scanner processes.
    # --------------------------------------------------------

    with scanner_lock:

        # ----------------------------------------------------
        # Existing scanner?
        # ----------------------------------------------------

        if scanner_process is not None:

            try:

                if scanner_process.poll() is None:

                    return jsonify({

                        "success": False,

                        "message":
                            "IDS scanning is already running.",

                        "active": True

                    }), 409

            except Exception:

                pass

            scanner_process = None

        # ----------------------------------------------------
        # Validate scanner file.
        # ----------------------------------------------------

        if not os.path.isfile(
            SCANNER_SCRIPT
        ):

            return jsonify({

                "success": False,

                "message":
                    (
                        "Scanner file not found: "
                        f"{SCANNER_SCRIPT}"
                    ),

                "active": False

            }), 500

        # ----------------------------------------------------
        # Make sure data directory exists.
        # ----------------------------------------------------

        try:

            os.makedirs(
                DATA_DIR,
                exist_ok=True
            )

        except OSError as error:

            return jsonify({

                "success": False,

                "message": str(error),

                "active": False

            }), 500

        # ----------------------------------------------------
        # Remove previous STOP request.
        # ----------------------------------------------------

        if reset_session:
            live_session_start_index = len(read_csv_rows())

        ok, error = clear_control_file()

        if not ok:

            return jsonify({

                "success": False,

                "message":
                    (
                        "Unable to clear scanner "
                        f"control file: {error}"
                    ),

                "active": False

            }), 500

        # ----------------------------------------------------
        # Windows process creation.
        #
        # CREATE_NEW_PROCESS_GROUP prevents the scanner from
        # becoming tied to Flask's console process.
        # ----------------------------------------------------

        creation_flags = 0

        if os.name == "nt":

            creation_flags = (
                subprocess.CREATE_NEW_PROCESS_GROUP
            )

        # ----------------------------------------------------
        # Start ONLY live_predictor.py.
        #
        # This does NOT execute app.py.
        # ----------------------------------------------------

        try:

            scanner_process = subprocess.Popen(

                [
                    sys.executable,
                    SCANNER_SCRIPT
                ],

                cwd=BASE_DIR,

                stdin=subprocess.DEVNULL,

                stdout=subprocess.DEVNULL,

                stderr=subprocess.DEVNULL,

                creationflags=creation_flags,

                close_fds=False

            )

        except Exception as error:

            scanner_process = None

            return jsonify({

                "success": False,

                "message":
                    (
                        "Unable to start IDS scanner: "
                        f"{error}"
                    ),

                "active": False

            }), 500

        # ----------------------------------------------------
        # Save PID.
        #
        # This is only for information/debugging and is NOT
        # used to launch anything.
        # ----------------------------------------------------

        scanner_pid = scanner_process.pid

        # ----------------------------------------------------
        # Give process time to initialize.
        # ----------------------------------------------------

        time.sleep(1.0)

        # ----------------------------------------------------
        # Check for immediate crash.
        # ----------------------------------------------------

        if scanner_process.poll() is not None:

            return_code = (
                scanner_process.returncode
            )

            scanner_process = None

            return jsonify({

                "success": False,

                "message":
                    (
                        "IDS scanner stopped immediately. "
                        f"Exit code: {return_code}"
                    ),

                "active": False

            }), 500

        return jsonify({

            "success": True,

            "message":
                "IDS scanning started.",

            "active": True,

            "pid": scanner_pid,

            "session_start_index": live_session_start_index

        })


# ============================================================
# STOP SCANNING
# ============================================================

@app.route(
    "/api/scanner/stop",
    methods=["POST"]
)
def stop_scanning():

    global scanner_process

    with scanner_lock:

        # ----------------------------------------------------
        # No scanner known to Flask.
        # ----------------------------------------------------

        if scanner_process is None:

            return jsonify({

                "success": True,

                "message":
                    "IDS scanning is already stopped.",

                "active": False,

                "resumable": live_session_start_index is not None

            })

        # ----------------------------------------------------
        # Scanner already stopped.
        # ----------------------------------------------------

        try:

            if scanner_process.poll() is not None:

                scanner_process = None

                return jsonify({

                    "success": True,

                    "message":
                        "IDS scanner is already stopped.",

                    "active": False,

                    "resumable": live_session_start_index is not None

                })

        except Exception:

            scanner_process = None

            return jsonify({

                "success": False,

                "message":
                    "IDS scanner process is unavailable.",

                "active": False

            }), 400

        # ----------------------------------------------------
        # Create STOP request.
        # ----------------------------------------------------

        try:

            os.makedirs(
                DATA_DIR,
                exist_ok=True
            )

            with open(
                CONTROL_FILE,
                "w",
                encoding="utf-8"
            ) as file:

                file.write(
                    "STOP"
                )

        except OSError as error:

            return jsonify({

                "success": False,

                "message":
                    str(error),

                "active": True

            }), 500

        # ----------------------------------------------------
        # Wait for live_predictor.py to stop normally.
        # ----------------------------------------------------

        try:

            scanner_process.wait(
                timeout=20
            )

        except subprocess.TimeoutExpired:

            try:

                scanner_process.kill()

                scanner_process.wait(
                    timeout=5
                )

            except Exception:

                pass

        # ----------------------------------------------------
        # Clear Flask's process reference.
        # ----------------------------------------------------

        scanner_process = None

        # ----------------------------------------------------
        # Remove STOP request.
        # ----------------------------------------------------

        try:

            if os.path.exists(
                CONTROL_FILE
            ):

                os.remove(
                    CONTROL_FILE
                )

        except OSError:

            pass

        return jsonify({

            "success": True,

            "message":
                "IDS scanning stopped.",

            "active": False

        })


# ============================================================
# CONTINUE SCANNING
# ============================================================

@app.route(
    "/api/scanner/continue",
    methods=["POST"]
)
def continue_scanning():

    return start_scanning(reset_session=False)


# ============================================================
# OLD SESSION STATUS COMPATIBILITY
# ============================================================

@app.route("/api/session/status")
def old_session_status():

    active = scanner_is_running()

    return jsonify({

        "active": active,

        "session": None

    })


# ============================================================
# OLD SESSION HISTORY COMPATIBILITY
# ============================================================

@app.route("/api/session/history")
def old_session_history():

    return jsonify({

        "sessions": []

    })


# ============================================================
# APPLICATION START
# ============================================================

if __name__ == "__main__":

    # --------------------------------------------------------
    # IMPORTANT:
    #
    # No debug mode.
    # No Flask reloader.
    # No threaded development reloader.
    #
    # Flask itself is started exactly once.
    # --------------------------------------------------------

    app.run(

        host="127.0.0.1",

        port=5000,

        debug=False,

        use_reloader=False,

        threaded=True

    )