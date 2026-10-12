import os
import csv
from datetime import datetime

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    PageBreak
)


# ============================================================
# PATHS
# ============================================================

BASE_DIR = os.path.dirname(
    os.path.dirname(
        os.path.abspath(__file__)
    )
)

LIVE_DATA_FILE = os.path.join(
    BASE_DIR,
    "data",
    "live_predictions.csv"
)

REPORT_DIR = os.path.join(
    BASE_DIR,
    "reports",
    "generated"
)


# ============================================================
# CREATE REPORT DIRECTORY
# ============================================================

os.makedirs(
    REPORT_DIR,
    exist_ok=True
)


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
# LOAD LIVE PREDICTIONS
# ============================================================

def load_predictions(start_time=None, end_time=None, attack_type=None):

    predictions = []

    if not os.path.exists(LIVE_DATA_FILE):

        print(
            "Warning: live_predictions.csv not found."
        )

        return predictions

    try:

        with open(
            LIVE_DATA_FILE,
            "r",
            encoding="utf-8"
        ) as file:

            reader = csv.DictReader(file)

            for row in reader:
                # Filter by start_time and end_time if provided
                row_time = row.get("time", "").strip()
                if start_time and row_time and row_time < start_time:
                    continue
                if end_time and row_time and row_time > end_time:
                    continue
                if attack_type and not matches_attack_type(row, attack_type):
                    continue

                predictions.append(row)

    except Exception as error:

        print(
            "Warning: Could not load predictions:",
            error
        )

    return predictions


# ============================================================
# LOAD MODEL METRICS
# ============================================================

def load_model_metrics():

    metrics_file = os.path.join(
        BASE_DIR,
        "models",
        "model_metrics.json"
    )

    default_metrics = {

        "algorithm":
            "Random Forest Classifier",

        "accuracy":
            80.96,

        "precision":
            0.93,

        "recall":
            0.72,

        "f1_score":
            0.81,

        "threshold":
            0.30,

        "features": [
            "duration",
            "protocol_type",
            "src_bytes",
            "dst_bytes",
            "count"
        ]
    }

    if not os.path.exists(metrics_file):

        return default_metrics

    try:

        import json

        with open(
            metrics_file,
            "r",
            encoding="utf-8"
        ) as file:

            return json.load(file)

    except Exception as error:

        print(
            "Warning: Could not load model metrics:",
            error
        )

        return default_metrics


# ============================================================
# CALCULATE STATISTICS
# ============================================================

def calculate_statistics(data):

    total = len(data)

    normal = 0
    attacks = 0

    for row in data:

        prediction = row.get(
            "prediction",
            ""
        ).upper()

        if prediction == "NORMAL":
            normal += 1

        elif prediction == "ATTACK":
            attacks += 1

    attack_rate = 0

    if total > 0:
        attack_rate = (
            attacks / total
        ) * 100

    return {
        "total": total,
        "normal": normal,
        "attacks": attacks,
        "attack_rate": attack_rate
    }


# ============================================================
# PROTOCOL STATISTICS
# ============================================================

def protocol_statistics(data):

    protocols = {}

    for row in data:

        protocol = row.get(
            "protocol",
            "unknown"
        ).upper()

        protocols[protocol] = (
            protocols.get(protocol, 0) + 1
        )

    return protocols


# ============================================================
# ATTACK STATISTICS
# ============================================================

def attack_statistics(data):

    attacks = [
        row
        for row in data
        if row.get(
            "prediction",
            ""
        ).upper() == "ATTACK"
    ]

    return attacks


# ============================================================
# PAGE HEADER / FOOTER
# ============================================================

def add_page_number(canvas, document):

    canvas.saveState()

    canvas.setFont(
        "Helvetica",
        8
    )

    canvas.setFillColor(
        colors.grey
    )

    canvas.drawCentredString(
        A4[0] / 2,
        10 * mm,
        f"Real-Time IDS Security Report  |  Page {document.page}"
    )

    canvas.restoreState()


# ============================================================
# GENERATE REPORT
# ============================================================

def generate_report(start_time=None, end_time=None, attack_type=None):

    data = load_predictions(
        start_time=start_time,
        end_time=end_time,
        attack_type=attack_type
    )

    statistics = calculate_statistics(
        data
    )

    protocols = protocol_statistics(
        data
    )

    attacks = attack_statistics(
        data
    )

    model_metrics = load_model_metrics()

    timestamp = datetime.now().strftime(
        "%Y-%m-%d_%H-%M-%S"
    )

    report_path = os.path.join(
        REPORT_DIR,
        f"IDS_Security_Report_{timestamp}.pdf"
    )


    # ========================================================
    # DOCUMENT
    # ========================================================

    document = SimpleDocTemplate(

        report_path,

        pagesize=A4,
        
        rightMargin=18 * mm,
        leftMargin=18 * mm,
        topMargin=18 * mm,
        bottomMargin=18 * mm
    )


    styles = getSampleStyleSheet()


    title_style = ParagraphStyle(

        "ReportTitle",

        parent=styles["Title"],

        fontSize=24,

        leading=30,

        alignment=TA_CENTER,

        textColor=colors.HexColor(
            "#101827"
        ),

        spaceAfter=12
    )


    subtitle_style = ParagraphStyle(

        "Subtitle",

        parent=styles["Normal"],

        fontSize=11,

        alignment=TA_CENTER,

        textColor=colors.HexColor(
            "#667085"
        ),

        spaceAfter=20
    )


    heading_style = ParagraphStyle(

        "SectionHeading",

        parent=styles["Heading2"],

        fontSize=16,

        leading=20,

        textColor=colors.HexColor(
            "#101827"
        ),

        spaceBefore=10,

        spaceAfter=10
    )


    normal_style = ParagraphStyle(

        "NormalText",

        parent=styles["Normal"],

        fontSize=10,

        leading=15,

        textColor=colors.HexColor(
            "#344054"
        )
    )


    # ========================================================
    # STORY
    # ========================================================

    story = []


    # ========================================================
    # TITLE
    # ========================================================

    story.append(
        Spacer(
            1,
            15 * mm
        )
    )

    story.append(
        Paragraph(
            "REAL-TIME INTRUSION<br/>DETECTION SYSTEM",
            title_style
        )
    )

    story.append(
        Paragraph(
            "Machine Learning Network Security Report",
            subtitle_style
        )
    )

    period_str = ""
    if start_time and end_time:
        period_str = f"<br/><b>Reporting Period:</b> {start_time} to {end_time}"
    elif start_time:
        period_str = f"<br/><b>Reporting Period:</b> From {start_time} onwards"
    elif end_time:
        period_str = f"<br/><b>Reporting Period:</b> Up to {end_time}"
    else:
        period_str = "<br/><b>Reporting Period:</b> All Recorded Traffic"

    story.append(
        Paragraph(
            f"<b>Generated:</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{period_str}",
            subtitle_style
        )
    )


    # ========================================================
    # EXECUTIVE SUMMARY
    # ========================================================

    story.append(
        Paragraph(
            "1. Executive Summary",
            heading_style
        )
    )

    summary_text = (

        "This report summarizes the network traffic analyzed "
        "by the Real-Time Intrusion Detection System. The system "
        "uses machine-learning-based classification to identify "
        "network flows as either normal traffic or potential "
        "intrusions."
    )

    story.append(
        Paragraph(
            summary_text,
            normal_style
        )
    )

    story.append(
        Spacer(
            1,
            8
        )
    )


    # ========================================================
    # SUMMARY TABLE
    # ========================================================

    summary_table_data = [

        ["Metric", "Value"],

        [
            "Total Network Flows",
            str(statistics["total"])
        ],

        [
            "Normal Flows",
            str(statistics["normal"])
        ],

        [
            "Detected Attacks",
            str(statistics["attacks"])
        ],

        [
            "Attack Rate",
            f'{statistics["attack_rate"]:.2f}%'
        ]
    ]


    summary_table = Table(

        summary_table_data,

        colWidths=[
            95 * mm,
            65 * mm
        ]
    )


    summary_table.setStyle(
        TableStyle([

            (
                "BACKGROUND",
                (0, 0),
                (-1, 0),
                colors.HexColor(
                    "#101827"
                )
            ),

            (
                "TEXTCOLOR",
                (0, 0),
                (-1, 0),
                colors.white
            ),

            (
                "FONTNAME",
                (0, 0),
                (-1, 0),
                "Helvetica-Bold"
            ),

            (
                "FONTNAME",
                (0, 1),
                (-1, -1),
                "Helvetica"
            ),

            (
                "GRID",
                (0, 0),
                (-1, -1),
                0.5,
                colors.HexColor(
                    "#D0D5DD"
                )
            ),

            (
                "BACKGROUND",
                (0, 1),
                (-1, -1),
                colors.HexColor(
                    "#F8F9FA"
                )
            ),

            (
                "ALIGN",
                (1, 1),
                (1, -1),
                "CENTER"
            ),

            (
                "VALIGN",
                (0, 0),
                (-1, -1),
                "MIDDLE"
            ),

            (
                "TOPPADDING",
                (0, 0),
                (-1, -1),
                8
            ),

            (
                "BOTTOMPADDING",
                (0, 0),
                (-1, -1),
                8
            )
        ])
    )


    story.append(
        summary_table
    )


    # ========================================================
    # MODEL INFORMATION
    # ========================================================

    story.append(
        Paragraph(
            "2. Machine Learning Model",
            heading_style
        )
    )


    model_data = [

    ["Parameter", "Value"],

    [
        "Algorithm",
        model_metrics.get(
            "algorithm",
            "Random Forest Classifier"
        )
    ],

    [
        "Training Features",
        ", ".join(
            model_metrics.get(
                "features",
                []
            )
        )
    ],

    [
        "Classification",
        "Normal / Attack"
    ],

    [
        "Optimized Threshold",
        f'{model_metrics.get("threshold", 0.30):.2f}'
    ],

    [
        "Validation Accuracy",
        f'{model_metrics.get("accuracy", 0):.2f}%'
    ],

    [
        "Attack Precision",
        f'{model_metrics.get("precision", 0):.2f}'
    ],

    [
        "Attack Recall",
        f'{model_metrics.get("recall", 0):.2f}'
    ],

    [
        "Attack F1-Score",
        f'{model_metrics.get("f1_score", 0):.2f}'
    ]
]


    model_table = Table(

        model_data,

        colWidths=[
            65 * mm,
            95 * mm
        ]
    )


    model_table.setStyle(
        TableStyle([

            (
                "BACKGROUND",
                (0, 0),
                (-1, 0),
                colors.HexColor(
                    "#4169E1"
                )
            ),

            (
                "TEXTCOLOR",
                (0, 0),
                (-1, 0),
                colors.white
            ),

            (
                "FONTNAME",
                (0, 0),
                (-1, 0),
                "Helvetica-Bold"
            ),

            (
                "GRID",
                (0, 0),
                (-1, -1),
                0.5,
                colors.HexColor(
                    "#D0D5DD"
                )
            ),

            (
                "VALIGN",
                (0, 0),
                (-1, -1),
                "MIDDLE"
            ),

            (
                "TOPPADDING",
                (0, 0),
                (-1, -1),
                7
            ),

            (
                "BOTTOMPADDING",
                (0, 0),
                (-1, -1),
                7
            )
        ])
    )


    story.append(
        model_table
    )


    # ========================================================
    # PROTOCOL DISTRIBUTION
    # ========================================================

    story.append(
        Paragraph(
            "3. Network Protocol Distribution",
            heading_style
        )
    )


    protocol_data = [
        ["Protocol", "Flow Count"]
    ]


    for protocol, count in sorted(
        protocols.items(),
        key=lambda item: item[1],
        reverse=True
    ):

        protocol_data.append(
            [
                protocol,
                str(count)
            ]
        )


    if len(protocol_data) == 1:

        protocol_data.append(
            [
                "No data",
                "0"
            ]
        )


    protocol_table = Table(

        protocol_data,

        colWidths=[
            100 * mm,
            60 * mm
        ]
    )


    protocol_table.setStyle(
        TableStyle([

            (
                "BACKGROUND",
                (0, 0),
                (-1, 0),
                colors.HexColor(
                    "#101827"
                )
            ),

            (
                "TEXTCOLOR",
                (0, 0),
                (-1, 0),
                colors.white
            ),

            (
                "FONTNAME",
                (0, 0),
                (-1, 0),
                "Helvetica-Bold"
            ),

            (
                "GRID",
                (0, 0),
                (-1, -1),
                0.5,
                colors.HexColor(
                    "#D0D5DD"
                )
            ),

            (
                "ALIGN",
                (1, 1),
                (1, -1),
                "CENTER"
            ),

            (
                "TOPPADDING",
                (0, 0),
                (-1, -1),
                7
            ),

            (
                "BOTTOMPADDING",
                (0, 0),
                (-1, -1),
                7
            )
        ])
    )


    story.append(
        protocol_table
    )


    # ========================================================
    # ATTACK HISTORY
    # ========================================================

    story.append(
        PageBreak()
    )


    story.append(
        Paragraph(
            "4. Detected Attack History",
            heading_style
        )
    )


    if attacks:

        attack_table_data = [

            [
                "Time",
                "Source",
                "Destination",
                "Protocol",
                "Threat Vector",
                "Severity",
                "Confidence"
            ]
        ]


        for attack in attacks[-20:][::-1]:

            attack_table_data.append([

                attack.get(
                    "time",
                    "-"
                ),

                attack.get(
                    "source",
                    "-"
                ),

                attack.get(
                    "destination",
                    "-"
                ),

                attack.get(
                    "protocol",
                    "-"
                ).upper(),

                attack.get(
                    "threat_type",
                    "ANOMALOUS_FLOW"
                ).replace("_", " "),

                attack.get(
                    "severity",
                    "HIGH"
                ),

                f'{attack.get("confidence", "-")}%'

            ])


        attack_table = Table(

            attack_table_data,

            colWidths=[
                28 * mm,
                30 * mm,
                30 * mm,
                18 * mm,
                32 * mm,
                18 * mm,
                18 * mm
            ],

            repeatRows=1
        )


        attack_table.setStyle(
            TableStyle([

                (
                    "BACKGROUND",
                    (0, 0),
                    (-1, 0),
                    colors.HexColor(
                        "#B42318"
                    )
                ),

                (
                    "TEXTCOLOR",
                    (0, 0),
                    (-1, 0),
                    colors.white
                ),

                (
                    "FONTNAME",
                    (0, 0),
                    (-1, 0),
                    "Helvetica-Bold"
                ),

                (
                    "GRID",
                    (0, 0),
                    (-1, -1),
                    0.4,
                    colors.HexColor(
                        "#F2B8B5"
                    )
                ),

                (
                    "FONTSIZE",
                    (0, 0),
                    (-1, -1),
                    7
                ),

                (
                    "VALIGN",
                    (0, 0),
                    (-1, -1),
                    "MIDDLE"
                ),

                (
                    "TOPPADDING",
                    (0, 0),
                    (-1, -1),
                    6
                ),

                (
                    "BOTTOMPADDING",
                    (0, 0),
                    (-1, -1),
                    6
                )
            ])
        )


        story.append(
            attack_table
        )

    else:

        story.append(
            Paragraph(
                "No attack records were detected in the available "
                "prediction log.",
                normal_style
            )
        )


    # ========================================================
    # SECURITY RECOMMENDATIONS
    # ========================================================

    story.append(
        Paragraph(
            "5. Security Recommendations",
            heading_style
        )
    )


    recommendations = [

        "Investigate repeated attack predictions from the same source address.",

        "Monitor network flows with unusually high traffic volume or packet counts.",

        "Review suspicious TCP and UDP connections identified by the ML classifier.",

        "Use the attack confidence score together with network context when validating alerts.",

        "Continue collecting representative network traffic to improve the IDS model.",

        "Periodically retrain and evaluate the model using updated datasets."
    ]


    for index, recommendation in enumerate(
        recommendations,
        start=1
    ):

        story.append(
            Paragraph(
                f"<b>{index}.</b> {recommendation}",
                normal_style
            )
        )

        story.append(
            Spacer(
                1,
                5
            )
        )


    # ========================================================
    # CONCLUSION
    # ========================================================

    story.append(
        Paragraph(
            "6. Conclusion",
            heading_style
        )
    )


    conclusion = (

        "The Real-Time Intrusion Detection System combines live "
        "network packet capture, flow-level feature extraction, "
        "machine-learning classification, threshold optimization, "
        "CSV logging and dashboard-based monitoring. The generated "
        "statistics and attack history provide a summary of the "
        "traffic observed during the monitoring period."
    )


    story.append(
        Paragraph(
            conclusion,
            normal_style
        )
    )


    # ========================================================
    # BUILD PDF
    # ========================================================

    document.build(
        story,
        onFirstPage=add_page_number,
        onLaterPages=add_page_number
    )


    return report_path


# ============================================================
# TEST / DIRECT EXECUTION
# ============================================================

if __name__ == "__main__":

    generated_file = generate_report()

    print()
    print("==========================================")
    print("       IDS SECURITY REPORT")
    print("==========================================")
    print()
    print("Report generated successfully!")
    print()
    print("File:")
    print(generated_file)
    print()
    print("==========================================")