/* ============================================================
   REAL-TIME IDS DASHBOARD
   Clean version
   No session system
   No duplicate bar chart
   Stable real-time attack alerts
============================================================ */


/* ============================================================
   GLOBAL STATE
============================================================ */

let dashboardRefreshTimer = null;

let scannerActive = false;

let lastPredictionCount = 0;

let protocolChartHasAnimated = false;


/*
   ------------------------------------------------------------
   ATTACK ALERT STATE
   ------------------------------------------------------------

   This prevents the same historical attack from appearing
   repeatedly every time updateDashboard() runs.

   alertInitialized:
       Becomes true after the first alert data is loaded.

   lastAlertKey:
       Identifies the most recent attack.

   dismissedAlertKey:
       Stores the attack that the user closed.

   localStorage:
       Keeps the dismissed alert closed even if the dashboard
       refreshes.
*/

let alertInitialized = false;

let lastAlertKey = null;

let dismissedAlertKey =
    localStorage.getItem(
        "idsDismissedAlertKey"
    );

let alertCloseTimer = null;


/* ============================================================
   INITIALIZATION
============================================================ */

document.addEventListener("DOMContentLoaded", () => {

    console.log("IDS Dashboard loaded.");

    // Bind packet history modal button
    const historyBtn = document.getElementById("packetHistoryButton");
    if (historyBtn) {
        historyBtn.addEventListener("click", showPacketHistory);
    }

    updateDashboard();

    dashboardRefreshTimer =
        setInterval(updateDashboard, 2000);

});


/* ============================================================
   SYSTEM SCANNER STATUS POLLING (For topbar/cards)
============================================================ */

async function updateScannerStatus() {

    try {

        const response =
            await fetch(
                "/api/scanner/status"
            );

        const data =
            await response.json();

        scannerActive =
            data.active === true;

        const systemStatusEl =
            document.getElementById(
                "systemPacketStatus"
            );

        if (systemStatusEl) {
            if (scannerActive) {
                systemStatusEl.innerText = "CAPTURING";
                systemStatusEl.className = "online";
            } else {
                systemStatusEl.innerText = "STANDBY";
                systemStatusEl.className = "offline";
            }
        }

    } catch (error) {

        console.error(
            "Scanner status check error:",
            error
        );

    }

}


/* ============================================================
   MAIN DASHBOARD UPDATE
============================================================ */

async function updateDashboard() {

    try {

        await updateScannerStatus();

        await updateStatistics();

        await updatePredictions();

        await updateCharts();

        await updateAlerts();

    } catch (error) {

        console.error(
            "Dashboard update error:",
            error
        );

    }

}


/* ============================================================
   STATISTICS
============================================================ */

async function updateStatistics() {

    const response =
        await fetch(
            "/api/stats"
        );


    if (!response.ok) {

        throw new Error(
            "Statistics request failed."
        );

    }


    const data =
        await response.json();


    const total =
        Number(data.total || 0);

    const normal =
        Number(data.normal || 0);

    const attack =
        Number(data.attack || 0);


    setText(
        "total",
        total.toLocaleString()
    );


    setText(
        "normal",
        normal.toLocaleString()
    );


    setText(
        "attack",
        attack.toLocaleString()
    );


    const attackRate =
        total > 0
            ? ((attack / total) * 100)
                .toFixed(2)
            : "0.00";


    setText(
        "attackRate",
        attackRate + "%"
    );

    setText(
        "secureTrafficRate",
        total > 0 ? ((normal / total) * 100).toFixed(1) + "%" : "0%"
    );

    setText(
        "threatTrafficRate",
        total > 0 ? ((attack / total) * 100).toFixed(1) + "%" : "0%"
    );


    /*
       Update donut chart.
    */

    updateTrafficDonut(
        normal,
        attack,
        total
    );

}


/* ============================================================
   TRAFFIC DONUT
============================================================ */

function updateTrafficDonut(
    normal,
    attack,
    total
) {

    const donut =
        document.getElementById(
            "trafficDonut"
        );


    const donutTotal =
        document.getElementById(
            "donutTotal"
        );


    const donutNormal =
        document.getElementById(
            "donutNormal"
        );


    const donutAttack =
        document.getElementById(
            "donutAttack"
        );


    if (donutTotal) {

        donutTotal.innerText =
            total.toLocaleString();

    }


    if (donutNormal) {

        donutNormal.innerText =
            normal.toLocaleString();

    }


    if (donutAttack) {

        donutAttack.innerText =
            attack.toLocaleString();

    }


    if (!donut) {

        return;

    }


    if (total <= 0) {

        donut.style.background =
            "conic-gradient(#cbd5e1 0% 100%)";

        return;

    }


    const normalPercent =
        (normal / total) * 100;


    donut.style.background =
        `conic-gradient(
            #22c55e 0% ${normalPercent}%,
            #ef4444 ${normalPercent}% 100%
        )`;

}


/* ============================================================
   LIVE PREDICTIONS
============================================================ */

async function updatePredictions() {

    const response =
        await fetch(
            "/api/predictions"
        );


    if (!response.ok) {

        throw new Error(
            "Predictions request failed."
        );

    }


    const predictions =
        await response.json();


    displayPredictions(
        predictions
    );


    setText(
        "lastUpdate",
        "Updated: " +
        new Date().toLocaleTimeString()
    );

}


/* ============================================================
   DISPLAY PREDICTIONS
============================================================ */

function displayPredictions(
    predictions
) {

    const table =
        document.getElementById(
            "predictionTable"
        );


    if (!table) {

        return;

    }


    table.innerHTML = "";


    if (
        !predictions ||
        predictions.length === 0
    ) {

        table.innerHTML = `
            <tr>
                <td colspan="6">
                    No predictions available.
                </td>
            </tr>
        `;

        return;

    }


    /*
       Display latest predictions first.
    */

    const latest =
        predictions
            .slice()
            .reverse();


    latest.forEach(row => {

        const tr =
            document.createElement("tr");


        const prediction =
            row.prediction || "UNKNOWN";


        const resultClass =
            prediction === "ATTACK"
                ? "attack-result"
                : "normal-result";


        const threatType = row.threat_type || (prediction === "ATTACK" ? "ANOMALOUS_FLOW" : "NORMAL");
        const severity = row.severity || (prediction === "ATTACK" ? "HIGH" : "LOW");

        let threatBadgeClass = "badge-normal";
        if (threatType === "DNS_TUNNELING") threatBadgeClass = "badge-dns";
        else if (threatType === "C2_BEACON") threatBadgeClass = "badge-c2";
        else if (threatType === "DATA_EXFILTRATION") threatBadgeClass = "badge-exfil";
        else if (threatType === "ANOMALOUS_FLOW") threatBadgeClass = "badge-anomaly";

        const severityBadgeClass = `badge-sev-${severity.toLowerCase()}`;

        tr.innerHTML = `

            <td>
                ${escapeHtml(
                    row.time || "-"
                )}
            </td>

            <td>
                ${escapeHtml(
                    row.source || "-"
                )}
            </td>

            <td>
                ${escapeHtml(
                    row.destination || "-"
                )}
            </td>

            <td>
                ${escapeHtml(
                    row.protocol || "-"
                )}
            </td>

            <td>
                <span class="threat-badge ${threatBadgeClass}">
                    ${escapeHtml(threatType.replaceAll("_", " "))}
                </span>
            </td>

            <td>
                <span class="sev-badge ${severityBadgeClass}">
                    ${escapeHtml(severity)}
                </span>
            </td>

            <td class="${resultClass}">
                ${escapeHtml(
                    prediction
                )}
            </td>

            <td>
                ${escapeHtml(
                    row.confidence || "-"
                )}%
            </td>

        `;


        table.appendChild(tr);

    });


    /*
       Keep track of number of predictions.
    */

    lastPredictionCount =
        predictions.length;

}


/* ============================================================
   CHART DATA
============================================================ */

async function updateCharts() {

    const response =
        await fetch(
            "/api/chart-data"
        );


    if (!response.ok) {

        throw new Error(
            "Chart data request failed."
        );

    }


    const data =
        await response.json();


    updateProtocolChart(
        data.protocols || {}
    );


    updateThreatSummary(
        data.timeline || []
    );

}


/* ============================================================
   PROTOCOL DISTRIBUTION
============================================================ */

function updateProtocolChart(
    protocols
) {

    const container =
        document.getElementById(
            "protocolChart"
        );


    if (!container) {

        return;

    }


    container.innerHTML = "";


    const entries =
        Object.entries(protocols);


    if (entries.length === 0) {

        container.innerHTML =
            "<p>No protocol data available.</p>";

        return;

    }


    entries.sort(
        (a, b) => b[1] - a[1]
    );


    const max =
        Math.max(
            ...entries.map(
                item => Number(item[1]) || 0
            ),
            1
        );


    entries.forEach(
        ([protocol, count]) => {

            const percentage =
                (
                    (Number(count) / max) *
                    100
                );


            const row =
                document.createElement(
                    "div"
                );


            row.className =
                "protocol-row";

            const barAnimationClass = protocolChartHasAnimated
                ? ""
                : " protocol-bar-intro";


            row.innerHTML = `

                <div class="protocol-label">

                    <strong>
                        ${escapeHtml(
                            protocol.toUpperCase()
                        )}
                    </strong>

                    <span>
                        ${Number(count).toLocaleString()}
                    </span>

                </div>

                <div class="protocol-bar-bg">

                    <div
                        class="protocol-bar${barAnimationClass}"
                        style="width:${percentage}%">
                    </div>

                </div>

            `;


            container.appendChild(row);

        }
    );

    protocolChartHasAnimated = true;

}


/* ============================================================
   THREAT ACTIVITY SUMMARY
============================================================ */

function updateThreatSummary(
    timeline
) {

    const container =
        document.getElementById(
            "threatSummaryList"
        );


    const entries = (timeline || []).map(item => ({
        time: item.time || "Unknown interval",
        attacks: Number(item.attacks) || 0
    }));

    const peak = Math.max(...entries.map(item => item.attacks), 0);
    const active = entries.filter(item => item.attacks > 0).length;
    const latest = entries.length ? entries[entries.length - 1].attacks : 0;

    setText("peakAttacks", peak.toLocaleString());
    setText("activeIntervals", active.toLocaleString());
    setText("latestAttacks", latest.toLocaleString());

    container.innerHTML = entries.length
        ? entries.slice(-4).reverse().map(item => `
            <div class="threat-summary-row">
                <span><b>${escapeHtml(item.time)}</b><small>minute</small></span>
                <strong>${item.attacks.toLocaleString()} prediction(s)</strong>
            </div>
        `).join("")
        : "<p>No attack activity detected.</p>";

}


/* ============================================================
   ATTACK ALERTS
============================================================ */

async function updateAlerts() {

    const response =
        await fetch(
            "/api/alerts"
        );


    if (!response.ok) {

        throw new Error(
            "Alerts request failed."
        );

    }


    const alerts =
        await response.json();


    displayAlertHistory(
        alerts
    );


    updateLiveAttackAlert(
        alerts
    );

}


/* ============================================================
   ATTACK HISTORY
============================================================ */

function displayAlertHistory(
    alerts
) {

    const table =
        document.getElementById(
            "alertTable"
        );


    if (!table) {

        return;

    }


    table.innerHTML = "";


    if (
        !alerts ||
        alerts.length === 0
    ) {

        table.innerHTML = `
            <tr>
                <td colspan="6">
                    No attacks detected.
                </td>
            </tr>
        `;

        return;

    }


    alerts
        .slice()
        .reverse()
        .forEach(row => {

            const tr =
                document.createElement(
                    "tr"
                );


            const attackUrl =
                `/attack-details?time=${encodeURIComponent(
                    row.time || ""
                )}&source=${encodeURIComponent(
                    row.source || ""
                )}`;


            const threatType = row.threat_type || "ANOMALOUS_FLOW";
            const severity = row.severity || "HIGH";

            let threatBadgeClass = "badge-anomaly";
            if (threatType === "DNS_TUNNELING") threatBadgeClass = "badge-dns";
            else if (threatType === "C2_BEACON") threatBadgeClass = "badge-c2";
            else if (threatType === "DATA_EXFILTRATION") threatBadgeClass = "badge-exfil";

            const severityBadgeClass = `badge-sev-${severity.toLowerCase()}`;

            tr.innerHTML = `

                <td>
                    ${escapeHtml(
                        row.time || "-"
                    )}
                </td>

                <td>
                    ${escapeHtml(
                        row.source || "-"
                    )}
                </td>

                <td>
                    ${escapeHtml(
                        row.destination || "-"
                    )}
                </td>

                <td>
                    ${escapeHtml(
                        row.protocol || "-"
                    )}
                </td>

                <td>
                    <span class="threat-badge ${threatBadgeClass}">
                        ${escapeHtml(threatType.replaceAll("_", " "))}
                    </span>
                </td>

                <td>
                    <span class="sev-badge ${severityBadgeClass}">
                        ${escapeHtml(severity)}
                    </span>
                </td>

                <td class="attack-result">
                    ${escapeHtml(
                        row.confidence || "-"
                    )}%
                </td>

                <td>

                    <a
                        href="${attackUrl}"
                        class="investigate-button">

                        Investigate

                    </a>

                </td>

            `;


            table.appendChild(tr);

        });

}


/* ============================================================
   CREATE UNIQUE ALERT KEY
============================================================ */

function createAlertKey(
    alert
) {

    if (!alert) {

        return null;

    }


    /*
       Use all important identifying information.

       The time is especially important because the same
       source/destination may legitimately generate another
       attack later.
    */

    return [
        alert.time || "",
        alert.source || "",
        alert.destination || "",
        alert.protocol || "",
        alert.confidence || ""
    ].join("|");

}


/* ============================================================
   LIVE ATTACK ALERT
============================================================ */

function updateLiveAttackAlert(
    alerts
) {

    const alertBox =
        document.getElementById(
            "attackAlert"
        );


    if (!alertBox) {

        return;

    }


    /*
       No attack history.
    */

    if (
        !alerts ||
        alerts.length === 0
    ) {

        alertBox.classList.add(
            "hidden"
        );

        return;

    }


    /*
       The API returns attack history.
       The latest item is therefore the newest attack.
    */

    const latest =
        alerts[alerts.length - 1];


    const latestAlertKey =
        createAlertKey(
            latest
        );


    /*
       --------------------------------------------------------
       FIRST LOAD
       --------------------------------------------------------

       Do NOT display an old historical attack immediately
       when the dashboard is opened.

       We simply remember the latest existing attack.

       This makes the alert truly real-time.
    */

    if (!alertInitialized) {

        lastAlertKey =
            latestAlertKey;

        alertInitialized = true;

        alertBox.classList.add(
            "hidden"
        );

        return;

    }


    /*
       --------------------------------------------------------
       NO NEW ATTACK
       --------------------------------------------------------

       If the newest attack is the same attack we already
       processed, do nothing.

       This is what prevents the alert from reappearing
       every 2 seconds.
    */

    if (
        latestAlertKey ===
        lastAlertKey
    ) {

        return;

    }


    /*
       A genuinely new attack has appeared.
    */

    lastAlertKey =
        latestAlertKey;


    /*
       --------------------------------------------------------
       IF USER ALREADY DISMISSED THIS EXACT ATTACK
       --------------------------------------------------------
    */

    if (
        dismissedAlertKey ===
        latestAlertKey
    ) {

        alertBox.classList.add(
            "hidden"
        );

        return;

    }


    /*
       Only show a live alert while scanner is active.

       Historical attacks remain visible in the alert history
       table regardless of scanner state.
    */

    if (!scannerActive) {

        alertBox.classList.add(
            "hidden"
        );

        return;

    }


    /*
       Fill alert information.
    */

    const threatName = (latest.threat_type || "POTENTIAL INTRUSION").replaceAll("_", " ");
    const severityName = latest.severity || "HIGH";

    setText(
        "alertThreatType",
        threatName
    );

    setText(
        "alertSeverity",
        severityName
    );

    setText(
        "alertMessage",
        `Security sensor detected ${threatName} with ${severityName} severity.`
    );


    setText(
        "alertSource",
        latest.source || "-"
    );


    setText(
        "alertDestination",
        latest.destination || "-"
    );


    setText(
        "alertProtocol",
        latest.protocol || "-"
    );


    setText(
        "alertConfidence",
        (latest.confidence || "-") + "%"
    );


    /*
       Show the NEW alert.
    */

    alertBox.classList.remove(
        "hidden"
    );

    if (alertCloseTimer) {
        clearTimeout(alertCloseTimer);
    }

    alertCloseTimer = setTimeout(() => {
        alertBox.classList.add("hidden");
        alertCloseTimer = null;
    }, 4000);

}


/* ============================================================
   CLOSE ALERT
============================================================ */

document.addEventListener(
    "click",
    event => {

        if (
            event.target.id ===
            "closeAlert"
        ) {

            const alertBox =
                document.getElementById(
                    "attackAlert"
                );


            /*
               Remember which attack the user closed.

               This is the important part of the fix.
            */

            if (lastAlertKey) {

                dismissedAlertKey =
                    lastAlertKey;


                localStorage.setItem(
                    "idsDismissedAlertKey",
                    lastAlertKey
                );

            }


            if (alertBox) {

                if (alertCloseTimer) {
                    clearTimeout(alertCloseTimer);
                    alertCloseTimer = null;
                }

                alertBox.classList.add(
                    "hidden"
                );

            }

        }

    }
);


/* ============================================================
   PACKET HISTORY
============================================================ */

async function showPacketHistory() {

    try {

        const response =
            await fetch(
                "/api/packet-history/latest?limit=200"
            );


        if (!response.ok) {

            throw new Error(
                "Packet history request failed."
            );

        }


        const data =
            await response.json();


        const packets =
            data.packets ||
            data.results ||
            [];


        displayPacketHistory(
            packets
        );


    } catch (error) {

        console.error(
            "Packet history error:",
            error
        );


        alert(
            "Unable to load packet history:\n" +
            error.message
        );

    }

}


/* ============================================================
   PACKET HISTORY DISPLAY
============================================================ */

function displayPacketHistory(packets) {

    const modal =
        document.getElementById("historyModal");

    const table =
        document.getElementById("packetHistoryTable");

    if (!modal || !table) {
        return;
    }

    table.innerHTML = "";

    if (!packets || packets.length === 0) {

        table.innerHTML = `
            <tr>
                <td colspan="8">
                    No packet history available.
                </td>
            </tr>
        `;

    } else {

        packets.slice().reverse().forEach(row => {

            const tr =
                document.createElement("tr");

            const prediction =
                row.prediction || "UNKNOWN";

            const resultClass =
                prediction === "ATTACK"
                    ? "attack-result"
                    : "normal-result";

            const threatType = row.threat_type || (prediction === "ATTACK" ? "ANOMALOUS_FLOW" : "NORMAL");
            const severity = row.severity || (prediction === "ATTACK" ? "HIGH" : "LOW");

            let threatBadgeClass = "badge-normal";
            if (threatType === "DNS_TUNNELING") threatBadgeClass = "badge-dns";
            else if (threatType === "C2_BEACON") threatBadgeClass = "badge-c2";
            else if (threatType === "DATA_EXFILTRATION") threatBadgeClass = "badge-exfil";
            else if (threatType === "ANOMALOUS_FLOW") threatBadgeClass = "badge-anomaly";

            const severityBadgeClass = `badge-sev-${severity.toLowerCase()}`;

            tr.innerHTML = `

                <td>${escapeHtml(row.time || "-")}</td>

                <td>${escapeHtml(row.source || "-")}</td>

                <td>${escapeHtml(row.destination || "-")}</td>

                <td>${escapeHtml(row.protocol || "-")}</td>

                <td>
                    <span class="threat-badge ${threatBadgeClass}">
                        ${escapeHtml(threatType.replaceAll("_", " "))}
                    </span>
                </td>

                <td>
                    <span class="sev-badge ${severityBadgeClass}">
                        ${escapeHtml(severity)}
                    </span>
                </td>

                <td class="${resultClass}">
                    ${escapeHtml(prediction)}
                </td>

                <td>
                    ${escapeHtml(row.confidence || "-")}%
                </td>

            `;

            table.appendChild(tr);

        });

    }

    modal.classList.add("show");
}

document.addEventListener("click", event => {

    if (event.target.id === "historyClose") {

        const modal =
            document.getElementById("historyModal");

        if (modal) {
            modal.classList.remove("show");
        }

    }

});


/* ============================================================
   HELPERS
============================================================ */

function setText(
    elementId,
    value
) {

    const element =
        document.getElementById(
            elementId
        );


    if (element) {

        element.innerText =
            value;

    }

}


/* ============================================================
   HTML ESCAPING
============================================================ */

function escapeHtml(value) {

    return String(value)
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll('"', "&quot;")
        .replaceAll("'", "&#039;");

}