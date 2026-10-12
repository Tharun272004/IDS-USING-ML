/* ============================================================
   LIVE MONITORING SCRIPT
============================================================ */

let refreshTimer = null;
let isUpdating = false;
let liveSessionStartIndex = 0;

document.addEventListener("DOMContentLoaded", async () => {
    console.log("Live Monitoring Console Loaded.");

    const startBtn = document.getElementById("startScanner");
    const stopBtn = document.getElementById("stopScanner");
    const continueBtn = document.getElementById("continueScanner");
    const historyBtn = document.getElementById("packetHistoryButton");

    if (startBtn) startBtn.addEventListener("click", startScanning);
    if (stopBtn) stopBtn.addEventListener("click", stopScanning);
    if (continueBtn) continueBtn.addEventListener("click", continueScanning);
    if (historyBtn) historyBtn.addEventListener("click", showPacketHistory);

    await updateScannerStatus();
    await updateLiveMetrics();

    refreshTimer = setInterval(() => {
        updateScannerStatus();
        updateLiveMetrics();
    }, 1000);
});

async function updateScannerStatus() {
    try {
        const res = await fetch("/api/scanner/status");
        if (!res.ok) return;
        const data = await res.json();
        const active = data.active || false;

        if (Number.isInteger(data.session_start_index)) {
            liveSessionStartIndex = data.session_start_index;
        }

        const statusPill = document.getElementById("scannerStatus");
        const statusText = document.getElementById("scannerMessage");
        const startBtn = document.getElementById("startScanner");
        const stopBtn = document.getElementById("stopScanner");
        const continueBtn = document.getElementById("continueScanner");
        const banner = document.getElementById("statusBanner");
        const controlStateBox = document.getElementById("controlStateBox");
        const controlStateText = document.getElementById("controlStateText");
        const resumable = data.resumable === true;

        if (active) {
            if (statusPill) {
                statusPill.innerText = "SCANNING";
                statusPill.className = "scanner-status running";
            }
            if (statusText) {
                statusText.innerText = "Real-time packet sniffer is active and processing network flows.";
            }
            if (banner) banner.className = "monitor-status-banner banner-active";
            if (controlStateBox) controlStateBox.className = "control-state-box scanning";
            if (controlStateText) controlStateText.innerText = "SCANNING";
            if (startBtn) startBtn.style.display = "none";
            if (stopBtn) stopBtn.style.display = "inline-flex";
            if (continueBtn) continueBtn.style.display = "none";
        } else {
            if (statusPill) {
                statusPill.innerText = "STOPPED";
                statusPill.className = "scanner-status stopped";
            }
            if (statusText) {
                statusText.innerText = "Scanner is currently stopped. Packet capture is paused.";
            }
            if (banner) banner.className = "monitor-status-banner banner-stopped";
            if (controlStateBox) controlStateBox.className = "control-state-box stopped";
            if (controlStateText) controlStateText.innerText = "STOPPED";
            if (startBtn) startBtn.style.display = resumable ? "none" : "inline-flex";
            if (stopBtn) stopBtn.style.display = "none";
            if (continueBtn) continueBtn.style.display = resumable ? "inline-flex" : "none";
        }
    } catch (e) {
        console.error("Scanner status check error:", e);
    }
}

async function startScanning() {
    const btn = document.getElementById("startScanner");
    if (btn) btn.disabled = true;
    try {
        const res = await fetch("/api/scanner/start", { method: "POST" });
        const data = await res.json();
        console.log("Scanner start response:", data);
        if (res.ok && Number.isInteger(data.session_start_index)) {
            liveSessionStartIndex = data.session_start_index;
            renderLiveStream([]);
            updateLiveMetrics();
        }
        await updateScannerStatus();
    } catch (e) {
        alert("Failed to start scanner: " + e.message);
    } finally {
        if (btn) btn.disabled = false;
    }
}

async function stopScanning() {
    const btn = document.getElementById("stopScanner");
    if (btn) btn.disabled = true;
    try {
        const res = await fetch("/api/scanner/stop", { method: "POST" });
        const data = await res.json();
        console.log("Scanner stop response:", data);
        await updateScannerStatus();
    } catch (e) {
        alert("Failed to stop scanner: " + e.message);
    } finally {
        if (btn) btn.disabled = false;
    }
}

async function continueScanning() {
    const btn = document.getElementById("continueScanner");
    if (btn) btn.disabled = true;
    try {
        const res = await fetch("/api/scanner/continue", { method: "POST" });
        const data = await res.json();
        console.log("Scanner continue response:", data);
        if (res.ok && Number.isInteger(data.session_start_index)) {
            liveSessionStartIndex = data.session_start_index;
        }
        await updateScannerStatus();
    } catch (e) {
        alert("Failed to resume scanner: " + e.message);
    } finally {
        if (btn) btn.disabled = false;
    }
}

async function updateLiveMetrics() {
    if (isUpdating) return;
    isUpdating = true;
    try {
        const liveRes = await fetch(`/api/live-monitoring?start_index=${liveSessionStartIndex}`);

        if (liveRes.ok) {
            const s = await liveRes.json();
            const totalEl = document.getElementById("metricTotal");
            const normalEl = document.getElementById("metricNormal");
            const attackEl = document.getElementById("metricAttack");
            const rateEl = document.getElementById("metricRate");

            if (totalEl) totalEl.innerText = (s.total || 0).toLocaleString();
            if (normalEl) normalEl.innerText = (s.normal || 0).toLocaleString();
            if (attackEl) attackEl.innerText = (s.attack || 0).toLocaleString();
            if (rateEl) rateEl.innerText = (s.attack_rate || 0) + "%";
            renderLiveStream(s.predictions || []);
        }
    } catch (e) {
        console.error("Live metrics update error:", e);
    } finally {
        isUpdating = false;
    }
}

function renderLiveStream(rows) {
    const tbody = document.getElementById("liveStreamTable");
    if (!tbody) return;

    if (!rows || rows.length === 0) {
        tbody.innerHTML = `<tr><td colspan="8" style="text-align:center; padding: 25px; color: #64748b;">No network flows captured yet. Click "Start Scanning" above.</td></tr>`;
        return;
    }

    tbody.innerHTML = "";
    const latest = rows.slice().reverse().slice(0, 15);

    latest.forEach(row => {
        const tr = document.createElement("tr");
        const pred = row.prediction || "UNKNOWN";
        const isAttack = pred === "ATTACK";

        const threatType = row.threat_type || (isAttack ? "ANOMALOUS_FLOW" : "NORMAL");
        const severity = row.severity || (isAttack ? "HIGH" : "LOW");

        let threatClass = "badge-normal";
        if (threatType === "DNS_TUNNELING") threatClass = "badge-dns";
        else if (threatType === "C2_BEACON") threatClass = "badge-c2";
        else if (threatType === "DATA_EXFILTRATION") threatClass = "badge-exfil";
        else if (threatType === "ANOMALOUS_FLOW") threatClass = "badge-anomaly";

        const sevClass = `badge-sev-${severity.toLowerCase()}`;
        const resultClass = isAttack ? "attack-result" : "normal-result";

        tr.innerHTML = `
            <td>${escapeHtml(row.time || "-")}</td>
            <td>${escapeHtml(row.source || "-")}</td>
            <td>${escapeHtml(row.destination || "-")}</td>
            <td><strong>${escapeHtml(row.protocol || "-")}</strong></td>
            <td><span class="threat-badge ${threatClass}">${escapeHtml(threatType.replaceAll("_", " "))}</span></td>
            <td><span class="sev-badge ${sevClass}">${escapeHtml(severity)}</span></td>
            <td class="${resultClass}">${escapeHtml(pred)}</td>
            <td>${escapeHtml(row.confidence || "-")}%</td>
        `;
        tbody.appendChild(tr);
    });

    const updateLabel = document.getElementById("lastStreamUpdate");
    if (updateLabel) {
        const now = new Date();
        updateLabel.innerText = "Live: " + now.toLocaleTimeString();
    }
}

async function showPacketHistory() {
    try {
        const response = await fetch(`/api/packet-history/latest?limit=200`);
        if (!response.ok) throw new Error("Packet history request failed.");
        const data = await response.json();
        const packets = data.packets || [];
        displayPacketHistory(packets);
    } catch (err) {
        alert("Unable to load packet history:\n" + err.message);
    }
}

function displayPacketHistory(packets) {
    const modal = document.getElementById("historyModal");
    const table = document.getElementById("packetHistoryTable");
    if (!modal || !table) return;

    table.innerHTML = "";

    if (!packets || packets.length === 0) {
        table.innerHTML = `<tr><td colspan="8" style="text-align:center; padding: 20px;">No packet history available.</td></tr>`;
    } else {
        packets.slice().reverse().forEach(row => {
            const tr = document.createElement("tr");
            const pred = row.prediction || "UNKNOWN";
            const isAttack = pred === "ATTACK";

            const threatType = row.threat_type || (isAttack ? "ANOMALOUS_FLOW" : "NORMAL");
            const severity = row.severity || (isAttack ? "HIGH" : "LOW");

            let threatClass = "badge-normal";
            if (threatType === "DNS_TUNNELING") threatClass = "badge-dns";
            else if (threatType === "C2_BEACON") threatClass = "badge-c2";
            else if (threatType === "DATA_EXFILTRATION") threatClass = "badge-exfil";
            else if (threatType === "ANOMALOUS_FLOW") threatClass = "badge-anomaly";

            const sevClass = `badge-sev-${severity.toLowerCase()}`;
            const resultClass = isAttack ? "attack-result" : "normal-result";

            tr.innerHTML = `
                <td>${escapeHtml(row.time || "-")}</td>
                <td>${escapeHtml(row.source || "-")}</td>
                <td>${escapeHtml(row.destination || "-")}</td>
                <td>${escapeHtml(row.protocol || "-")}</td>
                <td><span class="threat-badge ${threatClass}">${escapeHtml(threatType.replaceAll("_", " "))}</span></td>
                <td><span class="sev-badge ${sevClass}">${escapeHtml(severity)}</span></td>
                <td class="${resultClass}">${escapeHtml(pred)}</td>
                <td>${escapeHtml(row.confidence || "-")}%</td>
            `;
            table.appendChild(tr);
        });
    }

    modal.classList.add("show");
}

document.addEventListener("click", e => {
    if (e.target && e.target.id === "historyClose") {
        const modal = document.getElementById("historyModal");
        if (modal) modal.classList.remove("show");
    }
});

function escapeHtml(str) {
    if (str === null || str === undefined) return "";
    return String(str)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}
