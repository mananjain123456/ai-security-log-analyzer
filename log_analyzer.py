from flask import Flask, request, jsonify, render_template_string
import requests
import json
import os
import time
import threading
import psutil
import hashlib
import smtplib
from email.message import EmailMessage
from datetime import datetime

app = Flask(__name__)

# --- Model & API Settings ---
OLLAMA_API = "http://127.0.0.1:11434/api/generate"
MODEL_NAME = "gemma2:2b"
OUTPUT_FILE = "forensics_alerts.jsonl"

# --- SMTP Email Configuration ---
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587
SENDER_EMAIL = "your_email@gmail.com"
SENDER_APP_PASSWORD = "your_16_digit_app_password"
ALERT_RECIPIENT = "security_admin@yourdomain.com"

# --- Limits, Deduplication & Caching ---
MAX_RAM_PERCENT = 90.0
seen_logs = set()
alerts_cache = []
LAST_EMAIL_SENT = 0
EMAIL_COOLDOWN_SECONDS = 60

# Track active sources for live dashboard telemetry
source_activity = {
    "VMware": {"last_seen": None, "count": 0},
    "AWS_EC2": {"last_seen": None, "count": 0},
    "Source_3": {"last_seen": None, "count": 0}
}

# --- Startup Cache Initialization ---
if os.path.exists(OUTPUT_FILE):
    try:
        with open(OUTPUT_FILE, "r") as f:
            for line in f:
                if line.strip():
                    record = json.loads(line.strip())
                    alerts_cache.append(record)
                    src = record.get("source", "VMware")
                    if src in source_activity:
                        source_activity[src]["count"] += 1
                        source_activity[src]["last_seen"] = record.get("timestamp")
                    if "original_log" in record:
                        log_str = json.dumps(record["original_log"], sort_keys=True)
                        seen_logs.add(hashlib.md5(f"{src}:{log_str}".encode()).hexdigest())
    except Exception as e:
        print(f"[!] Error loading cache: {e}")

# --- Helper Functions ---

def check_resources():
    ram_usage = psutil.virtual_memory().percent
    if ram_usage > MAX_RAM_PERCENT:
        print(f"\n[CRITICAL] System RAM reached {ram_usage}%. Halting for system safety.")
        os._exit(1)

def send_critical_email(record):
    """Dispatches alerts via SMTP when critical events are detected."""
    try:
        msg = EmailMessage()
        threat = record['triage'].get('threat_type', 'CRITICAL_ALERT')
        src = record.get('source', 'UNKNOWN')
        msg['Subject'] = f"[SOC ALERT - {src}] {threat}"
        msg['From'] = SENDER_EMAIL
        msg['To'] = ALERT_RECIPIENT

        body = f"""=== CRITICAL SECURITY INCIDENT DETECTED ===
Source Node: {src}
Timestamp: {record.get('timestamp')}
Threat Classification: {threat}

AI Forensics Summary:
{record['triage'].get('summary')}

Recommended Immediate Action:
{record['triage'].get('recommended_action')}

Raw Log Record:
{json.dumps(record.get('original_log'), indent=2)}

-- 
AI Multi-Source Forensics SIEM
"""
        msg.set_content(body)
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(SENDER_EMAIL, SENDER_APP_PASSWORD)
            server.send_message(msg)
        print(f"[!] Critical alert email dispatched for [{src}] - {threat}")
    except Exception as e:
        print(f"[-] Failed to dispatch email: {e}")

def query_llm_for_triage(log_text, source_name):
    """Sends log text to Gemma 2 with source environment context."""
    prompt = f"""You are an elite Cyber Forensics SOC Analyst.
Analyze the following log received from environment source: [{source_name}].
Return ONLY a valid JSON object matching this schema:
{{
  "severity": "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO",
  "threat_type": "string",
  "summary": "One concise sentence describing the finding in the context of {source_name}.",
  "recommended_action": "Actionable mitigation step."
}}

Classification Criteria:
- "INFO" / "LOW": Isolated single authentication failure, system daemon checks, routine ping/status tests.
- "MEDIUM": Multiple password failures on standard accounts, port probing, cloud metadata query anomalies.
- "HIGH": Sustained brute force attacks, repeated root/admin auth attempts, unauthorized cloud IAM changes, privilege abuse.
- "CRITICAL": Confirmed root/system shell takeover, remote code execution (RCE), kernel exploit, data exfiltration.

Log to evaluate:
{log_text}
"""
    payload = {
        "model": MODEL_NAME,
        "prompt": prompt,
        "stream": False,
        "format": "json",
        "options": {
            "temperature": 0.1,
            "num_ctx": 4096
        }
    }

    try:
        response = requests.post(OLLAMA_API, json=payload, timeout=15)
        raw_output = response.json().get("response", "{}")
        return json.loads(raw_output)
    except Exception as e:
        return {
            "severity": "LOW",
            "threat_type": "PARSER_FALLBACK",
            "summary": f"Automated evaluation fallback: {str(e)}",
            "recommended_action": "Inspect log payload manually in SOC console."
        }

def process_ai_triage(data, source_name):
    """Asynchronous background worker for AI triage and persistence."""
    global LAST_EMAIL_SENT
    check_resources()

    log_content = data if isinstance(data, str) else json.dumps(data)
    triage_result = query_llm_for_triage(log_content, source_name)

    now_iso = datetime.now().isoformat()
    record = {
        "id": hashlib.md5(f"{now_iso}:{log_content}".encode()).hexdigest()[:8],
        "source": source_name,
        "timestamp": now_iso,
        "original_log": data,
        "triage": triage_result
    }

    # Update Telemetry Stats
    if source_name in source_activity:
        source_activity[source_name]["last_seen"] = now_iso
        source_activity[source_name]["count"] += 1

    alerts_cache.append(record)
    with open(OUTPUT_FILE, "a") as f:
        f.write(json.dumps(record) + "\n")

    # Critical Email Alert Gate
    current_time = time.time()
    is_critical = triage_result.get("severity", "").upper() == "CRITICAL"
    cooldown_passed = (current_time - LAST_EMAIL_SENT) > EMAIL_COOLDOWN_SECONDS

    if is_critical and cooldown_passed:
        LAST_EMAIL_SENT = current_time
        threading.Thread(target=send_critical_email, args=(record,)).start()

# --- Upgraded SOC Dashboard UI ---
HTML_DASHBOARD = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Multi-Node AI Forensics SIEM</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet">
    <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;700&family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <style>
        body { font-family: 'Inter', sans-serif; }
        .font-mono { font-family: 'JetBrains Mono', monospace; }
        ::-webkit-scrollbar { width: 6px; height: 6px; }
        ::-webkit-scrollbar-track { background: #030712; }
        ::-webkit-scrollbar-thumb { background: #1f2937; border-radius: 4px; }
        ::-webkit-scrollbar-thumb:hover { background: #374151; }
        .glass-card { background: rgba(17, 24, 39, 0.7); backdrop-filter: blur(12px); border: 1px solid rgba(31, 41, 55, 0.7); }
        .glow-cyan { box-shadow: 0 0 15px -3px rgba(6, 182, 212, 0.2); }
    </style>
</head>
<body class="bg-gray-950 text-gray-100 min-h-screen antialiased flex flex-col justify-between">

    <!-- Top Navigation -->
    <header class="glass-card sticky top-0 z-50 border-b border-gray-800/80 px-6 py-3.5">
        <div class="max-w-7xl mx-auto flex flex-wrap justify-between items-center gap-4">
            <div class="flex items-center space-x-3.5">
                <div class="h-9 w-9 rounded-lg bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center text-cyan-400 glow-cyan">
                    <i class="fa-solid fa-shield-virus text-lg"></i>
                </div>
                <div>
                    <div class="flex items-center gap-2">
                        <h1 class="text-sm font-bold tracking-wider uppercase text-gray-100">NextGen Forensics Engine</h1>
                        <span class="text-[10px] font-mono bg-cyan-950/80 text-cyan-300 border border-cyan-700/50 px-2 py-0.5 rounded">Gemma 2 (2B)</span>
                    </div>
                    <p class="text-[11px] text-gray-400">Enterprise Multi-Node Telemetry & Autonomous Threat Triage</p>
                </div>
            </div>

            <!-- Ingestion Node Statuses -->
            <div class="flex items-center gap-3">
                <div class="flex items-center gap-2 bg-gray-900/80 border border-gray-800 px-3 py-1.5 rounded-lg text-xs">
                    <span class="h-2 w-2 rounded-full bg-blue-500 animate-pulse"></span>
                    <span class="text-gray-400">VMware:</span>
                    <span id="nodeVMware" class="font-mono text-gray-200 font-semibold">0</span>
                </div>
                <div class="flex items-center gap-2 bg-gray-900/80 border border-gray-800 px-3 py-1.5 rounded-lg text-xs">
                    <span class="h-2 w-2 rounded-full bg-amber-500 animate-pulse"></span>
                    <span class="text-gray-400">AWS EC2:</span>
                    <span id="nodeAWS" class="font-mono text-gray-200 font-semibold">0</span>
                </div>
                <div class="flex items-center gap-2 bg-gray-900/80 border border-gray-800 px-3 py-1.5 rounded-lg text-xs">
                    <span class="h-2 w-2 rounded-full bg-purple-500 animate-pulse"></span>
                    <span class="text-gray-400">Node 3:</span>
                    <span id="node3" class="font-mono text-gray-200 font-semibold">0</span>
                </div>
                <button onclick="clearDatabase()" class="text-xs bg-rose-950/60 hover:bg-rose-900 text-rose-300 border border-rose-800/60 px-3 py-1.5 rounded-lg transition flex items-center gap-1.5">
                    <i class="fa-solid fa-trash-can text-[11px]"></i> Wipe Logs
                </button>
            </div>
        </div>
    </header>

    <!-- Main SOC Workspace -->
    <main class="max-w-7xl mx-auto w-full px-6 py-6 grid grid-cols-1 lg:grid-cols-3 gap-6 flex-grow">

        <!-- Ingested Threat Stream (2 Cols) -->
        <section class="lg:col-span-2 space-y-4">
            
            <!-- Controls Bar -->
            <div class="flex flex-wrap items-center justify-between gap-3 glass-card p-3 rounded-xl">
                <div class="flex items-center gap-2 text-xs font-semibold text-gray-300">
                    <i class="fa-solid fa-wave-square text-cyan-400 animate-pulse"></i>
                    <span>Live Threat Stream</span>
                </div>

                <div class="flex items-center gap-2">
                    <!-- Source Filter -->
                    <select id="filterSource" onchange="renderAlerts()" class="bg-gray-900 border border-gray-700 text-xs rounded-lg px-2.5 py-1.5 text-gray-300 focus:outline-none focus:border-cyan-500">
                        <option value="ALL">All Nodes</option>
                        <option value="VMware">VMware</option>
                        <option value="AWS_EC2">AWS EC2</option>
                        <option value="Source_3">Node 3</option>
                    </select>

                    <!-- Severity Filter -->
                    <select id="filterSeverity" onchange="renderAlerts()" class="bg-gray-900 border border-gray-700 text-xs rounded-lg px-2.5 py-1.5 text-gray-300 focus:outline-none focus:border-cyan-500">
                        <option value="ALL">All Severities</option>
                        <option value="CRITICAL">Critical</option>
                        <option value="HIGH">High</option>
                        <option value="MEDIUM">Medium</option>
                        <option value="LOW">Low / Info</option>
                    </select>

                    <!-- Search Input -->
                    <div class="relative">
                        <i class="fa-solid fa-magnifying-glass absolute left-2.5 top-2 text-[11px] text-gray-500"></i>
                        <input id="searchInput" oninput="renderAlerts()" type="text" placeholder="Search payloads/threats..." class="bg-gray-900 border border-gray-700 text-xs rounded-lg pl-7 pr-3 py-1.5 text-gray-200 focus:outline-none focus:border-cyan-500 w-44">
                    </div>
                </div>
            </div>

            <!-- Feed Stream List -->
            <div id="alertsContainer" class="space-y-3 max-h-[72vh] overflow-y-auto pr-1">
                <div class="text-center py-20 text-gray-600 text-xs font-mono">
                    <i class="fa-solid fa-satellite-dish text-2xl mb-2 text-gray-700 animate-bounce"></i><br>
                    Listening on ingestion endpoints: /logs/vmware, /logs/aws_ec2, /logs/source3
                </div>
            </div>
        </section>

        <!-- Right Side: Analytics & Interactive Manual Triage -->
        <aside class="space-y-5">
            
            <!-- Quick Metrics Grid -->
            <div class="grid grid-cols-2 gap-3">
                <div class="glass-card p-3.5 rounded-xl border border-gray-800">
                    <span class="text-[11px] text-gray-400 font-medium">Total Ingested</span>
                    <div id="totalCount" class="text-2xl font-bold font-mono text-cyan-400 mt-1">0</div>
                </div>
                <div class="glass-card p-3.5 rounded-xl border border-gray-800">
                    <span class="text-[11px] text-gray-400 font-medium">Critical / High</span>
                    <div id="criticalCount" class="text-2xl font-bold font-mono text-rose-400 mt-1">0</div>
                </div>
            </div>

            <!-- Manual Triage Workbench -->
            <div class="glass-card p-4 rounded-xl border border-gray-800 space-y-3">
                <div class="flex items-center justify-between">
                    <h3 class="text-xs font-bold uppercase tracking-wider text-gray-200 flex items-center gap-2">
                        <i class="fa-solid fa-microchip text-cyan-400"></i> Manual Forensics Sandbox
                    </h3>
                    <span class="text-[10px] text-gray-500 font-mono">Direct AI Hook</span>
                </div>
                <p class="text-[11px] text-gray-400">Inject raw tool outputs (e.g. Nmap, AWS GuardDuty, Auth traces) directly for immediate triage:</p>

                <!-- Source Selector for Manual Test -->
                <div>
                    <label class="text-[10px] text-gray-400 font-semibold block mb-1">Target Environment Node:</label>
                    <select id="manualSource" class="w-full bg-gray-900 border border-gray-800 rounded-lg p-2 text-xs text-gray-200 focus:outline-none focus:border-cyan-500">
                        <option value="VMware">VMware Environment</option>
                        <option value="AWS_EC2">AWS EC2 Cloud Instance</option>
                        <option value="Source_3">Node 3 (Custom/Future)</option>
                    </select>
                </div>

                <textarea id="manualInput" rows="5" class="w-full bg-gray-950 border border-gray-800 rounded-lg p-3 text-xs text-gray-200 font-mono focus:outline-none focus:border-cyan-500" placeholder="Paste authentication strings, AWS CloudTrail JSON, or raw tool logs..."></textarea>

                <button onclick="submitManualLog()" id="analyzeBtn" class="w-full bg-cyan-600 hover:bg-cyan-500 text-white font-semibold text-xs py-2.5 px-4 rounded-lg transition flex justify-center items-center gap-2 shadow-lg shadow-cyan-950">
                    <i class="fa-solid fa-bolt"></i> <span>Execute Forensics Triage</span>
                </button>
            </div>

            <!-- Endpoint Telemetry Help Box -->
            <div class="glass-card p-4 rounded-xl border border-gray-800 text-[11px] space-y-2 text-gray-400 font-mono">
                <div class="text-xs font-bold text-gray-300 font-sans flex items-center gap-1.5 mb-2">
                    <i class="fa-solid fa-network-wired text-cyan-400"></i> Ingestion Endpoints
                </div>
                <div class="bg-gray-950 p-2 rounded border border-gray-900">
                    <span class="text-blue-400">POST</span> /logs/vmware
                </div>
                <div class="bg-gray-950 p-2 rounded border border-gray-900">
                    <span class="text-amber-400">POST</span> /logs/aws_ec2
                </div>
                <div class="bg-gray-950 p-2 rounded border border-gray-900">
                    <span class="text-purple-400">POST</span> /logs/source3
                </div>
            </div>

        </aside>
    </main>

    <script>
        let alertsData = [];

        function getSeverityBadge(sev) {
            const s = (sev || 'INFO').toUpperCase();
            if (s === 'CRITICAL') return '<span class="bg-rose-950 text-rose-300 border border-rose-700/60 px-2 py-0.5 rounded text-[10px] font-bold tracking-wide">CRITICAL</span>';
            if (s === 'HIGH') return '<span class="bg-orange-950 text-orange-300 border border-orange-700/60 px-2 py-0.5 rounded text-[10px] font-bold tracking-wide">HIGH</span>';
            if (s === 'MEDIUM') return '<span class="bg-amber-950 text-amber-300 border border-amber-700/60 px-2 py-0.5 rounded text-[10px] font-bold tracking-wide">MEDIUM</span>';
            return '<span class="bg-blue-950 text-blue-300 border border-blue-700/60 px-2 py-0.5 rounded text-[10px] font-bold tracking-wide">INFO / LOW</span>';
        }

        function getSourceBadge(src) {
            if (src === 'AWS_EC2') return '<span class="bg-amber-950/80 text-amber-400 border border-amber-800/80 px-2 py-0.5 rounded text-[10px] font-mono font-semibold"><i class="fa-brands fa-aws mr-1"></i>AWS_EC2</span>';
            if (src === 'Source_3') return '<span class="bg-purple-950/80 text-purple-400 border border-purple-800/80 px-2 py-0.5 rounded text-[10px] font-mono font-semibold"><i class="fa-solid fa-server mr-1"></i>NODE_3</span>';
            return '<span class="bg-blue-950/80 text-blue-400 border border-blue-800/80 px-2 py-0.5 rounded text-[10px] font-mono font-semibold"><i class="fa-solid fa-desktop mr-1"></i>VMWARE</span>';
        }

        function renderAlerts() {
            const container = document.getElementById('alertsContainer');
            const sevFilter = document.getElementById('filterSeverity').value;
            const srcFilter = document.getElementById('filterSource').value;
            const query = document.getElementById('searchInput').value.toLowerCase();

            let countVM = 0, countAWS = 0, count3 = 0;
            alertsData.forEach(a => {
                if (a.source === 'VMware') countVM++;
                else if (a.source === 'AWS_EC2') countAWS++;
                else if (a.source === 'Source_3') count3++;
            });

            document.getElementById('nodeVMware').innerText = countVM;
            document.getElementById('nodeAWS').innerText = countAWS;
            document.getElementById('node3').innerText = count3;

            const filtered = alertsData.filter(a => {
                const s = (a.triage?.severity || 'LOW').toUpperCase();
                const src = a.source || 'VMware';
                
                // Severity Filter
                let passSev = (sevFilter === 'ALL') ? true : (sevFilter === 'LOW' ? (s === 'LOW' || s === 'INFO') : s === sevFilter);
                // Source Filter
                let passSrc = (srcFilter === 'ALL') ? true : src === srcFilter;
                // Text Query Filter
                let payloadText = JSON.stringify(a).toLowerCase();
                let passText = !query || payloadText.includes(query);

                return passSev && passSrc && passText;
            });

            document.getElementById('totalCount').innerText = alertsData.length;
            document.getElementById('criticalCount').innerText = alertsData.filter(a => ['CRITICAL', 'HIGH'].includes((a.triage?.severity || '').toUpperCase())).length;

            if (filtered.length === 0) {
                container.innerHTML = '<div class="text-center py-16 text-gray-500 text-xs font-mono">No matching forensic telemetry found for current filters.</div>';
                return;
            }

            container.innerHTML = filtered.slice().reverse().map(item => `
                <div class="glass-card border border-gray-800/90 hover:border-gray-700 transition rounded-xl p-4 space-y-3">
                    <div class="flex items-center justify-between gap-2 flex-wrap">
                        <div class="flex items-center gap-2">
                            ${getSourceBadge(item.source)}
                            ${getSeverityBadge(item.triage?.severity)}
                            <span class="text-xs font-mono text-cyan-300 font-semibold">${item.triage?.threat_type || 'ANOMALY'}</span>
                        </div>
                        <span class="text-[11px] font-mono text-gray-500">${new Date(item.timestamp).toLocaleTimeString()}</span>
                    </div>

                    <p class="text-xs font-medium text-gray-200 leading-relaxed">${item.triage?.summary || 'Log evaluated by inference engine.'}</p>

                    ${item.triage?.recommended_action ? `
                    <div class="bg-gray-950/80 border-l-2 border-cyan-500 p-2.5 rounded-r text-[11px] text-gray-300">
                        <span class="font-bold text-cyan-400">Mitigation:</span> ${item.triage.recommended_action}
                    </div>` : ''}

                    <details class="text-[11px] text-gray-400 pt-1">
                        <summary class="cursor-pointer hover:text-gray-200 text-gray-500 font-mono flex items-center gap-1.5">
                            <i class="fa-solid fa-code text-[10px]"></i> View Raw Telemetry Payload
                        </summary>
                        <pre class="mt-2 bg-gray-950 p-3 rounded-lg text-[11px] font-mono text-gray-300 overflow-x-auto border border-gray-900">${typeof item.original_log === 'string' ? item.original_log : JSON.stringify(item.original_log, null, 2)}</pre>
                    </details>
                </div>
            `).join('');
        }

        async function fetchAlerts() {
            try {
                const res = await fetch('/api/alerts');
                alertsData = await res.json();
                renderAlerts();
            } catch (e) {
                console.error("Fetch failure:", e);
            }
        }

        async function submitManualLog() {
            const text = document.getElementById('manualInput').value.trim();
            const source = document.getElementById('manualSource').value;
            if (!text) return;

            const btn = document.getElementById('analyzeBtn');
            btn.innerHTML = '<i class="fa-solid fa-spinner animate-spin"></i> Running Triage...';
            btn.disabled = true;

            try {
                await fetch('/api/analyze-manual', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({ log: text, source: source })
                });
                document.getElementById('manualInput').value = '';
            } finally {
                btn.innerHTML = '<i class="fa-solid fa-bolt"></i> <span>Execute Forensics Triage</span>';
                btn.disabled = false;
            }
        }

        async function clearDatabase() {
            if (confirm("Are you sure you want to permanently erase the alert database across all nodes?")) {
                await fetch('/api/clear', { method: 'POST' });
                alertsData = [];
                renderAlerts();
            }
        }

        setInterval(fetchAlerts, 2000);
        fetchAlerts();
    </script>
</body>
</html>
"""

# --- Flask Multi-Source Endpoints ---

@app.route('/')
def dashboard():
    return render_template_string(HTML_DASHBOARD)

# Ingestion Route for any source: /logs, /logs/vmware, /logs/aws_ec2, /logs/source3
@app.route('/logs', methods=['POST'])
@app.route('/logs/<source_name>', methods=['POST'])
def handle_logs(source_name="VMware"):
    data = request.json
    if not data:
        return jsonify({"status": "empty"}), 400

    # Normalize source names
    src = source_name.strip()
    if src.lower() in ["vmware", "kali"]:
        src = "VMware"
    elif src.lower() in ["aws", "aws_ec2", "ec2"]:
        src = "AWS_EC2"
    elif src.lower() in ["source3", "source_3", "custom"]:
        src = "Source_3"

    log_str = json.dumps(data, sort_keys=True)

    # Filter out local telemetry feedback loops
    if "fluent-bit" in log_str.lower():
        return jsonify({"status": "ignored_internal_telemetry"}), 200

    # Source-isolated cryptographic deduplication
    log_hash = hashlib.md5(f"{src}:{log_str}".encode()).hexdigest()
    if log_hash in seen_logs:
        return jsonify({"status": "duplicate_ignored"}), 200

    seen_logs.add(log_hash)
    threading.Thread(target=process_ai_triage, args=(data, src)).start()
    return jsonify({"status": "received", "source": src}), 200

@app.route('/api/alerts', methods=['GET'])
def get_alerts():
    return jsonify(alerts_cache)

@app.route('/api/analyze-manual', methods=['POST'])
def analyze_manual():
    data = request.json or {}
    log_content = data.get("log", "")
    source_name = data.get("source", "VMware")
    if log_content:
        threading.Thread(target=process_ai_triage, args=(log_content, source_name)).start()
    return jsonify({"status": "processing"}), 202

@app.route('/api/clear', methods=['POST'])
def clear_database():
    global alerts_cache, seen_logs, source_activity
    alerts_cache = []
    seen_logs = set()
    for k in source_activity:
        source_activity[k]["count"] = 0
        source_activity[k]["last_seen"] = None
    if os.path.exists(OUTPUT_FILE):
        os.remove(OUTPUT_FILE)
    print("\n[!] Multi-source forensics database wiped clean.\n")
    return jsonify({"status": "cleared"}), 200

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)
