                    ┌─────────────────────┐
                    │   VMware / Kali     │
                    │     Fluent Bit      │
                    └──────────┬──────────┘
                               │
                               │ Logs
                               ▼
                    ┌─────────────────────┐
                    │     Flask API       │
                    │  Multi-Node Ingest  │
                    └──────────┬──────────┘
                               │
                  ┌────────────┴────────────┐
                  │                         │
                  ▼                         ▼
          Deduplication              Self-Ingestion
          MD5 Hashing                   Filtering
                  │
                  ▼
             Background
              Processing
                  │
                  ▼
          ┌───────────────┐
          │   Gemma 2 2B │
          │   AI Triage   │
          └───────┬───────┘
                  │
                  ▼
          Severity Classification
                  │
          ┌───────┴────────┐
          ▼                ▼
      SOC Dashboard     CRITICAL
                           │
                           ▼
                      SMTP Alert

# AI Forensics Triage Framework 🛡️🧠

A multi-node, AI-powered Security Information and Event Management (SIEM) and log triage pipeline. This framework ingests real-time telemetry from multiple environments (VMware/Local, AWS Cloud, etc.), parses them using a local Large Language Model (Gemma 2 via Ollama) for privacy-preserving threat analysis, and visualizes the results on an interactive SOC dashboard.

## 🌟 Key Features

* **Privacy-First AI Triage:** Uses local LLMs (`gemma2:2b`) via Ollama. No raw security logs are ever sent to third-party APIs like OpenAI or Anthropic.
* **Multi-Node Ingestion:** Dynamic API routing to accept and tag logs from different environments (e.g., `/logs/vmware`, `/logs/aws_ec2`).
* **Cryptographic Deduplication:** Implements MD5 hashing on incoming payloads to drop duplicate logs and prevent Fluent Bit infinite retry loops.
* **Intelligent Alerting:** Automatically dispatches rate-limited SMTP email notifications *only* when the AI confirms a threat severity of `CRITICAL`.
* **Resource Guardrails:** Built-in `psutil` memory monitoring to forcefully halt the pipeline if system RAM exceeds a safety threshold (default 90%) to protect the host machine.
* **Interactive SOC Dashboard:** A Flask-served, Tailwind CSS-styled web interface featuring live threat streams, multi-dimensional filtering, statistical telemetry, and a manual forensics sandbox.

## 🏗️ Architecture

1. **Log Forwarder:** Fluent Bit runs on target machines (Kali Linux VMs, AWS EC2 instances) to monitor `/var/log/auth.log`, `/var/log/syslog`, etc.
2. **Regex Filtering:** Fluent Bit filters for anomalies (errors, failures, unauthorized access) and drops self-referential telemetry noise.
3. **Webhook Receiver:** Python (Flask) receives the JSON payload.
4. **AI Processing:** Flask offloads the log to a background thread where Ollama (Gemma 2) structures the unstructured log into a standardized JSON threat report.
5. **Visualization:** The web dashboard polls the backend and updates the live threat stream.

## 📋 Prerequisites

Before running this framework, ensure you have the following installed:
* **Python 3.8+**
* **Ollama** (Running locally)
* **Fluent Bit** (Installed on your target monitoring nodes)

## 🚀 Installation & Setup

### 1. Clone the Repository
```bash
git clone [https://github.com/yourusername/ai-forensics-triage.git](https://github.com/yourusername/ai-forensics-triage.git)
cd ai-forensics-triage

