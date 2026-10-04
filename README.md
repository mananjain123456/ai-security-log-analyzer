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



