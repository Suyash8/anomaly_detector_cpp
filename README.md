# 🐺 Anomaly Detection Engine

_A high-performance C++ engine designed to analyze web server logs, build behavioral baselines, and detect anomalous activity in real-time._

This engine transforms the reactive, manual task of log review into a proactive, automated hunt for threats. It's built in modern C++ for one reason: **performance**. It is designed to process a high volume of logs efficiently, applying layers of increasingly sophisticated detection logic to find the needles in your digital haystack.

![Language](https://img.shields.io/badge/language-C%2B%2B17-blue.svg)
![Build System](https://img.shields.io/badge/build-CMake-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)

---

### **Core Philosophy**

This engine transforms the reactive, manual task of log review into a proactive, automated hunt for threats. It's built on three core principles:

1.  **Layered Defense:** By combining fast heuristics, statistical analysis, and machine learning, we can catch a much wider range of threats.
2.  **Context is King:** The engine provides context by building historical baselines for every IP, URL path, and user session, allowing it to ask: _"Is this behavior normal for **you**?"_
3.  **Performance is a Feature:** Security tools should not cripple the systems they protect. By using modern C++, we ensure high throughput and a low resource footprint.

### **Key Features**

- **Multi-Tiered Detection Engine:**
  - **Tier 1 (Heuristics):** Blazing-fast checks for obvious red flags.
    - Rate-limiting violations (e.g., brute-force, content scraping).
    - Suspicious string matching (`sqlmap`, `../../`, `nmap`) using the efficient Aho-Corasick algorithm.
    - Advanced User-Agent Analysis: Detects missing/headless UAs, known bad bots, outdated browsers, and UA cycling.
    - Threat Intelligence integration for blocking known-malicious IPs.
  - **Tier 2 (Statistical Analysis):** Builds profiles of "normal" behavior and flags significant deviations.
    - **Live Z-Score Calculation:** Measures how far a given request's metrics (latency, size, errors) deviate from the historical average for that specific IP or path.
    - **Behavioral Change Detection:** Catches when a trusted IP suddenly changes its activity pattern.
  - **Tier 3 (Machine Learning):** Uses a pre-trained model to find complex, multi-variate anomalies that simpler rules would miss.
    - **ONNX Runtime:** Executes ML models trained in Python (e.g., Scikit-learn) directly within the C++ application for maximum performance.
    - **Automated Retraining:** Can be configured to periodically retrain its model on new data and hot-swap it without a restart.
- **Stateful and Persistent:** The engine's learned baselines can be saved to disk, allowing it to survive restarts without losing valuable historical context.
- **Flexible Alerting:** Dispatches detailed alerts to multiple destinations simultaneously.
  - Human-readable format for the console.
  - Structured JSON for file logging or sending to a SIEM.
  - Syslog support.
  - Generic HTTP Webhooks for easy integration with tools like Slack or custom dashboards.
- **Operationally Mature:** Designed for real-world use with features like:
  - Centralized configuration via `config.ini`.
  - Graceful shutdown and signal handling.
  - Live configuration reloading and state resets without downtime.

### **How It Works: The Detection Pipeline**

The engine processes each log entry through a well-defined pipeline:

`Log Ingestion -> Parsing -> Analysis & Enrichment -> Rule Evaluation -> Alerting`

1.  **Ingestion & Parsing:** `main.cpp` reads logs from a file or `stdin`. The log is passed to a **pluggable parser** (selected in `config.ini`) which converts the raw text into a structured `LogEntry`. This allows the engine to support various formats like Nginx, Apache, or custom JSON.

2.  **Analysis Engine:** This is the stateful core. It takes the `LogEntry` and enriches it with historical context, producing a comprehensive `AnalyzedEvent`. It tracks statistics and sliding windows for every IP, path, and session it has ever seen.

3.  **Feature Manager:** If Tier 3 is active, this component converts the rich `AnalyzedEvent` into a simple, normalized vector of numbers—the exact format the machine learning model expects.

4.  **Rule Engine:** The `AnalyzedEvent` is passed here for judgment. It checks the event against the configured rules in order of computational cost: Allow/Deny lists first, then Tier 1, Tier 2, and finally Tier 3.

5.  **Alert Manager:** If any rule is triggered, the `AlertManager` formats a detailed alert, handles throttling to prevent alert fatigue, and sends it to all enabled dispatchers (File, Syslog, HTTP, etc.).
