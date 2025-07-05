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

### **Building from Source**

This project uses CMake and the `vcpkg` package manager for a portable and maintainable build process.

#### **1. Prerequisites**

- A C++17 compliant compiler (GCC, Clang, or MSVC).
- [CMake](https://cmake.org/download/) (version 3.16 or higher).
- [Git](https://git-scm.com/downloads).

#### **2. Install vcpkg**

This project uses `vcpkg` to automatically manage its dependencies (`nlohmann-json`, `onnxruntime`, `cpp-httplib`).

```bash
# Clone the vcpkg repository
git clone https://github.com/microsoft/vcpkg.git

# Run the bootstrap script
./vcpkg/bootstrap-vcpkg.sh
# On Windows, use: .\vcpkg\bootstrap-vcpkg.bat
```

Take note of the absolute path to your `vcpkg` directory.

#### **3. Configure and Build**

From the root of the `anomaly-detector` project directory, run the following commands.

```bash
# 1. Configure the project with CMake.
#    Replace <path-to-vcpkg> with the actual path on your system.
cmake -B build -S . -DCMAKE_TOOLCHAIN_FILE=<path-to-vcpkg>/scripts/buildsystems/vcpkg.cmake

# 2. Build the project in Release mode (optimized).
cmake --build build --config Release

#    Alternatively, build in Debug mode (with debug symbols).
#    cmake --build build --config Debug
```

The compiled executable `anomaly_detector` will be located in the `build/` directory.

### **Running the Engine**

You can run the engine by passing the path to a configuration file.

```bash
./build/anomaly_detector config.ini
```

To process logs from standard input, set `log_input_path = "stdin"` in your `config.ini` and pipe logs to the executable:

```bash
cat /var/log/nginx/access.log | ./build/anomaly_detector config.ini
```

#### **Live Interactive Controls**

The engine can be controlled while it's running (on POSIX systems):

| Shortcut | Signal    | Action                              |
| :------- | :-------- | :---------------------------------- |
| `Ctrl+C` | `SIGINT`  | Gracefully shut down (saves state). |
| `Ctrl+R` | `SIGHUP`  | Reload `config.ini` on the fly.     |
| `Ctrl+E` | `SIGUSR1` | Reset engine state (clears memory). |
| `Ctrl+P` | `SIGUSR2` | Pause log processing.               |
| `Ctrl+Q` | `SIGCONT` | Resume log processing.              |

### **Configuration: `config.ini`**

Nearly every aspect of the engine is controlled via `config.ini`. The file is heavily commented and allows you to:

- Set file paths for logs, state files, and alerts.
- Enable or disable entire detection tiers (`Tier1`, `Tier2`, `Tier3`).
- Fine-tune thresholds for rules (e.g., `max_requests_per_ip_in_window`, `z_score_threshold`).
- Configure alert dispatchers (Syslog, HTTP webhook URL, etc.).
- Enable ML data collection to generate training sets.

### **Understanding Alerts**

Alerts are designed to be rich with context to aid investigation.

**Console Output:** A human-readable summary.

```
ALERT DETECTED:
  Timestamp: 2023-01-01 12:02:00.0
  Tier:      TIER1_HEURISTIC
  Source IP: 192.168.0.3
  Reason:    Multiple failed login attempts from IP. Count: 3 in last 60s.
  Score:     78.00
  Action:    Investigate IP for brute-force/credential stuffing; consider blocking.
  Log Line:  7
  Sample:    192.168.0.3|-|01/Jan/2023:12:02:00 +0000|0.200|0.150|POST /login HTTP/1.1|401|100|https://exam...
----------------------------------------
```

**JSON Output:** A machine-readable format sent to files and webhooks, containing the full log and analysis context.

```json
{
  "timestamp_ms": 1672574520000,
  "alert_reason": "Multiple failed login attempts from IP. Count: 3 in last 60s.",
  "detection_tier": "TIER1_HEURISTIC",
  "anomaly_score": 78.0,
  "log_context": {
    "source_ip": "192.168.0.3",
    "request_path": "/login",
    "status_code": 401,
    "user_agent": "Mozilla/5.0"
  },
  "analysis_context": {
    "ip_error_event_zscore": 3.1,
    "is_ua_missing": false
  },
  "raw_log": "..."
}
```

### **License**

This project is licensed under the **MIT License**. See the `LICENSE` file for details.
