# Anomaly Detection Engine

A C++ engine for analyzing web server logs and detecting unusual activity patterns in real-time.

The main idea here is pretty straightforward - instead of manually sifting through log files looking for problems, this thing automatically builds up a picture of what "normal" looks like for your traffic and flags anything that seems off. It's written in C++17 and can handle a decent amount of logs per second while running several different types of detection algorithms.

![Language](https://img.shields.io/badge/language-C%2B%2B17-blue.svg)
![Build System](https://img.shields.io/badge/build-CMake-blue.svg)
![Dependencies](https://img.shields.io/badge/deps-vcpkg-green.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)

---

## Table of Contents

- [Core Philosophy](#core-philosophy)
- [Key Features](#key-features)
- [Architecture Overview](#architecture-overview)
  - [Detection Pipeline](#detection-pipeline)
  - [Component Organization](#component-organization)
- [Codebase Structure](#codebase-structure)
- [Building from Source](#building-from-source)
  - [Prerequisites](#prerequisites)
  - [Quick Start](#quick-start)
  - [Advanced Build Options](#advanced-build-options)
- [Running the Engine](#running-the-engine)
  - [Basic Usage](#basic-usage)
  - [Live Interactive Controls](#live-interactive-controls)
  - [Configuration Templates](#configuration-templates)
- [Configuration System](#configuration-system)
  - [Configuration Structure](#configuration-structure)
  - [Hot Configuration Reload](#hot-configuration-reload)
  - [Environment Templates](#environment-templates)
- [Detection Tiers Explained](#detection-tiers-explained)
  - [Tier 1: Heuristic Detection](#tier-1-heuristic-detection)
  - [Tier 2: Statistical Analysis](#tier-2-statistical-analysis)
  - [Tier 3: Machine Learning](#tier-3-machine-learning)
  - [Tier 4: Prometheus Integration](#tier-4-prometheus-integration)
- [Monitoring & Metrics](#monitoring--metrics)
- [Memory Management](#memory-management)
- [Development & Testing](#development--testing)
- [Deployment](#deployment)
- [Troubleshooting](#troubleshooting)
- [API Reference](#api-reference)
- [Contributing](#contributing)
- [License](#license)

---

## Core Philosophy

The basic approach is to layer different detection methods instead of relying on just one. Here's the thinking behind it:

1. **Multiple Detection Layers:** Fast pattern matching catches obvious stuff, statistical analysis spots behavioral changes, machine learning finds complex patterns, and external monitoring adds another perspective.
2. **Context Matters:** Rather than just looking at individual requests, the engine keeps track of what's normal for each IP address and URL path. So it can tell the difference between a legitimate user having a busy day versus someone probing your site.
3. **Performance Considerations:** Security tools shouldn't slow down your systems. The code uses modern C++ features and memory optimization to keep resource usage reasonable.
4. **Operational Reality:** Includes monitoring, error recovery, configuration reloading, and other features you actually need when running this in production.

## Key Features

### Multi-Tiered Detection System

The detection works in four tiers, each with different strengths:

- **Tier 1 (Pattern Matching):** Quick checks for known bad things
  - Rate limiting violations (brute force attempts, scraping)
  - Suspicious string patterns using Aho-Corasick algorithm
  - User-Agent analysis - missing UAs, known bad bots, old browsers, UA switching
  - Threat intelligence feeds for known malicious IPs
- **Tier 2 (Statistical Analysis):** Looks for deviations from normal behavior
  - **Z-Score Analysis:** How far current metrics are from historical averages
  - **Behavior Change Detection:** When trusted IPs suddenly act differently
  - **Seasonal Patterns:** Adapts to normal traffic cycles (like higher usage during business hours)
- **Tier 3 (Machine Learning):** Uses trained models for complex pattern recognition
  - **ONNX Runtime:** Runs Python-trained models directly in C++
  - **Model Updates:** Can swap in new models without restarting
  - **Feature Engineering:** About 50 different calculated features for analysis
- **Tier 4 (Prometheus Integration):** Advanced monitoring through PromQL
  - **Custom Metrics:** Define detection rules using Prometheus query language
  - **Historical Data:** Uses Prometheus time-series for trend analysis
  - **Fault Tolerance:** Handles Prometheus connectivity issues gracefully

### Production Features

- **Persistent State:** Learned behavior patterns survive restarts
- **Flexible Alerting:** Sends alerts to multiple places at once
  - Console output for humans
  - JSON format for SIEM systems
  - Syslog integration
  - HTTP webhooks for Slack or custom dashboards
- **Operational Stuff:**
  - Configuration via config.ini file
  - Hot config reloading (no downtime)
  - Graceful shutdown handling
  - Built-in metrics and monitoring
  - Memory management with automatic cleanup

### Performance & Memory stuff

- **Memory Optimizations:**
  - Custom hash tables optimized for IP lookups
  - Object pooling and string interning to reduce allocations
  - Hibernation of inactive state when memory gets tight
  - SIMD optimizations for string matching where possible
- **Threading:**
  - Lock-free data structures in hot paths
  - Work-stealing queues for better load distribution
  - Thread affinity tuning (though this is still experimental)
  - Double-buffered updates so reads don't block

## Architecture Overview

### How it processes logs

Each log entry goes through this pipeline:

```
Log Input → Parsing → Analysis & Context → Rule Checking → Alerting
     ↓         ↓           ↓               ↓           ↓
  File/stdin  LogEntry   AnalyzedEvent   RuleEngine  AlertManager
  MongoDB     Parser     +Features       +Scoring    +Dispatchers
              Pluggable  +Context        +Tiers      +Throttling
```

#### The main stages

1. **Reading & Parsing** (`src/main.cpp`, `src/io/log_readers/`)

   - Reads from files, stdin, or MongoDB
   - Different parsers for nginx, Apache, JSON, etc
   - Turns raw text into structured LogEntry objects

2. **Analysis Engine** (`src/analysis/`)

   - The core piece that adds context to each log entry
   - Creates AnalyzedEvent with 50+ calculated features
   - Keeps track of stats and windows for every IP, path, session
   - Has memory optimizations with cleanup when things get tight

3. **Feature Manager** (`src/models/`)

   - Converts the analyzed event into ML feature vectors
   - Handles normalization and scaling
   - Supports both training mode and inference

4. **Rule Engine** (`src/detection/`)

   - Runs the analyzed event through all the detection rules
   - Processes tiers in order of computational cost
   - Tracks metrics and performance for each rule

5. **Alert Manager** (`src/core/`)
   - Formats alerts with investigation context
   - Throttles duplicate alerts to avoid spam
   - Sends to multiple destinations with different formats

### Code organization

The codebase is split into logical modules:

### Runtime Controls

When the engine is running, you can control it with these signals:

| Signal    | Shortcut | What it does   | Notes                                                    |
| :-------- | :------- | :------------- | :------------------------------------------------------- |
| `SIGINT`  | `Ctrl+C` | Clean shutdown | Saves state, flushes alerts, closes connections properly |
| `SIGHUP`  | `Ctrl+R` | Reload config  | Picks up changes from config.ini without restart         |
| `SIGUSR1` | `Ctrl+E` | Reset state    | Clears all learned data and starts fresh                 |
| `SIGUSR2` | `Ctrl+P` | Pause/resume   | Stops processing but keeps connections open              |
| `SIGTERM` | -        | Force shutdown | Emergency stop, doesn't save state                       |

### Configuration Templates

There are a few pre-made configs to get you started:

```bash
# For development work - more logging and debugging
cp config_templates/development.ini config.ini

# Production setup - stable and secure defaults
cp config_templates/production.ini config.ini

# High throughput - tuned for lots of logs per second
cp config_templates/high_performance.ini config.ini
```

## Configuration System

The configuration uses INI format with hot-reloading and validation.

### Basic structure

Here's how the config is organized:

```ini
# Main settings
log_source_type = file|mongodb|stdin
log_input_path = /path/to/logs
alerts_to_stdout = true
alerts_to_file = true

# Each detection tier can be enabled/disabled
[Tier1]
enabled = true
max_requests_per_ip_in_window = 1000
suspicious_path_substrings = ../,/etc/passwd,sqlmap

[Tier2]
enabled = true
z_score_threshold = 3.5
min_samples_for_z_score = 30

[Tier3]
enabled = false
model_path = models/isolation_forest.onnx
anomaly_score_threshold = 0.6

[Tier4]
enabled = false
prometheus_url = http://localhost:9090
evaluation_interval_seconds = 60

# Other features
[MemoryManagement]
enabled = true
max_memory_usage_mb = 1024
enable_object_pooling = true

[PerformanceMonitoring]
enabled = true
enable_load_shedding = true
max_cpu_usage_percent = 80.0

[DynamicLearning]
enabled = true
confidence_threshold = 0.95
seasonal_detection_sensitivity = 0.8
```

### Reloading config

You can change configuration without restarting:

```bash
# Send reload signal
kill -HUP <pid>

# Or if running in terminal
# Press Ctrl+R
```

The system checks the changes before applying them and logs any validation errors.

### Environment-specific configs

Different environments need different settings:

**Development** (`config_templates/development.ini`):

- More debugging output and logging
- Lower thresholds for easier testing
- Verbose error reporting
- Fewer retry attempts for faster feedback

**Production** (`config_templates/production.ini`):

- Optimized for stability
- Conservative performance settings
- Full error handling
- Security-focused defaults

**High-Performance** (`config_templates/high_performance.ini`):

- Tuned for processing lots of logs
- Higher memory limits
- Aggressive performance settings
- Minimal logging overhead

## Detection Tiers Explained

Here's how the four-tier detection system works:

### Tier 1: Pattern Matching

Fast rule-based checks for known attack patterns:

#### Rate limiting & brute force detection

```cpp
// Example: detecting brute force login attempts
if (failed_login_count > config.max_failed_logins_per_ip) {
    create_alert(TIER1_HEURISTIC, "Brute force attack detected",
                 HIGH_SEVERITY, "Block IP immediately");
}
```

#### Pattern matching

- **Aho-Corasick Algorithm**: Searches for multiple suspicious patterns efficiently
- **Path Analysis**: Looks for directory traversal (`../`), config access (`/etc/passwd`)
- **User-Agent Analysis**: Identifies bots, scanners, and outdated browsers
- **Threat Intel**: Checks against external IP reputation feeds

#### Implementation details

- **Location**: `src/detection/rule_engine.cpp` (functions: `check_requests_per_ip_rule`, `check_suspicious_string_rules`)
- **Key Files**: `src/utils/aho_corasick.hpp`, `src/io/threat_intel/intel_manager.hpp`
- **Performance**: Usually under 1ms per event

### Tier 2: Statistical Analysis

Builds behavioral baselines and detects statistical anomalies:

#### Z-Score calculation

```cpp
// Example: detecting unusual request volume for an IP
double z_score = (current_requests - mean_requests) / std_deviation;
if (z_score > config.z_score_threshold) {
    create_alert(TIER2_STATISTICAL, "Request volume anomaly",
                 MEDIUM_SEVERITY, "Investigate unusual activity pattern");
}
```

#### Features it tracks

- **Request Patterns**: Volume, timing, frequency distributions
- **Error Rates**: HTTP 4xx/5xx response patterns
- **Content Access**: HTML vs asset request ratios
- **Session Behavior**: Path traversal patterns, session duration
- **Time Patterns**: Time-of-day and day-of-week variations

#### Implementation details

- **Location**: `src/analysis/analysis_engine.cpp` (main analysis loop)
- **Key Components**: `src/analysis/per_ip_state.hpp`, `src/analysis/per_path_state.hpp`
- **Memory Management**: Uses sliding windows and efficient stats tracking

### Tier 3: Machine Learning

Uses pre-trained ML models for complex anomaly detection:

#### ONNX Runtime integration

```cpp
// Simplified ML inference flow
std::vector<float> features = feature_manager.extract_features(analyzed_event);
std::vector<float> output = model_manager.predict(features);
double anomaly_score = output[0];

if (anomaly_score > config.anomaly_score_threshold) {
    create_alert(TIER3_ML, "ML-detected anomaly",
                 VARIABLE_SEVERITY, "Review complex behavioral pattern");
}
```

#### Feature engineering (about 50 features)

- **Request Characteristics**: Size, timing, response codes
- **Behavioral Metrics**: Request diversity, session patterns
- **Statistical Features**: Z-scores, percentiles, entropy measures
- **Temporal Features**: Time-based patterns and sequences

#### Model management

- **Training**: Use `ml/train.py` to create ONNX models from collected data
- **Hot-Swapping**: Models can be updated without restarting
- **Data Collection**: Engine can collect training data while running

#### Implementation details

- **Location**: `src/models/model_manager.hpp`, `src/models/feature_manager.hpp`
- **Dependencies**: ONNX Runtime, custom feature engineering
- **Performance**: Optimized inference with batch processing

### Tier 4: Prometheus Integration

Advanced monitoring and alerting through PromQL queries:

#### PromQL rule definition

```yaml
# Example Prometheus rule for detecting DDoS
groups:
  - name: anomaly_detection
    rules:
      - alert: HighRequestRate
        expr: rate(http_requests_total[5m]) > 1000
        for: 2m
        annotations:
          summary: "High request rate detected"
          description: "{{ $labels.instance }} is receiving {{ $value }} requests/sec"
```

#### Integration features

- **Circuit Breaker**: Handles Prometheus connectivity issues gracefully
- **Template Variables**: Dynamic PromQL queries with context substitution
- **Time-Series Analysis**: Uses Prometheus historical data
- **Custom Metrics**: Engine exports detailed metrics for external monitoring

#### Implementation details

- **Location**: `src/analysis/prometheus_anomaly_detector.hpp`
- **Dependencies**: HTTP client for Prometheus API
- **Configuration**: PromQL rules defined in config files

## Monitoring & Metrics

The engine provides monitoring and observability:

### Built-in web interface

There's a simple web interface at `http://localhost:9090` (port is configurable):

- **Current stats**: Processing rates, alert counts, etc.
- **Performance info**: Memory usage, CPU, latency numbers
- **Rule engine status**: How each tier is performing
- **System health**: Component status, errors, uptime

### Prometheus metrics export

Exports detailed metrics for external monitoring:

```prometheus
# Request processing metrics
anomaly_detector_events_processed_total{tier="tier1"} 15420
anomaly_detector_processing_time_seconds{component="analysis"} 0.0023

# Alert metrics
anomaly_detector_alerts_generated_total{severity="high"} 42
anomaly_detector_alerts_throttled_total{reason="duplicate"} 128

# Memory metrics
anomaly_detector_memory_usage_bytes 524288000
anomaly_detector_ip_states_count 1250
anomaly_detector_path_states_count 890

# Rule engine metrics
anomaly_detector_rule_evaluations_total{rule="brute_force"} 3420
anomaly_detector_rule_hits_total{rule="suspicious_paths"} 89
```

### Performance profiling

Built-in timing tools for optimization:

```cpp
// Enable in config.ini
enable_deep_timing = true

// Results get exported to performance reports
{
  "component": "analysis_engine",
  "avg_latency_ms": 2.3,
  "p95_latency_ms": 5.1,
  "p99_latency_ms": 12.4,
  "throughput_events_per_sec": 8750
}
```

## Memory Management

The engine includes memory optimization features:

### Object pooling

Commonly allocated objects get pooled to reduce allocation overhead:

```cpp
// String interning for common values
auto ip_id = string_pool->intern(log_entry.ip);
auto path_id = string_pool->intern(log_entry.path);

// Object pools for state objects
auto ip_state = ip_state_pool->acquire();
// ... use object ...
ip_state_pool->release(ip_state);
```

### Memory pressure handling

Automatic cleanup when memory usage gets high:

```cpp
if (memory_manager->is_memory_pressure()) {
    // Put inactive state objects into hibernation
    analysis_engine->hibernate_inactive_states();

    // Compact data structures
    analysis_engine->compact_memory();

    // Remove least recently used entries
    analysis_engine->evict_lru_entries();
}
```

### Optimized data structures

Custom implementations for performance:

- **Hash Tables**: Optimized for IP address lookups
- **Sliding Windows**: Memory-efficient circular buffers
- **State Hibernation**: Serialize inactive objects to save memory
- **SIMD Operations**: Vectorized string matching and calculations (where the CPU supports it)

Implementation: `src/core/memory_manager.hpp`, `src/analysis/optimized_analysis_engine.hpp`

#### Live Interactive Controls

When the engine is running you can control it with these signals (Unix systems):

| Shortcut | Signal    | What it does                        |
| :------- | :-------- | :---------------------------------- |
| `Ctrl+C` | `SIGINT`  | Clean shutdown (saves state).       |
| `Ctrl+R` | `SIGHUP`  | Reload `config.ini` on the fly.     |
| `Ctrl+E` | `SIGUSR1` | Reset engine state (clears memory). |
| `Ctrl+P` | `SIGUSR2` | Pause log processing.               |
| `Ctrl+Q` | `SIGCONT` | Resume log processing.              |

### Config file: `config.ini`

Almost everything is controlled through `config.ini`. The file has lots of comments and lets you:

- Set file paths for logs, state files, and alerts.
- Turn entire detection tiers on or off (`Tier1`, `Tier2`, `Tier3`, `Tier4`).
- Adjust thresholds for rules (like `max_requests_per_ip_in_window`, `z_score_threshold`).
- Configure alert outputs (syslog, HTTP webhooks, etc.).
- Enable ML data collection to build training sets.

### Understanding alerts

Alerts include context to help with investigation.

**Console Output:** Human-readable summary.

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

**JSON Output:** Machine-readable format for files and webhooks, includes full context.

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

### Codebase Structure

The project follows a modular architecture with clear separation of concerns:

```

anomaly*detector_cpp/
├── src/ # Main source code
│ ├── main.cpp # Application entry point & orchestration
│ ├── analysis/ # Core analysis and behavioral modeling
│ │ ├── analysis_engine.hpp/cpp # Main analysis engine
│ │ ├── optimized_analysis_engine.hpp # Memory-optimized variant
│ │ ├── analyzed_event.hpp # Enriched log event structure
│ │ ├── per_ip_state.hpp/cpp # Per-IP behavioral tracking
│ │ ├── per_path_state.hpp/cpp # Per-URL behavioral tracking
│ │ ├── per_session_state.hpp/cpp # Session-based tracking
│ │ └── prometheus_anomaly_detector.hpp # Tier 4 Prometheus integration
│ ├── core/ # Fundamental system components
│ │ ├── alert.hpp/cpp # Alert data structures
│ │ ├── alert_manager.hpp/cpp # Alert orchestration & dispatching
│ │ ├── config.hpp/cpp # Configuration management
│ │ ├── log_entry.hpp # Parsed log representation
│ │ ├── logger.hpp/cpp # Logging infrastructure
│ │ ├── memory_manager.hpp/cpp # Memory optimization & pooling
│ │ ├── metrics_manager.hpp/cpp # Performance metrics collection
│ │ └── production_hardening.hpp # Production safety features
│ ├── detection/ # Rule engines and detection logic
│ │ ├── rule_engine.hpp/cpp # Main rule evaluation engine
│ │ ├── optimized_rule_engine.hpp # Performance-optimized variant
│ │ └── rules/ # Individual rule implementations
│ │ └── scoring.hpp/cpp # Risk scoring algorithms
│ ├── io/ # Input/Output and external integrations
│ │ ├── alert_dispatch/ # Alert delivery mechanisms
│ │ │ ├── file_dispatcher.hpp/cpp # File-based alert logging
│ │ │ ├── http_dispatcher.hpp/cpp # Webhook/HTTP alert delivery
│ │ │ └── syslog_dispatcher.hpp/cpp # Syslog integration
│ │ ├── db/ # Database integrations
│ │ │ ├── mongo_manager.hpp/cpp # MongoDB connectivity
│ │ │ └── optimized_mongo_manager.hpp # High-performance MongoDB client
│ │ ├── log_readers/ # Log input sources
│ │ │ ├── base_log_reader.hpp # Abstract reader interface
│ │ │ ├── file_log_reader.hpp/cpp # File-based log reading
│ │ │ ├── mongo_log_reader.hpp/cpp # MongoDB log collection
│ │ │ └── optimized_file_log_reader.hpp # Memory-mapped file reader
│ │ ├── threat_intel/ # External threat intelligence
│ │ │ ├── intel_manager.hpp/cpp # Threat feed management
│ │ │ ├── optimized_intel_manager.hpp # High-performance variant
│ │ │ └── dns_cache.hpp/cpp # DNS resolution caching
│ │ └── web/ # Web server for monitoring
│ │ └── web_server.hpp/cpp # HTTP monitoring interface
│ ├── learning/ # Machine learning and adaptive systems
│ │ └── dynamic_learning_engine.hpp/cpp # Adaptive threshold management
│ ├── models/ # ML model management and features
│ │ ├── feature_manager.hpp/cpp # ML feature engineering
│ │ ├── model_data_collector.hpp/cpp # Training data collection
│ │ └── model_manager.hpp/cpp # ONNX model lifecycle
│ ├── tools/ # Utility applications and scripts
│ └── utils/ # Common utilities and helpers
│ ├── aho_corasick.hpp/cpp # Pattern matching algorithms
│ ├── advanced_threading.hpp/cpp # Thread optimization utilities
│ ├── bloom_filter.hpp/cpp # Probabilistic data structures
│ ├── circuit_breaker.hpp/cpp # Fault tolerance patterns
│ ├── graceful_degradation_manager.hpp # Performance degradation handling
│ ├── memory_profiler.hpp/cpp # Memory usage profiling
│ ├── performance_monitor.hpp/cpp # System performance tracking
│ ├── scoped_timer.hpp # Performance timing utilities
│ ├── simd_optimizations.hpp/cpp # SIMD acceleration
│ ├── sliding_window.hpp/cpp # Time-window data structures
│ ├── string_interning.hpp/cpp # Memory-efficient string handling
│ ├── ua_parser.hpp/cpp # User-Agent parsing utilities
│ └── utils.hpp/cpp # General utility functions
├── tests/ # Test suite
│ ├── test_analysis_engine.cpp # Analysis engine unit tests
│ ├── test_memory_monitoring.cpp # Memory management tests
│ ├── test_prometheus*_.cpp # Prometheus integration tests
│ ├── test*rule_engine*_.cpp # Rule engine test suites
│ ├── test*tier4_integration.cpp # Tier 4 integration tests
│ └── test*\*.cpp # Additional test files
├── config_templates/ # Configuration templates
│ ├── development.ini # Development environment config
│ ├── production.ini # Production environment config
│ └── high_performance.ini # High-throughput config
├── data/ # Runtime data and examples
│ ├── allowlist.txt # IP allowlist example
│ ├── sample_logs.txt # Sample log data
│ └── fake.log # Test log data
├── docs/ # Documentation
│ ├── CONFIGURATION.md # Configuration system docs
│ └── operations/ # Operational guides
├── ml/ # Machine learning components
│ ├── train.py # Model training script
│ └── requirements.txt # Python ML dependencies
├── monitoring/ # Monitoring and observability
│ ├── grafana/ # Grafana dashboards
│ ├── PROMQL_EXAMPLES.md # Prometheus query examples
│ └── README.md # Monitoring setup guide
├── third_party/ # External dependencies
│ └── onnxruntime/ # ONNX Runtime binaries
├── build/ # Build artifacts (generated)
├── vcpkg/ # Package manager (generated)
├── vcpkg_installed/ # Installed packages (generated)
├── CMakeLists.txt # CMake build configuration
├── vcpkg.json # Dependency manifest
├── build.sh # Build automation script
├── config.ini # Main configuration file
└── README.md # This file

````

### Key Components Explained

#### Core Analysis (`src/analysis/`)

- **`analysis_engine.hpp/cpp`**: The heart of the system. Maintains behavioral state for every IP, path, and session. Enriches raw log entries with historical context, statistical measures, and behavioral flags.

- **`optimized_analysis_engine.hpp`**: Memory-optimized variant using custom hash tables, object pooling, and hibernation mechanisms for high-throughput scenarios (10,000+ logs/sec).

- **`per_ip_state.hpp/cpp`**: Tracks per-IP metrics like request rates, error rates, user-agent changes, failed logins, and path diversity. Implements sliding windows and statistical calculations.

- **`per_path_state.hpp/cpp`**: Monitors per-URL behavior including access patterns, response times, and error rates to detect path-specific attacks.

- **`per_session_state.hpp/cpp`**: Session-based tracking that correlates requests across time to detect session-based attacks and behavioral anomalies.

#### Detection System (`src/detection/`)

- **`rule_engine.hpp/cpp`**: Orchestrates the multi-tier detection system. Evaluates events against increasingly sophisticated rules, manages scoring, and integrates with all detection tiers.

- **`rules/scoring.hpp/cpp`**: Implements risk scoring algorithms that combine evidence from multiple detection tiers into actionable threat scores.

#### I/O Systems (`src/io/`)

- **Alert Dispatching (`alert_dispatch/`)**: Multiple alert delivery channels including file logging, HTTP webhooks, and syslog integration with configurable formatting and throttling.

- **Log Readers (`log_readers/`)**: Pluggable log input system supporting files, MongoDB, and optimized memory-mapped reading for high-throughput scenarios.

- **Threat Intelligence (`threat_intel/`)**: Integration with external threat feeds, IP reputation services, and DNS-based blacklists with caching and update management.

#### Utilities (`src/utils/`)

- **Performance Optimizations**: SIMD string matching, advanced threading primitives, lock-free data structures, and memory profiling tools.

- **Production Features**: Circuit breakers, graceful degradation, error recovery, and comprehensive performance monitoring.

## Building from Source

### Getting Started

You'll need:

- **Compiler**: GCC 11+ or Clang 13+ with C++17 support
- **CMake**: Version 3.20 or higher
- **Git**: For pulling dependencies
- **Python 3.8+**: For ML model training (optional)

### Quick setup

```bash
# Clone the repo
git clone <repository-url>
cd anomaly_detector_cpp

# Get dependencies via vcpkg
git submodule update --init --recursive
./vcpkg/bootstrap-vcpkg.sh

# Build it (Release mode)
./build.sh release

# Run with example config
./build/bin/ad-log-ingestor config.ini
````

### Build options

```bash
# Build with tests
./build.sh test

# Build and run tests
./build.sh test run

# Manual cmake if you want more control
cmake -B build -S . \
  -DCMAKE_TOOLCHAIN_FILE=./vcpkg/scripts/buildsystems/vcpkg.cmake \
  -DCMAKE_BUILD_TYPE=Release \
  -DBUILD_TESTING=ON \
  -DENABLE_SIMD_OPTIMIZATIONS=ON \
  -DENABLE_MEMORY_PROFILING=ON

# Build specific targets
cmake --build build --target ad-log-ingestor
cmake --build build --target ad-event-processor
cmake --build build --target tests
```

The build creates two main executables:

- **`ad-log-ingestor`**: Main anomaly detection engine
- **`ad-event-processor`**: Batch processing version for high throughput

## Running the Engine

### Basic usage

```bash
# Run with config file
./build/bin/ad-log-ingestor config.ini

# Read logs from stdin (useful with tail)
tail -f /var/log/nginx/access.log | ./build/bin/ad-log-ingestor config.ini

# MongoDB log source (set this up in config.ini first)
./build/bin/ad-log-ingestor config.ini

# Use one of the template configs
cp config_templates/production.ini my_config.ini
./build/bin/ad-log-ingestor my_config.ini
```

## Development & Testing

### Test suite

There's a comprehensive test suite to make sure things work:

```bash
# Build and run all tests
./build.sh test run

# Run specific test categories
cd build && ctest -R "test_analysis"     # Analysis engine tests
cd build && ctest -R "test_rule_engine"  # Rule engine tests
cd build && ctest -R "test_memory"       # Memory management tests
cd build && ctest -R "test_prometheus"   # Prometheus integration tests
cd build && ctest -R "test_tier4"        # Tier 4 integration tests

# Run tests with verbose output
cd build && ctest --output-on-failure --verbose
```

### Main test files

- **`test_analysis_engine.cpp`**: Core analysis functionality, state management, feature extraction
- **`test_memory_monitoring.cpp`**: Memory optimization, object pooling, pressure handling
- **`test_rule_engine_metrics.cpp`**: Rule evaluation, scoring, performance metrics
- **`test_prometheus_*.cpp`**: Prometheus integration, metrics export, PromQL evaluation
- **`test_tier4_integration.cpp`**: End-to-end Tier 4 functionality
- **`test_system_integration.cpp`**: Full system integration testing

### Development workflow

```bash
# 1. Set up development environment
cp config_templates/development.ini config.ini

# 2. Enable debug builds and testing
cmake -B build -S . \
  -DCMAKE_BUILD_TYPE=Debug \
  -DBUILD_TESTING=ON \
  -DENABLE_MEMORY_PROFILING=ON

# 3. Build and test iteratively
cmake --build build && cd build && ctest

# 4. Run with development config
./build/bin/ad-log-ingestor config.ini
```

### Debugging and profiling

#### Memory profiling

```cpp
// Enable in config.ini
[MemoryManagement]
enable_memory_profiling = true

// Or via environment variable
ENABLE_MEMORY_PROFILING=1 ./build/bin/ad-log-ingestor config.ini
```

#### Performance profiling

```cpp
// Enable detailed timing
[Monitoring]
enable_deep_timing = true
enable_function_profiling = true

// Results go to performance_report.csv
```

#### Debug logging

```cpp
// Enhanced debug logging in development.ini
[Logging]
default_level = DEBUG
analysis.* = TRACE
rules.eval = DEBUG
```

### Adding new detection rules

To add a new Tier 1 rule:

1. **Add config**: Update `src/core/config.hpp` with new rule parameters
2. **Write the rule**: Add function to `src/detection/rule_engine.cpp`
3. **Hook it up**: Add call in `RuleEngine::evaluate_tier1_rules()`
4. **Test it**: Create test cases in `tests/test_rule_engine_*.cpp`
5. **Document it**: Update configuration templates

Example:

```cpp
// In src/detection/rule_engine.cpp
void RuleEngine::check_custom_rule(const AnalyzedEvent &event) {
    if (event.custom_metric > app_config.tier1.custom_threshold) {
        create_and_record_alert(event,
            "Custom rule violation detected",
            TIER1_HEURISTIC,
            AlertAction::INVESTIGATE,
            "Review custom behavior pattern",
            calculate_custom_score(event));
    }
}
```

### Machine learning model development

Train and deploy new ML models:

```bash
# 1. Enable data collection
[Tier3]
ml_data_collection_enabled = true
ml_data_collection_path = data/training_features.csv

# 2. Run engine to collect training data
./build/bin/ad-log-ingestor config.ini

# 3. Train new model
cd ml
python train.py --input data/training_features.csv --output models/new_model.onnx

# 4. Update config and hot-reload
[Tier3]
model_path = models/new_model.onnx
```

## Deployment

### Production deployment

#### System requirements

**Minimum requirements**:

- CPU: 2 cores, 2.0 GHz
- RAM: 4 GB
- Disk: 10 GB free space
- OS: Linux (Ubuntu 20.04+, RHEL 8+, CentOS 8+)

**For high throughput** (10,000+ logs/sec):

- CPU: 8+ cores, 3.0+ GHz with SIMD support
- RAM: 16+ GB
- Disk: SSD with 50+ GB free
- Network: Gigabit connection for log ingestion

#### Docker deployment

```dockerfile
# Multi-stage build for smaller images
FROM ubuntu:22.04 AS builder
RUN apt-get update && apt-get install -y \
    build-essential cmake git \
    && rm -rf /var/lib/apt/lists/*

COPY . /app
WORKDIR /app
RUN ./build.sh release

FROM ubuntu:22.04 AS runtime
RUN apt-get update && apt-get install -y \
    libssl3 libcurl4 \
    && rm -rf /var/lib/apt/lists/* \
    && useradd -r -s /bin/false anomaly_detector

COPY --from=builder /app/build/bin/ad-log-ingestor /usr/local/bin/
COPY --from=builder /app/config_templates/production.ini /etc/anomaly_detector/
COPY --from=builder /app/models/ /usr/local/share/anomaly_detector/models/

USER anomaly_detector
EXPOSE 9090
CMD ["/usr/local/bin/ad-log-ingestor", "/etc/anomaly_detector/production.ini"]
```

```bash
# Build and run container
docker build -t anomaly-detector .
docker run -d \
  --name anomaly-detector \
  -p 9090:9090 \
  -v /var/log:/var/log:ro \
  -v ./data:/data \
  anomaly-detector
```

#### Kubernetes Deployment

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: anomaly-detector
spec:
  replicas: 3
  selector:
    matchLabels:
      app: anomaly-detector
  template:
    metadata:
      labels:
        app: anomaly-detector
    spec:
      containers:
        - name: anomaly-detector
          image: anomaly-detector:latest
          ports:
            - containerPort: 9090
          resources:
            requests:
              memory: "2Gi"
              cpu: "1000m"
            limits:
              memory: "4Gi"
              cpu: "2000m"
          volumeMounts:
            - name: config
              mountPath: /etc/anomaly_detector
            - name: data
              mountPath: /data
          livenessProbe:
            httpGet:
              path: /health
              port: 9090
            initialDelaySeconds: 30
            periodSeconds: 10
          readinessProbe:
            httpGet:
              path: /health
              port: 9090
            initialDelaySeconds: 5
            periodSeconds: 5
      volumes:
        - name: config
          configMap:
            name: anomaly-detector-config
        - name: data
          persistentVolumeClaim:
            claimName: anomaly-detector-data
```

#### Systemd service

```ini
# /etc/systemd/system/anomaly-detector.service
[Unit]
Description=Anomaly Detection Engine
After=network.target
Wants=network.target

[Service]
Type=simple
User=anomaly_detector
Group=anomaly_detector
ExecStart=/usr/local/bin/ad-log-ingestor /etc/anomaly_detector/config.ini
ExecReload=/bin/kill -HUP $MAINPID
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal
SyslogIdentifier=anomaly-detector

# Security hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/log/anomaly_detector /var/lib/anomaly_detector

[Install]
WantedBy=multi-user.target
```

```bash
# Install and start the service
sudo cp anomaly-detector.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable anomaly-detector
sudo systemctl start anomaly-detector

# Check the service status
sudo systemctl status anomaly-detector
sudo journalctl -u anomaly-detector -f
```

### Performance tuning

#### High-throughput config

For processing lots of logs per second:

```ini
[MemoryManagement]
max_memory_usage_mb = 8192
enable_object_pooling = true
eviction_threshold_percent = 90.0

[PerformanceMonitoring]
enable_load_shedding = true
max_cpu_usage_percent = 85.0
moderate_load_shed_percentage = 5.0

[Tier1]
max_unique_paths_stored_per_ip = 5000

[Tier2]
min_samples_for_z_score = 20  # Lower for faster adaptation

[Tier3]
enabled = false  # Disable ML for max throughput
```

#### Memory optimization

```ini
[MemoryManagement]
enable_memory_compaction = true
state_object_ttl_seconds = 1800  # Shorter TTL
eviction_check_interval_seconds = 30

# Use optimized analysis engine
use_optimized_analysis_engine = true
```

#### Network tuning

```bash
# System-level TCP tuning for high log rates
echo 'net.core.rmem_max = 134217728' >> /etc/sysctl.conf
echo 'net.core.wmem_max = 134217728' >> /etc/sysctl.conf
echo 'net.ipv4.tcp_rmem = 4096 87380 134217728' >> /etc/sysctl.conf
sysctl -p
```

### Security Hardening

#### File Permissions

```bash
# Restrict configuration file access
sudo chown root:anomaly_detector /etc/anomaly_detector/config.ini
sudo chmod 640 /etc/anomaly_detector/config.ini

# Secure log directories
sudo chown anomaly_detector:anomaly_detector /var/log/anomaly_detector
sudo chmod 750 /var/log/anomaly_detector
```

#### Network Security

```bash
# Firewall rules for monitoring interface
sudo ufw allow from 10.0.0.0/8 to any port 9090
sudo ufw allow from 172.16.0.0/12 to any port 9090
sudo ufw allow from 192.168.0.0/16 to any port 9090
```

#### SELinux/AppArmor

```bash
# SELinux context for CentOS/RHEL
sudo setsebool -P httpd_can_network_connect 1
sudo semanage fcontext -a -t bin_t "/usr/local/bin/ad-log-ingestor"
sudo restorecon -v /usr/local/bin/ad-log-ingestor
```

## Troubleshooting

### Common problems

#### Memory usage is too high

**What you'll see**: Process memory goes over configured limits, maybe the OOM killer gets involved
**How to check**:

```bash
# Look at memory metrics
curl http://localhost:9090/metrics | grep memory

# Turn on memory profiling
[MemoryManagement]
enable_memory_profiling = true
```

**How to fix**:

1. Lower the `max_memory_usage_mb` setting
2. Enable more aggressive memory management:
   ```ini
   [MemoryManagement]
   eviction_threshold_percent = 70.0
   enable_memory_compaction = true
   state_object_ttl_seconds = 1800
   ```
3. Use the optimized analysis engine: `use_optimized_analysis_engine = true`

#### CPU usage is too high

**What you'll see**: CPU consistently above 80%, processing starts lagging
**How to check**:

```bash
# Check processing metrics
curl http://localhost:9090/metrics | grep processing_time

# Enable profiling
[PerformanceMonitoring]
enable_function_profiling = true
```

**How to fix**:

1. Enable load shedding:
   ```ini
   [PerformanceMonitoring]
   enable_load_shedding = true
   max_cpu_usage_percent = 80.0
   ```
2. Temporarily disable expensive tiers:
   ```ini
   [Tier3]
   enabled = false
   ```
3. Tune rule thresholds for your environment

#### Too many alerts (alert fatigue)

**What you'll see**: Way too many alerts, important ones get lost in the noise
**How to fix**:

1. Adjust throttling settings:
   ```ini
   alert_throttle_duration_seconds = 600
   alert_throttle_max_alerts = 20
   ```
2. Tune detection thresholds:

   ```ini
   [Tier1]
   max_requests_per_ip_in_window = 1500  # Higher threshold

   [Tier2]
   z_score_threshold = 4.0  # Less sensitive
   ```

3. Add trusted IPs to allowlists

#### Database connection issues

**What you'll see**: MongoDB connection failures, logs not getting processed
**How to check**:

```bash
# Test MongoDB connection manually
mongo "mongodb://localhost:27017/database" --eval "db.stats()"

# Check engine logs
journalctl -u anomaly-detector -f | grep -i mongo
```

**How to fix**:

1. Double-check MongoDB config:
   ```ini
   [MongoLogSource]
   uri = mongodb://localhost:27017
   database = correct_database_name
   collection = correct_collection_name
   ```
2. Enable retry and circuit breaker:
   ```ini
   [ErrorHandling]
   database_recovery_strategy = "RETRY"
   max_retry_attempts = 5
   ```

#### Prometheus integration not working

**What you'll see**: Tier 4 rules don't evaluate, Prometheus connection errors
**How to check**:

```bash
# Test Prometheus API manually
curl "http://localhost:9090/api/v1/query?query=up"

# Check Tier 4 metrics
curl http://localhost:9090/metrics | grep tier4
```

**How to fix**:

1. Check Prometheus config:
   ```ini
   [Tier4]
   prometheus_url = http://localhost:9090
   auth_token = your_token_if_needed
   ```
2. Enable circuit breaker:
   ```ini
   [Tier4]
   enable_circuit_breaker = true
   circuit_breaker_failure_threshold = 3
   ```

### Debug mode

Turn on comprehensive debugging:

```ini
[Logging]
default_level = DEBUG
analysis.* = TRACE
rules.eval = DEBUG
io.* = DEBUG

[Monitoring]
enable_deep_timing = true
enable_function_profiling = true

[MemoryManagement]
enable_memory_profiling = true
```

### Useful log patterns

Keep an eye out for these in the logs:

```bash
# Memory pressure events
journalctl -u anomaly-detector | grep -i "memory pressure"

# Rule engine performance issues
journalctl -u anomaly-detector | grep -i "rule processing time"

# Configuration reload events
journalctl -u anomaly-detector | grep -i "configuration reloaded"

# Alert throttling (might indicate tuning needed)
journalctl -u anomaly-detector | grep -i "throttled"
```

### Performance monitoring

Key metrics to watch in production:

```prometheus
# Processing rate and latency
rate(anomaly_detector_events_processed_total[5m])
histogram_quantile(0.95, anomaly_detector_processing_time_seconds_bucket)

# Memory usage
anomaly_detector_memory_usage_bytes / (1024*1024)  # MB
anomaly_detector_ip_states_count

# Alert rates
rate(anomaly_detector_alerts_generated_total[5m])
rate(anomaly_detector_alerts_throttled_total[5m])

# Rule engine performance
histogram_quantile(0.95, anomaly_detector_rule_processing_time_seconds_bucket)
```

## API Reference

### Main classes

#### AnalysisEngine

This is the core behavioral analysis component.

```cpp
class AnalysisEngine {
public:
    // Main processing method
    AnalyzedEvent process_and_analyze(const LogEntry &raw_log);

    // State persistence
    bool save_state(const std::string &path) const;
    bool load_state(const std::string &path);

    // Memory management
    void run_pruning(uint64_t current_timestamp_ms);
    bool check_memory_pressure() const;
    void trigger_memory_cleanup();

    // Configuration
    void reconfigure(const Config::AppConfig &new_config);
    void reset_in_memory_state();

    // Metrics and monitoring
    EngineStateMetrics get_internal_state_metrics() const;
    std::vector<TopIpInfo> get_top_n_by_metric(size_t n, const std::string &metric);
};
```

#### RuleEngine

Handles the multi-tier detection and rule evaluation.

```cpp
class RuleEngine {
public:
    RuleEngine(AlertManager &manager, const Config::AppConfig &cfg);

    // Main evaluation method
    void evaluate_rules(const AnalyzedEvent &event);

    // Configuration management
    void reconfigure(const Config::AppConfig &new_config);
    bool load_ip_allowlist(const std::string &filepath);

    // Integration points
    void set_metrics_exporter(std::shared_ptr<PrometheusMetricsExporter> exporter);
    void set_tier4_anomaly_detector(std::shared_ptr<PrometheusAnomalyDetector> detector);
};
```

#### AlertManager

Takes care of alert formatting, throttling, and sending.

```cpp
class AlertManager {
public:
    // Alert creation and processing
    void process_alert(const Alert &alert);
    void add_dispatcher(std::unique_ptr<AlertDispatcher> dispatcher);

    // Throttling control
    bool should_throttle_alert(const std::string &key, const std::string &reason);
    void configure_throttling(uint32_t duration_seconds, uint32_t max_alerts);

    // State management
    void flush_pending_alerts();
    AlertStats get_alert_statistics() const;
};
```

#### Config System

Handles configuration management with hot-reloading.

```cpp
namespace Config {
    struct AppConfig {
        // Core settings
        std::string log_source_type;
        std::string log_input_path;
        bool alerts_to_stdout;

        // Detection tier configurations
        Tier1Config tier1;
        Tier2Config tier2;
        Tier3Config tier3;
        Tier4Config tier4;

        // Advanced features
        MemoryManagementConfig memory_management;
        PerformanceMonitoringConfig performance_monitoring;
        DynamicLearningConfig dynamic_learning;
        PrometheusConfig prometheus;
    };

    // Configuration loading and validation
    AppConfig load_config(const std::string &config_path);
    bool validate_config(const AppConfig &config);
    void save_config(const AppConfig &config, const std::string &path);
}
```

### Data structures

#### LogEntry

Represents a parsed log entry.

```cpp
struct LogEntry {
    std::string ip_address;
    std::string request_method;
    std::string request_path;
    std::string user_agent;
    std::string referer;
    uint64_t timestamp_ms;
    std::optional<uint16_t> http_status_code;
    std::optional<uint64_t> bytes_sent;
    std::optional<double> response_time_ms;

    // Computed fields
    std::string query_string;
    std::string path_without_query;
    RequestType request_type;  // HTML, ASSET, OTHER
};
```

#### AnalyzedEvent

Enriched log entry with behavioral context and features.

```cpp
struct AnalyzedEvent {
    LogEntry raw_log;

    // Behavioral flags
    bool is_new_ip;
    bool is_new_path_for_ip;
    bool is_ua_missing;
    bool is_ua_suspicious;
    bool is_ua_outdated;
    bool is_ua_changed;
    bool is_error_response;

    // Statistical measures
    double ip_request_rate_score;
    double ip_error_event_zscore;
    double ip_bytes_sent_zscore;
    double path_request_zscore;
    double path_error_zscore;

    // Counts and ratios
    uint32_t ip_requests_in_window;
    uint32_t ip_failed_logins_in_window;
    uint32_t session_requests_in_window;
    double html_asset_ratio;

    // Advanced features
    double request_entropy;
    double temporal_variance;
    uint32_t unique_paths_accessed;
    uint32_t ua_changes_in_window;

    // ML features (50+ engineered features)
    std::vector<double> feature_vector;

    // Tier 4 results
    std::vector<PrometheusAnomalyResult> prometheus_anomalies;
};
```

#### Alert

Represents a security alert with context.

```cpp
struct Alert {
    uint64_t timestamp_ms;
    AlertTier tier;                    // TIER1_HEURISTIC, TIER2_STATISTICAL, etc.
    AlertAction recommended_action;     // INVESTIGATE, BLOCK, MONITOR
    std::string alert_reason;
    double anomaly_score;

    // Context information
    LogContext log_context;            // IP, path, status, user_agent
    AnalysisContext analysis_context;   // Z-scores, flags, statistics
    std::string raw_log_line;

    // Metadata
    std::string alert_id;
    uint64_t log_line_number;
    std::string key_identifier;       // For throttling
};
```

### Utility stuff

#### Memory management

```cpp
namespace memory {
    // Object pooling
    template<typename T>
    class ObjectPool {
    public:
        std::shared_ptr<T> acquire();
        void release(std::shared_ptr<T> obj);
        size_t size() const;
    };

    // String interning
    class StringInternPool {
    public:
        uint32_t intern(const std::string &str);
        const std::string& lookup(uint32_t id) const;
    };

    // Memory monitoring
    class MemoryManager {
    public:
        bool is_memory_pressure() const;
        size_t get_current_usage() const;
        void trigger_cleanup();
    };
}
```

#### Performance utilities

```cpp
namespace utils {
    // High-precision timing
    class ScopedTimer {
    public:
        ScopedTimer(const std::string &name);
        ~ScopedTimer();  // Automatically logs elapsed time
    };

    // SIMD-optimized operations (when supported)
    namespace simd {
        bool contains_pattern(const std::string &text, const std::string &pattern);
        size_t count_occurrences(const std::string &text, char target);
    }

    // Advanced data structures
    template<typename T>
    class CircularBuffer {
    public:
        void push(const T &item);
        T pop();
        bool empty() const;
        size_t size() const;
    };

    template<typename T>
    class SlidingWindow {
    public:
        void add_event(uint64_t timestamp, const T &event);
        std::vector<T> get_events_in_window(uint64_t window_duration_ms) const;
        size_t count_in_window(uint64_t window_duration_ms) const;
    };
}
```

### Plugin Interfaces

#### Log Parser Plugin

```cpp
class LogParser {
public:
    virtual ~LogParser() = default;
    virtual std::optional<LogEntry> parse_line(const std::string &line) = 0;
    virtual std::string get_parser_name() const = 0;

    // Factory method for creating parsers
    static std::unique_ptr<LogParser> create_parser(const std::string &format);
};

// Built-in parsers: NginxParser, ApacheParser, JSONParser, CustomParser
```

#### Alert Dispatcher Plugin

```cpp
class AlertDispatcher {
public:
    virtual ~AlertDispatcher() = default;
    virtual bool dispatch_alert(const Alert &alert) = 0;
    virtual std::string get_dispatcher_name() const = 0;
};

// Built-in dispatchers: FileDispatcher, SyslogDispatcher, HTTPDispatcher
```

### Configuration Examples

#### Complete Configuration Template

```ini
# Core application settings
log_source_type = file
log_input_path = /var/log/nginx/access.log
alerts_to_stdout = true
alerts_to_file = true
alert_output_path = /var/log/anomaly_detector/alerts.json

# Alert throttling to prevent spam
alert_throttle_duration_seconds = 300
alert_throttle_max_alerts = 10

# State persistence for learning continuity
state_persistence_enabled = true
state_file_path = /var/lib/anomaly_detector/engine_state.dat
state_save_interval_events = 50000

# Tier 1: Fast heuristic detection
[Tier1]
enabled = true
sliding_window_duration_seconds = 60
max_requests_per_ip_in_window = 1000
max_failed_logins_per_ip = 50
suspicious_path_substrings = ../,/etc/passwd,sqlmap,xss
check_user_agent_anomalies = true
min_chrome_version = 90
min_firefox_version = 85

# Tier 2: Statistical anomaly detection
[Tier2]
enabled = true
z_score_threshold = 3.5
min_samples_for_z_score = 30
historical_deviation_factor = 3.0

# Tier 3: Machine learning detection
[Tier3]
enabled = true
model_path = models/isolation_forest.onnx
anomaly_score_threshold = 0.6
automated_retraining_enabled = false

# Tier 4: Prometheus integration
[Tier4]
enabled = false
prometheus_url = http://localhost:9090
query_timeout_seconds = 30
evaluation_interval_seconds = 60

# Memory optimization
[MemoryManagement]
enabled = true
max_memory_usage_mb = 2048
memory_pressure_threshold_mb = 1600
enable_object_pooling = true
eviction_threshold_percent = 80.0

# Performance monitoring and load shedding
[PerformanceMonitoring]
enabled = true
enable_load_shedding = true
max_cpu_usage_percent = 80.0
max_memory_usage_bytes = 2147483648

# Dynamic learning for adaptive thresholds
[DynamicLearning]
enabled = true
learning_window_hours = 24
confidence_threshold = 0.95
seasonal_detection_sensitivity = 0.8

# Prometheus metrics export
[Prometheus]
enabled = true
host = 0.0.0.0
port = 9090
metrics_path = /metrics
scrape_interval_seconds = 15
```

## License

This project uses the **MIT License** - see the [LICENSE](LICENSE) file for the full text.

```
MIT License

Copyright (c) 2025 Anomaly Detection Engine Contributors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

### Third-party dependencies

This project uses several open-source libraries:

- **ONNX Runtime**: Microsoft's ML inference engine (MIT License)
- **nlohmann/json**: JSON library for Modern C++ (MIT License)
- **cpp-httplib**: HTTP client/server library (MIT License)
- **spdlog**: Fast C++ logging library (MIT License)
- **toml++**: TOML parser and serializer (MIT License)
- **OpenMP**: Parallel computing API (Various licenses)
- **MongoDB C++ Driver**: Official MongoDB driver (Apache 2.0 License)

Dependencies are managed through vcpkg and their licenses are preserved.

---

## Quick Start Summary

Getting started in a few minutes:

```bash
# 1. Clone and build
git clone <repository-url>
cd anomaly_detector_cpp
git submodule update --init --recursive
./build.sh release

# 2. Configure
cp config_templates/development.ini config.ini

# 3. Run with sample data
./build/bin/ad-log-ingestor config.ini < data/sample_logs.txt

# 4. Check if it's working
curl http://localhost:9090/metrics
```

**Next steps:**

- Configure for your log format in `config.ini`
- Set up production deployment using Docker or systemd
- Connect with your monitoring setup (Prometheus/Grafana)
- Train custom ML models using the collected data

Check the sections above for detailed info, or look in the `docs/` folder.

---

**Having trouble?** Check the [troubleshooting guide](#troubleshooting) or open an issue on GitHub.
