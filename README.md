# 🐺 Anomaly Detector (Anomaly-Wolf): Real-Time Log Anomaly Detection Engine

_A high-performance C++ engine that sniffs out suspicious activity from your web server logs before the bad guys get too comfortable._

This project was born from the idea that sifting through millions of log lines manually is a terrible way to spend your time. Instead, let's build a C++-powered bloodhound that can stream logs in real-time, pick up the scent of anomalies, and bark when it finds something fishy.

---

### **Table of Contents**

- [So, What's the Big Idea? (Why?)](#so-whats-the-big-idea-why)
- [The Arsenal: What It Can Do](#the-arsenal-what-it-can-do)
- [Under the Hood: How It Works](#under-the-hood-how-it-works)
- [Expected Log Format (The Important Bit!)](#expected-log-format-the-important-bit)
  - [What If My Logs Are Different?](#what-if-my-logs-are-different)
- [Getting Started: Firing Up the Engine](#getting-started-firing-up-the-engine)
- [Tuning the Beast: The `config.ini` File](#tuning-the-beast-the-configini-file)
- [The Bark: Understanding Alerts](#the-bark-understanding-alerts)
- [The Roadmap: Where We're Going Next](#the-roadmap-where-were-going-next)
- [License](#license)

---

### **So, What's the Big Idea? (Why?)**

Web servers are chatty. They log _everything_. Hidden in that flood of text are the digital footprints of attackers, bots, and broken scripts. Finding them is like finding a needle in a haystack the size of a planet.

**Anomaly-Wolf** is designed to be that super-powered magnet. It automates the hunt by applying layers of detection logic in real-time, letting you know about potential threats as they happen, not after you read a post-mortem report. It's built in modern C++ for one reason: **speed**. We want to keep up with a torrent of logs on machines with as little as 1-2GB of RAM.

### **The Arsenal: What It Can Do**

This isn't just a simple script; it's a tiered detection system.

- **Blazing Fast Log Parsing:** Streams and parses `|`-delimited logs without breaking a sweat.
- **Tier 1: Heuristic "Gut Feeling" Rules:** These are the quick, common-sense checks for obviously shady stuff.
  - **High Request Rate:** Catches IPs that are a little too eager (e.g., brute-force, DoS probing).
  - **Failed Login Spam:** Detects IPs trying to guess passwords by hammering your login endpoints.
  - **Suspicious String Matching:** Flags requests containing classic "hacker words" (`sqlmap`, `../../`, `<script>`).
  - **Advanced User-Agent Analysis:** This is our pride and joy. It sniffs out:
    - Missing or empty User-Agents.
    - Known malicious bot/scanner signatures (`Nmap`, `Nikto`).
    * Ridiculously old browser versions (like someone running Chrome from 2015).
    * Headless browsers (`HeadlessChrome`, `Puppeteer`).
    * IPs that rapidly change their User-Agent identity (a classic bot move).
- **Tier 2: Statistical "Something's Not Right" Detection:** This tier builds a profile of "normal" and flags weird deviations.
  - **Welford's Algorithm:** We use this slick, single-pass algorithm to calculate mean and standard deviation on the fly for various metrics.
  - **Z-Score Outliers:** We check the Z-score for...
    - **Request Time:** Is this request taking way longer than usual for this IP/path?
    - **Bytes Sent:** Did this endpoint suddenly start sending gigabytes of data?
    - **Error Rate:** Is this usually-stable IP suddenly causing a cascade of 500 errors?
    - **Request Volume:** Is the traffic to this path suddenly way above its normal baseline?
  - **IP & Path Profiling:** All statistical checks are done on both a per-IP and per-path basis for granular detection.
- **Tier 3: Machine Learning Framework (Stubbed):**
  - The hooks are in place! We have a basic feature extractor and interfaces ready to plug in a real ML model (like Isolation Forest) when it's ready.

### **Under the Hood: How It Works**

We didn't just throw code at the wall. There's a method to the madness.

**Architecture: `Log -> Analysis Engine -> Rule Engine -> Alert Manager`**

1.  **Log Processor:** The `main` loop reads logs line-by-line.
2.  **Analysis Engine:** This is the brains of the data-gathering operation. It takes a raw log, enriches it with context, and creates an `AnalyzedEvent`. It asks questions like:
    - "What's the current request rate for this IP?"
    - "What's the historical average error rate for this path?"
    - "Is this User-Agent new for this IP?"
    - It does **not** decide if something is "bad." It just gathers the evidence.
3.  **Rule Engine:** This is the judge. It takes the `AnalyzedEvent` full of evidence and compares it against a set of configured rules. If a rule is broken, it convicts.
4.  **Alert Manager:** The town crier. When the `RuleEngine` convicts, the `AlertManager` shouts it from the rooftops (or, you know, prints it to your console and a JSON file).

This separation means we can add super complex analysis features without making the rule-checking logic a tangled mess.

### **Expected Log Format (The Important Bit!)**

We're opinionated about logs for now. The engine expects a `|`-delimited string with **15 fields** in this exact order:

`ip|remote_user|time_local|request_time|upstream_response_time|request|status|body_bytes_sent|referer|user_agent|host|country_code|upstream_addr|x_request_id|accept_encoding`

**Example:**

```
51.8.102.142|-|23/May/2025:00:00:35 +0530|0.005|-|GET /global/sarees.html HTTP/1.1|403|555|-|Mozilla/5.0...|www.somewebsite.com|US|-|34a0...|gzip,deflate
```

#### **What If My Logs Are Different?**

Good question! Right now, you'd have to roll up your sleeves and get your hands dirty in the code.

To adapt the parser, head over to `src/log_entry.cpp` and modify the `LogEntry::parse_from_string` function. You'll need to change the expected field count and the mapping of `fields[index]` to the members of the `LogEntry` struct. It's a rite of passage.

### **Getting Started: Firing Up the Engine**

You'll need a C++ compiler that supports C++17 (like a modern `g++`) and the `make` build tool. If you're on a Linux or macOS system, you probably already have these installed.

**1. Build the Executable:**

To compile the engine, navigate to the project's root directory in your terminal and simply run:

```bash
make
```

This will automatically find all the source files, compile them with performance optimizations (`-O3 -march=native`), and place the final executable at `bin/anomaly_detector`. The `make build` command does the exact same thing.

**2. Run the Engine:**

The Makefile includes a convenient `run` command that builds the project (if needed) and then immediately runs it using the default `config.ini` file.

```bash
make run
```

This is the easiest way to get started and see it in action!

Of course, you can also run the executable directly after building it. This is useful if you want to specify a different configuration file:

```bash
# First, build it
make

# Then run it manually
./bin/anomaly_detector /path/to/your/custom_config.ini
```

**3. Clean Up the Build Files:**

If you want to remove all the compiled files (the intermediate `.o` objects in `obj/` and the executable in `bin/`) to start fresh, use the `clean` command.

```bash
make clean
```

---

### **Tuning the Beast: The `config.ini` File**

All the knobs and levers are in `config.ini`. It's heavily commented, so it should be self-explanatory. You can toggle entire tiers of detection, change thresholds, set file paths, and define what you consider "suspicious."

A snippet to whet your appetite:

```ini
# --- Tier 2: Statistical Detection ---
[Tier2]
enabled = true
# Z-score absolute value above which an event is considered an outlier.
z_score_threshold = 3.5
# Minimum number of data samples required before Z-score calcs are performed.
min_samples_for_z_score = 30
```

### **The Bark: Understanding Alerts**

When Anomaly-Wolf finds something, it'll tell you.

**Console Output:**

```
ALERT DETECTED:
  Timestamp: 2025-06-11 14:30:05.123
  Tier:      TIER1_HEURISTIC
  Source IP: 192.168.1.100
  Reason:    IP rapidly cycling through different User-Agents
  Action:    Very high likelihood of bot; consider blocking
  Score:     20.00
----------------------------------------
```

**JSON Output (`alerts_log.json`):**
A machine-readable version of the same alert, perfect for piping into other tools.

```json
{"timestamp_ms":1718101805123, "ip":"192.168.1.100", "reason":"IP rapidly cycling through different User-Agents", ...}
```

### **The Roadmap: Where We're Going Next**

This is just the beginning. The foundation is solid, but there's a whole world of awesome features to add.

- [ ] **Full ML Model Integration (Tier 3):** Replace the stubs with a real, lightweight model using `ONNX Runtime` or `dlib`.
- [ ] **Geo-Velocity Detection:** Flag impossible travel (e.g., an IP logging in from New York and then 5 minutes later from Tokyo).
- [x] **Advanced User-Agent Analysis:** _Done!_
- [x] **Historical vs. Current Behavior Rules:** _Done!_
- [ ] **Live Configuration Reloading:** Tweak the `config.ini` and have the engine update without a restart (SIGHUP).
- [ ] **Prometheus Metrics Endpoint:** Expose internal stats (`/metrics`) for proper monitoring and dashboards.
- [ ] **Unit Testing Framework:** Add Google Test or Catch2 for robust testing.
- [ ] **Performance Enhancements:**
  - [ ] True LRU cache for state management to strictly bound memory.
  - [ ] Multithreaded log ingestion pipeline.
- [ ] **Sessionization:** Track users across multiple requests to detect anomalies at the session level.

### **License**

This project is licensed under the MIT License. Go nuts.
