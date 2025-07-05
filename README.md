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
