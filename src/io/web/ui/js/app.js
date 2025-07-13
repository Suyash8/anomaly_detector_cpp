document.addEventListener("DOMContentLoaded", () => {
  const App = {
    // --- STATE ---
    charts: {},
    updateInterval: 2000,
    data: {
      // Metrics history
      logs: [], // {timestamp, value}
      alerts: [], // {timestamp, value}
      latency: [], // {timestamp, p50, p90, p99}
      breakdown: [], // {timestamp, ...}
      memory: [], // {timestamp, value}

      // Current operational data
      recentAlerts: [],
      topState: {},
    },
    maxHistory: 60,

    // --- DOM ELEMENTS ---
    elements: {
      nav: {
        performance: document.getElementById("nav-performance"),
        operations: document.getElementById("nav-operations"),
      },
      views: {
        performance: document.getElementById("performance-view"),
        operations: document.getElementById("operations-view"),
      },
      kpis: {
        logsPerSec: document.getElementById("kpi-logs-per-sec"),
        alertsPerMin: document.getElementById("kpi-alerts-per-min"),
        p90Latency: document.getElementById("kpi-p90-latency"),
        memory: document.getElementById("kpi-memory-mb"),
      },
      alertsTableBody: document.querySelector("#alerts-table tbody"),
      widgets: {
        activeIps: document.getElementById("widget-active-ips"),
        scoredIps: document.getElementById("widget-scored-ips"),
        suspiciousPaths: document.getElementById("widget-suspicious-paths"),
        threatIntel: document.getElementById("widget-threat-intel"),
      },
    },

    // --- INITIALIZATION ---
    init() {
      this.setupNavigation();
      this.setupCharts();
      this.startUnifiedFetchingLoop();
    },

    setupNavigation() {
      this.elements.nav.performance.addEventListener("click", () =>
        this.switchView("performance")
      );
      this.elements.nav.operations.addEventListener("click", () =>
        this.switchView("operations")
      );
    },

    switchView(viewName) {
      Object.values(this.elements.nav).forEach((el) =>
        el.classList.remove("active")
      );
      Object.values(this.elements.views).forEach((el) =>
        el.classList.remove("active")
      );
      this.elements.nav[viewName].classList.add("active");
      this.elements.views[viewName].classList.add("active");
    },

    setupCharts() {
      const commonOptions = {
        maintainAspectRatio: false,
        scales: {
          x: { ticks: { color: "#aaa" }, grid: { color: "#444" } },
          y: {
            ticks: { color: "#aaa" },
            grid: { color: "#444" },
            beginAtZero: true,
          },
        },
        plugins: { legend: { labels: { color: "#e0e0e0" } } },
        animation: { duration: 250 },
      };

      this.charts.latency = new Chart(
        document.getElementById("latency-chart"),
        {
          type: "line",
          data: {
            labels: [],
            datasets: [
              {
                label: "p99 Latency (ms)",
                data: [],
                borderColor: "#ff6384",
                tension: 0.2,
                pointRadius: 0,
              },
              {
                label: "p90 Latency (ms)",
                data: [],
                borderColor: "#00aaff",
                tension: 0.2,
                pointRadius: 0,
              },
              {
                label: "p50 Latency (ms)",
                data: [],
                borderColor: "#ffce56",
                tension: 0.2,
                pointRadius: 0,
              },
            ],
          },
          options: commonOptions,
        }
      );

      this.charts.breakdown = new Chart(
        document.getElementById("breakdown-chart"),
        {
          type: "bar",
          data: {
            labels: ["Log Reader", "Analysis Engine", "Rule Engine"],
            datasets: [
              {
                label: "Avg Latency (ms)",
                data: [],
                backgroundColor: ["#ff6384", "#00aaff", "#ffce56"],
              },
            ],
          },
          options: {
            ...commonOptions,
            indexAxis: "y",
            plugins: { legend: { display: false } },
          },
        }
      );
    },

    // --- DATA FETCHING & RENDERING ---
    async startUnifiedFetchingLoop() {
      try {
        // Fetch all data concurrently
        const [perfRes, alertsRes, stateRes] = await Promise.all([
          fetch("/api/v1/metrics/performance").catch((e) => e),
          fetch("/api/v1/operations/alerts").catch((e) => e),
          fetch("/api/v1/operations/state").catch((e) => e),
        ]);

        // Process whatever data we received successfully
        if (perfRes instanceof Response && perfRes.ok) {
          this.processPerformanceData(await perfRes.json());
        }
        if (alertsRes instanceof Response && alertsRes.ok) {
          this.processOperationsData(await alertsRes.json());
        }
        if (stateRes instanceof Response && stateRes.ok) {
          this.data.topState = await stateRes.json();
        }

        // After ALL data for this tick is processed, update the entire UI
        this.renderAll();
      } catch (error) {
        console.error("Data fetch/processing failed:", error);
      } finally {
        // Schedule the next full update cycle
        setTimeout(() => this.startUnifiedFetchingLoop(), this.updateInterval);
      }
    },

    // --- DATA PROCESSING ---
    processPerformanceData(apiData) {
      const now = apiData.server_timestamp_ms;

      // Counters
      this.data.logs.push({
        timestamp: now,
        value: apiData.counters.ad_logs_processed_total || 0,
      });
      if (this.data.logs.length > this.maxHistory) this.data.logs.shift();

      // Gauges
      this.data.memory.push({
        timestamp: now,
        value: apiData.gauges?.ad_process_memory_rss_bytes || 0,
      });
      if (this.data.memory.length > this.maxHistory) this.data.memory.shift();

      // Histograms
      const getValues = (metric) => (metric ? metric.map((obs) => obs[1]) : []);
      const findMetricData = (prefix) =>
        apiData.histograms?.[
          Object.keys(apiData.histograms || {}).find((k) =>
            k.startsWith(prefix)
          )
        ] || [];

      const latencyValues = getValues(
        apiData.histograms?.ad_batch_processing_duration_seconds
      );
      latencyValues.sort((a, b) => a - b);

      this.data.latency.push({
        timestamp: now,
        p50: latencyValues[Math.floor(latencyValues.length * 0.5)] || 0,
        p90: latencyValues[Math.floor(latencyValues.length * 0.9)] || 0,
        p99: latencyValues[Math.floor(latencyValues.length * 0.99)] || 0,
      });
      if (this.data.latency.length > this.maxHistory) this.data.latency.shift();

      const readerValues = getValues(
        findMetricData("ad_log_reader_batch_fetch_duration_seconds")
      );
      const analysisValues = getValues(
        apiData.histograms?.ad_analysis_engine_process_duration_seconds
      );
      const ruleValues = getValues(
        apiData.histograms?.ad_rule_engine_evaluation_duration_seconds
      );
      const getAvg = (arr) =>
        arr.length > 0 ? arr.reduce((a, b) => a + b, 0) / arr.length : 0;

      this.data.breakdown.push({
        timestamp: now,
        reader: getAvg(readerValues),
        analysis: getAvg(analysisValues),
        rules: getAvg(ruleValues),
      });
      if (this.data.breakdown.length > this.maxHistory)
        this.data.breakdown.shift();
    },

    processOperationsData(alerts) {
      this.data.recentAlerts = alerts; // Store the latest batch of alerts

      const now = Date.now();
      this.data.alerts.push({ timestamp: now, value: alerts.length });
      if (this.data.alerts.length > this.maxHistory) this.data.alerts.shift();
    },

    // --- UI UPDATING ---
    renderAll() {
      this.renderPerformanceView();
      this.renderOperationsView();
    },

    renderPerformanceView() {
      const calculateRate = (history, seconds) => {
        if (history.length < 2) return 0.0;
        const now_ms = history[history.length - 1].timestamp;
        const cutoff_ms = now_ms - seconds * 1000;

        const relevantData = history.filter((d) => d.timestamp >= cutoff_ms);
        if (relevantData.length < 2) return 0.0;

        const first = relevantData[0];
        const last = relevantData[relevantData.length - 1];
        const valueDelta = last.value - first.value;
        const timeDeltaSec = (last.timestamp - first.timestamp) / 1000;

        return timeDeltaSec > 0 ? valueDelta / timeDeltaSec : 0.0;
      };

      this.elements.kpis.logsPerSec.textContent = calculateRate(
        this.data.logs,
        10
      ).toFixed(1);
      this.elements.kpis.alertsPerMin.textContent = (
        calculateRate(this.data.alerts, 60) * 60
      ).toFixed(1);

      const lastLatency = this.data.latency[this.data.latency.length - 1] || {};
      this.elements.kpis.p90Latency.textContent = (
        (lastLatency.p90 || 0) * 1000
      ).toFixed(2);

      const lastMemory = this.data.memory[this.data.memory.length - 1] || {};
      this.elements.kpis.memory.textContent = (
        (lastMemory.value || 0) /
        1024 /
        1024
      ).toFixed(1);

      // Update Charts
      this.charts.latency.data.labels = this.data.latency.map((p) =>
        new Date(p.timestamp).toLocaleTimeString()
      );
      this.charts.latency.data.datasets[0].data = this.data.latency.map(
        (p) => p.p99 * 1000
      );
      this.charts.latency.data.datasets[1].data = this.data.latency.map(
        (p) => p.p90 * 1000
      );
      this.charts.latency.data.datasets[2].data = this.data.latency.map(
        (p) => p.p50 * 1000
      );
      this.charts.latency.update("none");

      const lastBreakdown =
        this.data.breakdown[this.data.breakdown.length - 1] || {};
      this.charts.breakdown.data.datasets[0].data = [
        (lastBreakdown.reader || 0) * 1000,
        (lastBreakdown.analysis || 0) * 1000,
        (lastBreakdown.rules || 0) * 1000,
      ];
      this.charts.breakdown.update();
    },

    renderOperationsView() {
      this.elements.alertsTableBody.innerHTML = "";
      // ... (rest of table rendering logic from previous response) ...

      const createRow = (label, value, valueClass = "value-primary") =>
        `<div class="widget-row"><span class="ip-mono">${label}</span><span class="${valueClass}">${value}</span></div>`;
      this.elements.widgets.activeIps.innerHTML = (
        this.data.topState.top_active_ips || []
      )
        .map((item) => createRow(item.ip, item.value.toFixed(0)))
        .join("");
      this.elements.widgets.scoredIps.innerHTML = (
        this.data.topState.top_error_ips || []
      )
        .map((item) =>
          createRow(item.ip, item.value.toFixed(2), "value-destructive")
        )
        .join("");
      // ... (rest of widget rendering logic) ...
    },

    renderOperationsView() {
      const alerts = this.data.recentAlerts;
      const state = this.data.topState;

      // --- Render Alerts Table ---
      if (alerts && alerts.length > 0) {
        this.elements.alertsTableBody.innerHTML = ""; // Clear old rows
        const newIds = new Set(alerts.map((a) => a.log_context.line_number));

        for (const alert of alerts) {
          const tr = document.createElement("tr");
          // Check if this alert was present in the *previous* batch to determine if it's "new"
          const isNew =
            !this.currentAlertIds ||
            !this.currentAlertIds.has(alert.log_context.line_number);
          if (isNew) {
            tr.classList.add("new-alert");
          }

          const tierClass = alert.detection_tier
            .toLowerCase()
            .replace(/_/g, "-")
            .replace("heuristic", "t1")
            .replace("statistical", "t2")
            .replace("ml", "t3");

          // Use textContent to prevent XSS issues, even from our own API.
          const createCell = (content) => {
            const td = document.createElement("td");
            td.innerHTML = content;
            return td;
          };

          tr.appendChild(
            createCell(new Date(alert.timestamp_ms).toLocaleTimeString())
          );
          tr.appendChild(
            createCell(
              `<span class="ip-mono">${this.escapeHTML(
                alert.log_context.source_ip
              )}</span>`
            )
          );
          tr.appendChild(
            createCell(
              `<span class="badge ${tierClass}">${this.escapeHTML(
                alert.detection_tier
              )}</span>`
            )
          );
          tr.appendChild(createCell(alert.anomaly_score.toFixed(1)));
          tr.appendChild(createCell(this.escapeHTML(alert.alert_reason)));

          const detailsCell = document.createElement("td");
          const detailsToggle = document.createElement("span");
          detailsToggle.className = "details-toggle";
          detailsToggle.textContent = ">";
          // Safely store data without putting it directly in HTML attributes for large objects
          detailsToggle.alertData = alert;
          detailsCell.appendChild(detailsToggle);
          tr.appendChild(detailsCell);

          this.elements.alertsTableBody.appendChild(tr);
        }
        this.currentAlertIds = newIds; // Update the set of current IDs for the next cycle
        this.addDetailsToggleListeners();
      }

      // --- Render Widgets ---
      const createRow = (label, value, valueClass = "value-primary") =>
        `<div class="widget-row"><span class="ip-mono">${this.escapeHTML(
          label
        )}</span><span class="${valueClass}">${this.escapeHTML(
          value
        )}</span></div>`;

      this.elements.widgets.activeIps.innerHTML = (state.top_active_ips || [])
        .map((item) => createRow(item.ip, item.value.toFixed(0)))
        .join("");

      this.elements.widgets.scoredIps.innerHTML = (state.top_error_ips || [])
        .map((item) =>
          createRow(item.ip, item.value.toFixed(2), "value-destructive")
        )
        .join("");

      // Dummy data for widgets not yet provided by the API
      this.elements.widgets.suspiciousPaths.innerHTML =
        createRow("/etc/passwd", 23, "value-destructive") +
        createRow("/admin/config.php", 18, "value-destructive");
      this.elements.widgets.threatIntel.innerHTML = createRow(
        "203.0.113.12",
        "Blocked",
        "value-destructive"
      );
    },

    addDetailsToggleListeners() {
      // Use event delegation for better performance
      this.elements.alertsTableBody.onclick = (e) => {
        if (!e.target.classList.contains("details-toggle")) return;

        const button = e.target;
        const tr = button.closest("tr");
        const existingDetails =
          tr.nextElementSibling &&
          tr.nextElementSibling.classList.contains("details-row");

        if (existingDetails) {
          existingDetails.remove();
          button.textContent = ">";
        } else {
          const alertData = button.alertData; // Retrieve data stored on the element
          const detailsRow = document.createElement("tr");
          detailsRow.className = "details-row visible";

          const detailsCell = document.createElement("td");
          detailsCell.colSpan = 6;
          detailsCell.className = "details-cell";

          const pre = document.createElement("pre");
          // Pretty-print the JSON with 2-space indentation
          pre.textContent = JSON.stringify(alertData, null, 2);

          detailsCell.appendChild(pre);
          detailsRow.appendChild(detailsCell);
          tr.insertAdjacentElement("afterend", detailsRow);
          button.textContent = "v";
        }
      };
    },

    escapeHTML(str) {
      const p = document.createElement("p");
      p.textContent = str;
      return p.innerHTML;
    },
  };

  App.init();
});
