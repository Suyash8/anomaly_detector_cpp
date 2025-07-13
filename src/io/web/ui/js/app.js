document.addEventListener("DOMContentLoaded", () => {
  const App = {
    // --- STATE ---
    charts: {},
    updateInterval: 2000,
    currentAlertIds: new Set(),

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
      this.startDataFetching();
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
    startDataFetching() {
      this.fetchPerformanceData();
      this.fetchOperationsData();
      setInterval(() => this.fetchPerformanceData(), this.updateInterval);
      setInterval(() => this.fetchOperationsData(), this.updateInterval * 2);
    },

    async fetchPerformanceData() {
      try {
        const response = await fetch("/api/v1/metrics/performance");
        if (!response.ok) return;
        const data = await response.json();
        this.updatePerformanceView(data);
      } catch (e) {
        console.error("Perf fetch failed:", e);
      }
    },

    async fetchOperationsData() {
      try {
        const [alertsRes, stateRes] = await Promise.all([
          fetch("/api/v1/operations/alerts"),
          fetch("/api/v1/operations/state"),
        ]);
        if (alertsRes.ok) this.updateAlertsView(await alertsRes.json());
        if (stateRes.ok) this.updateWidgets(await stateRes.json());
      } catch (e) {
        console.error("Ops fetch failed:", e);
      }
    },

    updatePerformanceView(data) {
      // KPIs
      const logs_per_sec =
        data.counters?.ad_logs_processed_total?.["total"]?.rate_per_second || 0;
      this.elements.kpis.logsPerSec.textContent = logs_per_sec.toFixed(1);

      const p90_latency_ms =
        (data.histograms?.ad_batch_processing_duration_seconds?.quantiles[
          "0.9"
        ] || 0) * 1000;
      this.elements.kpis.p90Latency.textContent = p90_latency_ms.toFixed(2);

      this.elements.kpis.memory.textContent = (
        (data.gauges?.ad_process_memory_rss_bytes || 0) /
        1024 /
        1024
      ).toFixed(1);

      // Latency Chart
      const timeLabel = new Date().toLocaleTimeString();
      this.updateLineChart(this.charts.latency, timeLabel, [
        (data.histograms?.ad_batch_processing_duration_seconds?.quantiles[
          "0.99"
        ] || 0) * 1000,
        p90_latency_ms,
        (data.histograms?.ad_batch_processing_duration_seconds?.quantiles[
          "0.5"
        ] || 0) * 1000,
      ]);

      // Breakdown Chart
      const findMetric = (prefix) =>
        Object.keys(data.histograms || {}).find((k) => k.startsWith(prefix));
      const logReaderKey = findMetric(
        "ad_log_reader_batch_fetch_duration_seconds"
      );
      const getAvg = (metric) =>
        metric && metric.count > 0 ? (metric.sum / metric.count) * 1000 : 0;

      this.charts.breakdown.data.datasets[0].data = [
        getAvg(data.histograms?.[logReaderKey]),
        getAvg(data.histograms?.ad_analysis_engine_process_duration_seconds),
        getAvg(data.histograms?.ad_rule_engine_evaluation_duration_seconds),
      ];
      this.charts.breakdown.update();
    },

    updateAlertsView(alerts) {
      if (!alerts || alerts.length === 0) return;

      // Update KPI
      const time_delta_seconds =
        alerts[0].analysis_context?.time_delta_seconds ||
        this.updateInterval / 1000;
      const alerts_per_min = (alerts.length / time_delta_seconds) * 60;
      this.elements.kpis.alertsPerMin.textContent = alerts_per_min.toFixed(1);

      // Render table
      this.elements.alertsTableBody.innerHTML = ""; // Clear old rows
      const newIds = new Set(alerts.map((a) => a.log_context.line_number));

      for (const alert of alerts) {
        const tr = document.createElement("tr");
        const isNew = !this.currentAlertIds.has(alert.log_context.line_number);
        if (isNew) tr.classList.add("new-alert");

        const tierClass = alert.detection_tier
          .toLowerCase()
          .replace(/_/g, "-")
          .replace("heuristic", "t1")
          .replace("statistical", "t2")
          .replace("ml", "t3");
        tr.innerHTML = `
                    <td>${new Date(
                      alert.timestamp_ms
                    ).toLocaleTimeString()}</td>
                    <td class="ip-mono">${alert.log_context.source_ip}</td>
                    <td><span class="badge ${tierClass}">${
          alert.detection_tier
        }</span></td>
                    <td>${alert.anomaly_score.toFixed(1)}</td>
                    <td>${alert.alert_reason}</td>
                    <td><span class="details-toggle" data-alert='${JSON.stringify(
                      alert
                    )}'>></span></td>
                `;
        this.elements.alertsTableBody.appendChild(tr);
      }
      this.currentAlertIds = newIds;
      this.addDetailsToggleListeners();
    },

    addDetailsToggleListeners() {
      this.elements.alertsTableBody
        .querySelectorAll(".details-toggle")
        .forEach((toggle) => {
          toggle.addEventListener("click", (e) => {
            const button = e.currentTarget;
            const tr = button.closest("tr");
            const existingDetails =
              tr.nextElementSibling &&
              tr.nextElementSibling.classList.contains("details-row");

            if (existingDetails) {
              existingDetails.remove();
              button.textContent = ">";
            } else {
              const alertData = JSON.parse(button.dataset.alert);
              const detailsRow = document.createElement("tr");
              detailsRow.className = "details-row visible";
              detailsRow.innerHTML = `<td colspan="6" class="details-cell"><pre>${JSON.stringify(
                alertData,
                null,
                2
              )}</pre></td>`;
              tr.insertAdjacentElement("afterend", detailsRow);
              button.textContent = "v";
            }
          });
        });
    },

    updateWidgets(state) {
      const createRow = (label, value, valueClass = "value-primary") =>
        `<div class="widget-row"><span class="ip-mono">${label}</span><span class="${valueClass}">${value}</span></div>`;

      this.elements.widgets.activeIps.innerHTML = state.top_active_ips
        .map((item) => createRow(item.ip, item.value.toFixed(0)))
        .join("");
      this.elements.widgets.scoredIps.innerHTML = state.top_error_ips
        .map((item) =>
          createRow(item.ip, item.value.toFixed(2), "value-destructive")
        )
        .join("");

      // Dummy data for now as API does not provide this yet
      this.elements.widgets.suspiciousPaths.innerHTML =
        createRow("/etc/passwd", 23, "value-destructive") +
        createRow("/admin/config.php", 18, "value-destructive");
      this.elements.widgets.threatIntel.innerHTML = createRow(
        "203.0.113.12",
        "Blocked",
        "value-destructive"
      );
    },

    updateLineChart(chart, label, dataPoints) {
      chart.data.labels.push(label);
      if (chart.data.labels.length > 30) chart.data.labels.shift();
      dataPoints.forEach((point, i) => {
        chart.data.datasets[i].data.push(point);
        if (chart.data.datasets[i].data.length > 30)
          chart.data.datasets[i].data.shift();
      });
      chart.update("none"); // Use 'none' for smoother updates
    },
  };

  App.init();
});
