document.addEventListener("DOMContentLoaded", () => {
  const App = {
    // State
    charts: {},
    lastLogCount: 0,
    lastAlertCount: 0,
    lastTimestamp: Date.now(),
    updateInterval: 2000, // 2 seconds

    // UI Elements
    elements: {
      navPerformance: document.getElementById("nav-performance"),
      navOperations: document.getElementById("nav-operations"),
      performanceView: document.getElementById("performance-view"),
      operationsView: document.getElementById("operations-view"),
      kpiLogsPerSec: document.getElementById("kpi-logs-per-sec"),
      kpiAlertsPerMin: document.getElementById("kpi-alerts-per-min"),
      kpiP90Latency: document.getElementById("kpi-p90-latency"),
    },

    init() {
      this.setupNavigation();
      this.setupCharts();
      this.fetchPerformanceData();
      setInterval(() => this.fetchPerformanceData(), this.updateInterval);
    },

    setupNavigation() {
      this.elements.navPerformance.addEventListener("click", () =>
        this.switchView("performance")
      );
      this.elements.navOperations.addEventListener("click", () =>
        this.switchView("operations")
      );
    },

    switchView(viewName) {
      this.elements.navPerformance.classList.toggle(
        "active",
        viewName === "performance"
      );
      this.elements.navOperations.classList.toggle(
        "active",
        viewName === "operations"
      );
      this.elements.performanceView.classList.toggle(
        "active",
        viewName === "performance"
      );
      this.elements.operationsView.classList.toggle(
        "active",
        viewName === "operations"
      );
    },

    setupCharts() {
      const chartOptions = {
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

      // Latency Chart
      const latencyCtx = document
        .getElementById("latency-chart")
        .getContext("2d");
      this.charts.latency = new Chart(latencyCtx, {
        type: "line",
        data: {
          labels: [],
          datasets: [
            {
              label: "p99 Latency (ms)",
              data: [],
              borderColor: "#ff6384",
              tension: 0.2,
            },
            {
              label: "p90 Latency (ms)",
              data: [],
              borderColor: "#36a2eb",
              tension: 0.2,
            },
            {
              label: "p50 Latency (ms)",
              data: [],
              borderColor: "#ffce56",
              tension: 0.2,
            },
          ],
        },
        options: chartOptions,
      });

      // Breakdown Chart
      const breakdownCtx = document
        .getElementById("breakdown-chart")
        .getContext("2d");
      this.charts.breakdown = new Chart(breakdownCtx, {
        type: "bar",
        data: {
          labels: ["Log Reader", "Analysis Engine", "Rule Engine"],
          datasets: [
            {
              label: "Avg Latency (ms)",
              data: [0, 0, 0],
              backgroundColor: ["#ff6384", "#36a2eb", "#ffce56"],
            },
          ],
        },
        options: { ...chartOptions, indexAxis: "y" },
      });
    },

    async fetchPerformanceData() {
      try {
        const response = await fetch("/api/v1/metrics/performance");
        if (!response.ok)
          throw new Error(`HTTP error! status: ${response.status}`);
        const data = await response.json();
        this.updateUI(data);
      } catch (error) {
        console.error("Failed to fetch performance data:", error);
      }
    },

    updateUI(data) {
      const now = Date.now();
      const timeDiffSec = (now - this.lastTimestamp) / 1000;
      this.lastTimestamp = now;

      // Update KPIs
      const logCount = data.counters?.ad_logs_processed_total?.total || 0;
      const logDelta = logCount - this.lastLogCount;
      this.lastLogCount = logCount;
      this.elements.kpiLogsPerSec.textContent = (
        logDelta / timeDiffSec
      ).toFixed(1);

      const alertCount = data.counters?.ad_alerts_generated_total
        ? Object.values(data.counters.ad_alerts_generated_total).reduce(
            (a, b) => a + b,
            0
          )
        : 0;
      const alertDelta = alertCount - this.lastAlertCount;
      this.lastAlertCount = alertCount;
      this.elements.kpiAlertsPerMin.textContent = (
        (alertDelta / timeDiffSec) *
        60
      ).toFixed(1);

      const p90_latency_ms =
        (data.histograms?.ad_batch_processing_duration_seconds?.quantiles[
          "0.9"
        ] || 0) * 1000;
      this.elements.kpiP90Latency.textContent = p90_latency_ms.toFixed(2);

      // Update Latency Chart
      this.updateLineChart(
        this.charts.latency,
        new Date().toLocaleTimeString(),
        [
          (data.histograms?.ad_batch_processing_duration_seconds?.quantiles[
            "0.99"
          ] || 0) * 1000,
          p90_latency_ms,
          (data.histograms?.ad_batch_processing_duration_seconds?.quantiles[
            "0.5"
          ] || 0) * 1000,
        ]
      );

      // Update Breakdown Chart
      const breakdownData = [
        ((data.histograms?.[
          'ad_log_reader_batch_fetch_duration_seconds{type="file"}'
        ]?.sum || 0) /
          (data.histograms?.[
            'ad_log_reader_batch_fetch_duration_seconds{type="file"}'
          ]?.count || 1)) *
          1000,
        ((data.histograms?.ad_analysis_engine_process_duration_seconds?.sum ||
          0) /
          (data.histograms?.ad_analysis_engine_process_duration_seconds
            ?.count || 1)) *
          1000,
        ((data.histograms?.ad_rule_engine_evaluation_duration_seconds?.sum ||
          0) /
          (data.histograms?.ad_rule_engine_evaluation_duration_seconds?.count ||
            1)) *
          1000,
      ];
      this.charts.breakdown.data.datasets[0].data = breakdownData;
      this.charts.breakdown.update();
    },

    updateLineChart(chart, label, dataPoints) {
      chart.data.labels.push(label);
      if (chart.data.labels.length > 20) {
        chart.data.labels.shift();
      }
      dataPoints.forEach((point, index) => {
        chart.data.datasets[index].data.push(point);
        if (chart.data.datasets[index].data.length > 20) {
          chart.data.datasets[index].data.shift();
        }
      });
      chart.update();
    },
  };

  App.init();
});
