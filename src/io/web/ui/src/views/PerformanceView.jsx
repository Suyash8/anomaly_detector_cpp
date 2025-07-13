import React, { useState, useEffect, useMemo } from "react";
import KpiCard from "../components/KpiCard";
import ChartCard from "../components/ChartCard";

const chartOptions = {
  responsive: true,
  maintainAspectRatio: false,
  scales: {
    x: { ticks: { color: "#aaa" }, grid: { color: "#444" } },
    y: { ticks: { color: "#aaa" }, grid: { color: "#444" }, beginAtZero: true },
  },
  plugins: { legend: { labels: { color: "#e0e0e0" } } },
  animation: { duration: 250 },
};

export default function PerformanceView({ data }) {
  const [runtimeSeconds, setRuntimeSeconds] = useState(0);

  // Chart history state
  const [latencyHistory, setLatencyHistory] = useState([]);
  const [latencyLabels, setLatencyLabels] = useState([]);

  const [memoryHistory, setMemoryHistory] = useState([]);
  const [memoryLabels, setMemoryLabels] = useState([]);

  const [breakdownData, setBreakdownData] = useState([0, 0, 0]);

  // Sync runtime on data update
  useEffect(() => {
    if (data?.app_runtime_seconds != null) {
      setRuntimeSeconds(Math.floor(data.app_runtime_seconds));
    }
  }, [data]);

  // Tick up every second
  useEffect(() => {
    const interval = setInterval(() => {
      setRuntimeSeconds((prev) => prev + 1);
    }, 1000);
    return () => clearInterval(interval);
  }, []);

  // Update chart histories on new data
  useEffect(() => {
    if (!data) return;

    const nowLabel = new Date().toLocaleTimeString();
    const MAX_HISTORY = 30;

    const { histograms, gauges } = data;

    const getHistogramStats = (metricName) => {
      const obs = histograms?.[metricName]?.recent_observations || [];
      if (obs.length === 0) return { avg: 0, p50: 0, p90: 0, p99: 0 };
      const values = obs.map((o) => o[1]).sort((a, b) => a - b);
      const sum = values.reduce((acc, v) => acc + v, 0);
      return {
        avg: sum / values.length,
        p50: values[Math.floor(values.length * 0.5)] || 0,
        p90: values[Math.floor(values.length * 0.9)] || 0,
        p99: values[Math.floor(values.length * 0.99)] || 0,
      };
    };

    const latencyStats = getHistogramStats(
      "ad_batch_processing_duration_seconds"
    );
    setLatencyHistory((prev) =>
      [
        ...prev,
        [
          latencyStats.p99 * 1000,
          latencyStats.p90 * 1000,
          latencyStats.p50 * 1000,
        ],
      ].slice(-MAX_HISTORY)
    );
    setLatencyLabels((prev) => [...prev, nowLabel].slice(-MAX_HISTORY));

    setMemoryHistory((prev) =>
      [...prev, (gauges?.ad_process_memory_rss_bytes || 0) / 1024 / 1024].slice(
        -MAX_HISTORY
      )
    );
    setMemoryLabels((prev) => [...prev, nowLabel].slice(-MAX_HISTORY));

    const readerKey = Object.keys(histograms || {}).find((k) =>
      k.startsWith("ad_log_reader")
    );
    setBreakdownData([
      getHistogramStats(readerKey).avg * 1000,
      getHistogramStats("ad_analysis_engine_process_duration_seconds").avg *
        1000,
      getHistogramStats("ad_rule_engine_evaluation_duration_seconds").avg *
        1000,
    ]);
  }, [data]);

  // KPIs
  const processed = useMemo(() => {
    if (!data) return null;
    const { time_window_counters, gauges, histograms } = data;

    const totalLogs = time_window_counters?.ad_logs_processed?.["total"] || 0;
    const logsPerSec = totalLogs / runtimeSeconds;

    const totalAlerts =
      time_window_counters?.ad_alerts_generated?.["total"] || 0;
    const alertsPerMin = (totalAlerts / runtimeSeconds) * 60.0;

    const latencyObs =
      histograms?.ad_batch_processing_duration_seconds?.recent_observations ||
      [];
    const values = latencyObs.map((obs) => obs[1]).sort((a, b) => a - b);
    const p90Latency = values[Math.floor(values.length * 0.9)] || 0;

    const memoryMB = (gauges?.ad_process_memory_rss_bytes || 0) / 1024 / 1024;

    const hours = String(Math.floor(runtimeSeconds / 3600)).padStart(2, "0");
    const minutes = String(Math.floor((runtimeSeconds % 3600) / 60)).padStart(
      2,
      "0"
    );
    const seconds = String(Math.floor(runtimeSeconds % 60)).padStart(2, "0");
    const runtime = `${hours}:${minutes}:${seconds}`;

    return { logsPerSec, alertsPerMin, p90Latency, memoryMB, runtime };
  }, [data, runtimeSeconds]);

  if (!processed) return null;

  return (
    <div className="view active" id="performance-view">
      <div className="kpi-container">
        <KpiCard title="LOGS / SEC" value={processed.logsPerSec.toFixed(1)} />
        <KpiCard
          title="ALERTS / MIN"
          value={processed.alertsPerMin.toFixed(1)}
        />
        <KpiCard
          title="P90 LATENCY"
          value={(processed.p90Latency * 1000).toFixed(2)}
          unit="ms"
        />
        <KpiCard
          title="MEMORY"
          value={processed.memoryMB.toFixed(1)}
          unit="MB"
        />
        <KpiCard title="RUNTIME" value={processed.runtime} />
      </div>

      <ChartCard
        title="Latency Over Time"
        type="line"
        options={chartOptions}
        data={{
          labels: latencyLabels,
          datasets: [
            {
              label: "p99",
              data: latencyHistory.map((row) => row[0]),
              borderColor: "#ff6384",
              tension: 0.2,
              pointRadius: 0,
            },
            {
              label: "p90",
              data: latencyHistory.map((row) => row[1]),
              borderColor: "#00aaff",
              tension: 0.2,
              pointRadius: 0,
            },
            {
              label: "p50",
              data: latencyHistory.map((row) => row[2]),
              borderColor: "#ffce56",
              tension: 0.2,
              pointRadius: 0,
            },
          ],
        }}
      />

      <ChartCard
        title="Latency Breakdown"
        type="bar"
        options={{
          ...chartOptions,
          indexAxis: "y",
          plugins: { legend: { display: false } },
        }}
        data={{
          labels: ["Log Reader", "Analysis", "Rules"],
          datasets: [
            {
              label: "Avg Latency (ms)",
              data: breakdownData,
              backgroundColor: ["#ff6384", "#00aaff", "#ffce56"],
            },
          ],
        }}
      />

      <ChartCard
        title="Memory Usage"
        type="line"
        options={chartOptions}
        data={{
          labels: memoryLabels,
          datasets: [
            {
              label: "Memory RSS (MB)",
              data: memoryHistory,
              borderColor: "#4bc0c0",
              backgroundColor: "rgba(75, 192, 192, 0.2)",
              fill: true,
              tension: 0.2,
              pointRadius: 0,
            },
          ],
        }}
      />
    </div>
  );
}
