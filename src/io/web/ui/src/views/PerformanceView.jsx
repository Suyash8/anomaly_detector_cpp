import React, { useState, useEffect } from "react";
import KpiCard from "../components/KpiCard";
import WidgetCard from "../components/WidgetCard";
import ChartCard from "../components/ChartCard";
import { useRuntime } from "../hooks/useRuntime";
import { usePerformanceMetrics } from "../hooks/usePerformanceMetrics";

import { createInitialLineChartData } from "../utils/chartUtils";

// Common chart options
const commonChartOptions = {
  responsive: true,
  maintainAspectRatio: false,
  scales: {
    x: {
      ticks: {
        color: "#aaa",
        maxRotation: 0,
        autoSkip: true,
        maxTicksLimit: 10,
      },
      grid: { color: "#444" },
    },
    y: { ticks: { color: "#aaa" }, grid: { color: "#444" }, beginAtZero: true },
  },
  plugins: {
    legend: {
      labels: { color: "#e0e0e0", boxWidth: 12, padding: 15 },
      position: "bottom",
    },
  },
  animation: { duration: 0 },
};

export default function PerformanceView({ data }) {
  const [runtimeSeconds, setRuntimeSeconds] = useState(
    data?.app_runtime_seconds
  );

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

  // --- State and Hooks ---
  const { formattedRuntime } = useRuntime(runtimeSeconds);
  const processed = usePerformanceMetrics(data, runtimeSeconds);

  // State for historical line charts
  const [latencyChartData, setLatencyChartData] = useState(
    createInitialLineChartData([
      { label: "p99", borderColor: "#ff6384", tension: 0.2, pointRadius: 0 },
      { label: "p90", borderColor: "#00aaff", tension: 0.2, pointRadius: 0 },
      { label: "p50", borderColor: "#ffce56", tension: 0.2, pointRadius: 0 },
    ])
  );
  const [memoryChartData, setMemoryChartData] = useState(
    createInitialLineChartData([
      {
        label: "Memory RSS (MB)",
        borderColor: "#4bc0c0",
        backgroundColor: "rgba(75, 192, 192, 0.2)",
        fill: true,
        tension: 0.2,
        pointRadius: 0,
      },
    ])
  );
  const [stateElementsChartData, setStateElementsChartData] = useState(
    createInitialLineChartData([
      { label: "IP Asset Request", borderColor: "#ff6384" },
      { label: "IP Failed Login", borderColor: "#36a2eb" },
      { label: "IP HTML Request", borderColor: "#ffce56" },
      { label: "IP Paths Seen", borderColor: "#4bc0c0" },
      { label: "IP User Agents", borderColor: "#9966ff" },
      { label: "Session Request", borderColor: "#ff9f40" },
      { label: "Session Unique Paths", borderColor: "#00c853" },
      { label: "Session Unique UA", borderColor: "#8d6e63" },
    ])
  );

  // Effect to update historical chart data when new data arrives
  useEffect(() => {
    if (!data) return;
    const MAX_HISTORY = 30;
    const nowLabel = new Date().toLocaleTimeString();

    // Update Latency Chart
    const latencyStats =
      data.histograms?.ad_batch_processing_duration_seconds
        ?.recent_observations || [];
    const sortedLatency = latencyStats.map((o) => o[1]).sort((a, b) => a - b);
    const p99 =
      (sortedLatency[Math.floor(sortedLatency.length * 0.99)] || 0) * 1000;
    const p90 =
      (sortedLatency[Math.floor(sortedLatency.length * 0.9)] || 0) * 1000;
    const p50 =
      (sortedLatency[Math.floor(sortedLatency.length * 0.5)] || 0) * 1000;

    setLatencyChartData((prev) => ({
      labels: [...prev.labels, nowLabel].slice(-MAX_HISTORY),
      datasets: [
        {
          ...prev.datasets[0],
          data: [...prev.datasets[0].data, p99].slice(-MAX_HISTORY),
        },
        {
          ...prev.datasets[1],
          data: [...prev.datasets[1].data, p90].slice(-MAX_HISTORY),
        },
        {
          ...prev.datasets[2],
          data: [...prev.datasets[2].data, p50].slice(-MAX_HISTORY),
        },
      ],
    }));

    // Update Memory Chart
    const memoryMB =
      (data.gauges?.ad_process_memory_rss_bytes || 0) / 1024 / 1024;
    setMemoryChartData((prev) => ({
      labels: [...prev.labels, nowLabel].slice(-MAX_HISTORY),
      datasets: [
        {
          ...prev.datasets[0],
          data: [...prev.datasets[0].data, memoryMB].slice(-MAX_HISTORY),
        },
      ],
    }));

    // Update State Elements Chart
    const stateElements = data.gauges?.ad_state_elements_total || {};
    setStateElementsChartData((prev) => ({
      labels: [...prev.labels, nowLabel].slice(-MAX_HISTORY),
      datasets: [
        {
          ...prev.datasets[0],
          data: [
            ...prev.datasets[0].data,
            stateElements.ip_request_window || 0,
          ].slice(-MAX_HISTORY),
        },
        {
          ...prev.datasets[1],
          data: [
            ...prev.datasets[1].data,
            stateElements.ip_failed_login_window || 0,
          ].slice(-MAX_HISTORY),
        },
        {
          ...prev.datasets[2],
          data: [
            ...prev.datasets[2].data,
            stateElements.ip_html_request_window || 0,
          ].slice(-MAX_HISTORY),
        },
        {
          ...prev.datasets[3],
          data: [
            ...prev.datasets[3].data,
            stateElements.ip_paths_seen_set || 0,
          ].slice(-MAX_HISTORY),
        },
        {
          ...prev.datasets[4],
          data: [
            ...prev.datasets[4].data,
            stateElements.ip_user_agents_set || 0,
          ].slice(-MAX_HISTORY),
        },
        {
          ...prev.datasets[5],
          data: [
            ...prev.datasets[5].data,
            stateElements.session_request_window || 0,
          ].slice(-MAX_HISTORY),
        },
        {
          ...prev.datasets[6],
          data: [
            ...prev.datasets[6].data,
            stateElements.session_unique_paths_set || 0,
          ].slice(-MAX_HISTORY),
        },
        {
          ...prev.datasets[7],
          data: [
            ...prev.datasets[7].data,
            stateElements.session_unique_ua_set || 0,
          ].slice(-MAX_HISTORY),
        },
      ],
    }));
  }, [data]);

  // if (!processed)
  //   return <div className="view active">Loading performance data...</div>;

  return (
    <div className="view active" id="performance-view">
      <div className="kpi-container">
        <KpiCard title="LOGS / SEC" value={processed.kpis.logsPerSec} />
        <KpiCard title="ALERTS / MIN" value={processed.kpis.alertsPerMin} />
        <KpiCard
          title="P90 LATENCY"
          value={processed.kpis.p90Latency}
          unit="ms"
        />
        <KpiCard title="MEMORY" value={processed.kpis.memoryMB} unit="MB" />
        <KpiCard title="RUNTIME" value={formattedRuntime} />
      </div>

      <div className="performance-grid">
        <div className="main-charts">
          <ChartCard
            title="Batch Processing Latency"
            type="line"
            data={latencyChartData}
            options={commonChartOptions}
          />
          <ChartCard
            title="Average Latency Breakdown"
            type="bar"
            data={processed.charts.breakdownChartData}
            options={{
              ...commonChartOptions,
              indexAxis: "y",
              plugins: { legend: { display: false } },
            }}
          />
        </div>
        <div className="side-panel">
          <WidgetCard
            title="Active States Overview"
            data={processed.widgets.stateOverviewMetrics}
            valueFormatter={processed.widgets.formatValue}
          />
          <WidgetCard
            title="Total State Elements in Memory"
            data={processed.widgets.stateElementMetrics}
            valueFormatter={processed.widgets.formatValue}
          />
          <ChartCard
            title="State Element Counts"
            type="line"
            data={stateElementsChartData}
            options={{
              ...commonChartOptions,
              scales: {
                ...commonChartOptions.scales,
                y: { ...commonChartOptions.scales.y, type: "logarithmic" },
              },
            }}
          />
          <ChartCard
            title="Process Memory Usage"
            type="line"
            data={memoryChartData}
            options={{
              ...commonChartOptions,
              plugins: { legend: { display: false } },
            }}
          />
          {processed.charts.isDeepDiveEnabled && (
            <ChartCard
              title="Fine-Grained Latency (µs)"
              type="bar"
              data={processed.charts.deepDiveChartData}
              options={{
                ...commonChartOptions,
                indexAxis: "y",
                plugins: { legend: { display: false } },
              }}
            />
          )}
        </div>
      </div>
    </div>
  );
}
