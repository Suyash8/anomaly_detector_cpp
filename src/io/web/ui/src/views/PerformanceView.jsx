import React, { useMemo } from "react";
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
  // Memoize processed data to avoid re-calculation on every render
  const processed = useMemo(() => {
    if (!data) return null;

    const { time_window_counters, gauges, app_runtime_seconds, histograms } =
      data;
    const logsInLastMinute =
      time_window_counters?.ad_logs_processed?.["1m"] || 0;
    const logsPerSec = logsInLastMinute / 60.0;

    const p90Latency =
      (
        histograms?.ad_batch_processing_duration_seconds?.recent_observations ||
        []
      )
        .map((obs) => obs[1])
        .sort((a, b) => a - b)[
        Math.floor(
          (histograms?.ad_batch_processing_duration_seconds?.recent_observations
            .length || 0) * 0.9
        )
      ] || 0;

    const memoryMB = (gauges?.ad_process_memory_rss_bytes || 0) / 1024 / 1024;

    const runtime_s = app_runtime_seconds || 0;
    const hours = String(Math.floor(runtime_s / 3600)).padStart(2, "0");
    const minutes = String(Math.floor((runtime_s % 3600) / 60)).padStart(
      2,
      "0"
    );
    const seconds = String(Math.floor(runtime_s % 60)).padStart(2, "0");
    const runtime = `${hours}:${minutes}:${seconds}`;

    return { logsPerSec, p90Latency, memoryMB, runtime };
  }, [data]);

  if (!processed) return null;

  return (
    <div className="kpi-container">
      <KpiCard title="LOGS / SEC" value={processed.logsPerSec.toFixed(1)} />
      <KpiCard title="ALERTS / MIN" value={"N/A"} />
      <KpiCard
        title="P90 LATENCY (ms)"
        value={(processed.p90Latency * 1000).toFixed(2)}
      />
      <KpiCard title="MEMORY (MB)" value={processed.memoryMB.toFixed(1)} />
      <KpiCard title="RUNTIME" value={processed.runtime} />
    </div>
    // Chart components would go here, receiving processed data
  );
}
