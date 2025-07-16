import { useMemo } from "react";

const getHistogramStats = (histograms, metricName) => {
  if (!histograms || !metricName) return { avg: 0, p50: 0, p90: 0, p99: 0 };
  const obs = histograms[metricName]?.recent_observations || [];
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

export function usePerformanceMetrics(data, runtime) {
  return useMemo(() => {
    if (!data)
      return {
        kpis: {
          logsPerSec: NaN,
          alertsPerMin: NaN,
          p90Latency: NaN,
          memoryMB: NaN,
        },
        widgets: {
          stateOverviewMetrics: [
            { label: "Active IP States", value: NaN },
            {
              label: "Active Path States",
              value: NaN,
            },
            {
              label: "Active Session States",
              value: NaN,
            },
          ],
          stateElementMetrics: [
            {
              label: "IP Asset Request",
              value: NaN,
            },
            {
              label: "IP Failed Login",
              value: NaN,
            },
            {
              label: "IP HTML Request",
              value: NaN,
            },
            {
              label: "IP Paths Seen",
              value: NaN,
            },
            {
              label: "IP User Agents",
              value: NaN,
            },
            {
              label: "Session Request",
              value: NaN,
            },
            {
              label: "Session Unique Paths",
              value: NaN,
            },
            {
              label: "Session Unique UA",
              value: NaN,
            },
          ],
          formatValue: (val) => val,
        },
        charts: {
          breakdownChartData: {
            labels: ["Log Reader", "Analysis", "Rules"],
            datasets: [
              {
                label: "Avg Latency (ms)",
                data: [NaN, NaN, NaN],
                backgroundColor: ["#ff6384", "#00aaff", "#ffce56"],
              },
            ],
          },
          deepDiveChartData: {
            labels: [
              "Analysis Engine",
              "Rule Engine",
              "State Lookup",
              "UA Analysis",
              "ZScore Calculation",
              "Tier 1 Rules",
              "Tier 2 Rules",
              "Tier 3 Rules",
            ],
            datasets: [
              {
                label: "Avg Latency (µs)",
                data: [NaN, NaN, NaN, NaN, NaN, NaN, NaN, NaN],
                backgroundColor: [
                  "#ff6384",
                  "#36a2eb",
                  "#ffce56",
                  "#4bc0c0",
                  "#9966ff",
                  "#ff9f40",
                  "#00c853",
                  "#8d6e63",
                ],
              },
            ],
          },
          isDeepDiveEnabled: true,
        },
      };

    const { time_window_counters, gauges, histograms } = data;

    // --- Process KPIs ---
    const totalLogs = time_window_counters?.ad_logs_processed?.["total"] || 0;
    const logsPerSec = (totalLogs / runtime).toFixed(1);

    const memoryMB = (
      (gauges?.ad_process_memory_rss_bytes || 0) /
      1024 /
      1024
    ).toFixed(1);

    const totalAlerts =
      time_window_counters?.ad_alerts_generated?.["total"] || 0;
    const alertsPerMin = ((totalAlerts / runtime) * 60).toFixed(1);

    const latencyObs =
      histograms?.ad_batch_processing_duration_seconds?.recent_observations ||
      [];
    const values = latencyObs.map((obs) => obs[1]).sort((a, b) => a - b);
    const p90Latency = values[Math.floor(values.length * 0.9)] || 0;

    // --- Process Widget Data ---
    const formatValue = (val) =>
      val > 999 ? `${(val / 1000).toFixed(1)}k` : String(val || 0);
    const stateOverviewMetrics = [
      { label: "Active IP States", value: gauges?.ad_active_ip_states || 0 },
      {
        label: "Active Path States",
        value: gauges?.ad_active_path_states || 0,
      },
      {
        label: "Active Session States",
        value: gauges?.ad_active_session_states || 0,
      },
    ];
    const stateElements = gauges?.ad_state_elements_total || {};
    const stateElementMetrics = [
      {
        label: "IP Asset Reqest",
        value: stateElements.ip_asset_request_window || 0,
      },
      {
        label: "IP Failed Login",
        value: stateElements.ip_failed_login_window || 0,
      },
      {
        label: "IP HTML Reqest",
        value: stateElements.ip_html_request_window || 0,
      },
      {
        label: "IP Paths Seen",
        value: stateElements.ip_paths_seen_set || 0,
      },
      {
        label: "IP User Agents",
        value: stateElements.ip_ua_window || 0,
      },
      {
        label: "Session Request",
        value: stateElements.session_request_window || 0,
      },
      {
        label: "Session Unique Paths",
        value: stateElements.session_unique_paths || 0,
      },
      {
        label: "Session Unique UA",
        value: stateElements.session_unique_user_agents || 0,
      },
    ];

    // --- Process Chart Data ---
    const readerKey = Object.keys(histograms || {}).find((k) =>
      k.startsWith("ad_log_reader")
    );
    const breakdownChartData = {
      labels: ["Log Reader", "Analysis", "Rules"],
      datasets: [
        {
          label: "Avg Latency (ms)",
          data: [
            getHistogramStats(histograms, readerKey).avg,
            getHistogramStats(
              histograms,
              "ad_analysis_engine_process_duration_seconds"
            ).avg * 1000,
            getHistogramStats(
              histograms,
              "ad_rule_engine_evaluation_duration_seconds"
            ).avg * 1000,
          ],
          backgroundColor: ["#ff6384", "#00aaff", "#ffce56"],
        },
      ],
    };

    const deepDiveStats = {
      analysisEngine: getHistogramStats(
        histograms,
        "ad_analysis_engine_process_duration_seconds"
      ).avg,
      ruleEngine: getHistogramStats(
        histograms,
        "ad_rule_engine_evaluation_duration_seconds"
      ).avg,
      stateLookup: getHistogramStats(
        histograms,
        "ad_analysis_state_lookup_duration_seconds"
      ).avg,
      uaAnalysis: getHistogramStats(
        histograms,
        "ad_analysis_ua_analysis_duration_seconds"
      ).avg,
      zscoreCalculation: getHistogramStats(
        histograms,
        "ad_analysis_zscore_calc_duration_seconds"
      ).avg,
      tier1: getHistogramStats(histograms, "ad_rules_tier1_duration_seconds")
        .avg,
      tier2: getHistogramStats(histograms, "ad_rules_tier2_duration_seconds")
        .avg,
      tier3: getHistogramStats(histograms, "ad_rules_tier3_duration_seconds")
        .avg,
    };
    const deepDiveChartData = {
      labels: [
        "Analysis Engine",
        "Rule Engine",
        "State Lookup",
        "UA Analysis",
        "ZScore Calculation",
        "Tier 1 Rules",
        "Tier 2 Rules",
        "Tier 3 Rules",
      ],
      datasets: [
        {
          label: "Avg Latency (µs)",
          data: [
            deepDiveStats.analysisEngine * 1e6,
            deepDiveStats.ruleEngine * 1e6,
            deepDiveStats.stateLookup * 1e6,
            deepDiveStats.uaAnalysis * 1e6,
            deepDiveStats.zscoreCalculation * 1e6,
            deepDiveStats.tier1 * 1e6,
            deepDiveStats.tier2 * 1e6,
            deepDiveStats.tier3 * 1e6,
          ],
          backgroundColor: [
            "#ff6384",
            "#36a2eb",
            "#ffce56",
            "#4bc0c0",
            "#9966ff",
            "#ff9f40",
            "#00c853",
            "#8d6e63",
          ],
        },
      ],
    };
    const isDeepDiveEnabled = deepDiveStats.stateLookup > 0;

    return {
      kpis: {
        logsPerSec,
        alertsPerMin,
        p90Latency: (p90Latency || 0).toFixed(2),
        memoryMB,
      },
      widgets: {
        stateOverviewMetrics,
        stateElementMetrics,
        formatValue,
      },
      charts: {
        breakdownChartData,
        deepDiveChartData,
        isDeepDiveEnabled,
      },
    };
  }, [data, runtime]);
}
