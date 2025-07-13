import React, { useMemo } from "react";
import AlertsTable from "../components/AlertsTable";
import WidgetCard from "../components/WidgetCard";

export default function OperationsView({ data }) {
  const { alerts, state } = data;

  const formattedWidgets = useMemo(() => {
    if (!state) return {};
    return {
      activeIps: (state.top_active_ips || []).map((item) => ({
        label: item.ip,
        value: item.value,
      })),
      errorIps: (state.top_error_ips || []).map((item) => ({
        label: item.ip,
        value: item.value,
      })),
    };
  }, [state]);

  return (
    <div className="operations-grid">
      <AlertsTable alerts={alerts} />
      <div className="side-widgets-container">
        <WidgetCard
          title="Most Active IPs"
          data={formattedWidgets.activeIps}
          valueFormatter={(val) => `${val.toFixed(0)} reqs`}
        />
        <WidgetCard
          title="Top IPs by Error Rate"
          data={formattedWidgets.errorIps}
          valueFormatter={(val) => `${(val * 100).toFixed(1)}%`}
          valueClass="value-destructive"
        />
        <WidgetCard title="Suspicious Paths" />
        <WidgetCard title="Threat Intel Hits" />
      </div>
    </div>
  );
}
