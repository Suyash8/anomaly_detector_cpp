import React, { useMemo } from "react";
import AlertsTable from "../components/AlertsTable";
import WidgetCard from "../components/WidgetCard";

export default function OperationsView({ data }) {
  const { alerts, state } = data || { alerts: [], state: null };

  const formattedWidgets = useMemo(() => {
    if (!state)
      return {
        activeIps: [
          {
            label: "0.0.0.0",
            value: 1,
          },
          {
            label: "192.168.1.1",
            value: 2,
          },
          {
            label: "10.0.0.1",
            value: 3,
          },
          {
            label: "172.16.0.1",
            value: 4,
          },
          {
            label: "192.168.0.1",
            value: 5,
          },
        ],
        errorIps: [
          {
            label: "0.0.0.0",
            value: 0.5021,
          },
          {
            label: "192.168.1.1",
            value: 0.2183,
          },
          {
            label: "10.0.0.1",
            value: 0.3008,
          },
          {
            label: "172.16.0.1",
            value: 0.6721,
          },
          {
            label: "192.168.0.1",
            value: 0.7601,
          },
        ],
      };
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
