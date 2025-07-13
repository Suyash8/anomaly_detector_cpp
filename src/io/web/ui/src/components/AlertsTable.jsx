import React, { useState } from "react";

const ShieldIcon = ({ className = "" }) => (
  <svg
    className={`shield-icon ${className}`}
    fill="none"
    stroke="currentColor"
    viewBox="0 0 24 24"
  >
    <path
      strokeLinecap="round"
      strokeLinejoin="round"
      strokeWidth="2"
      d="M12 2L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-3z"
    ></path>
  </svg>
);

const AlertRow = ({ alert }) => {
  const [isExpanded, setIsExpanded] = useState(false);

  const tierClass =
    {
      TIER1_HEURISTIC: "tier-t1",
      TIER2_STATISTICAL: "tier-t2",
      TIER3_ML: "tier-t3",
    }[alert.detection_tier] || "tier-unknown";

  return (
    <>
      <tr>
        <td>{new Date(alert.timestamp_ms).toLocaleTimeString()}</td>
        <td>
          <span className="ip-mono">{alert.log_context.source_ip}</span>
        </td>
        <td>
          <span className={`badge ${tierClass}`}>
            {alert.detection_tier.split("_")[0]}
          </span>
        </td>
        <td>{alert.anomaly_score.toFixed(1)}</td>
        <td>{alert.alert_reason}</td>
        <td>
          <span
            className="details-toggle"
            onClick={() => setIsExpanded(!isExpanded)}
          >
            {isExpanded ? "v" : ">"}
          </span>
        </td>
      </tr>
      {isExpanded && (
        <tr className="details-row visible">
          <td colSpan="6" className="details-cell">
            <pre>{JSON.stringify(alert, null, 2)}</pre>
          </td>
        </tr>
      )}
    </>
  );
};

export default function AlertsTable({ alerts = [] }) {
  return (
    <div className="alerts-feed-card">
      <div className="card-header">
        <ShieldIcon className="small" />
        <h2>Recent Alerts</h2>
      </div>
      <div className="alerts-table-container">
        <table id="alerts-table">
          <thead>
            <tr>
              <th>Time</th>
              <th>Source IP</th>
              <th>Tier</th>
              <th>Score</th>
              <th>Reason</th>
              <th>Details</th>
            </tr>
          </thead>
          <tbody>
            {alerts.map((alert, index) => (
              <AlertRow
                key={`${alert.log_context.line_number}-${index}`}
                alert={alert}
              />
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
