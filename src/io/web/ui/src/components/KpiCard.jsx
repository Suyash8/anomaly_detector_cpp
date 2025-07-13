import React from "react";

export default function KpiCard({ title, value, unit = "" }) {
  return (
    <div className="kpi-card">
      <h3>{title}</h3>
      <span>
        {value !== null && value !== undefined ? value : "..."} {unit}
      </span>
    </div>
  );
}
