import React from "react";

export default function WidgetCard({
  title,
  data = [],
  valueFormatter,
  valueClass = "value-primary",
}) {
  return (
    <div className="widget-card">
      <div className="card-header">
        <h3>{title}</h3>
      </div>
      <div className="widget-content">
        {data.length > 0 ? (
          data.map((item, index) => (
            <div key={index} className="widget-row">
              <span className="ip-mono">{item.label}</span>
              <span className={valueClass}>{valueFormatter(item.value)}</span>
            </div>
          ))
        ) : (
          <div className="widget-row">
            <span>No data</span>
          </div>
        )}
      </div>
    </div>
  );
}
