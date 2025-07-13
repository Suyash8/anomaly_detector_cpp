import React from "react";
import { Line, Bar } from "react-chartjs-2";
import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  BarElement,
  Title,
  Tooltip,
  Legend,
  Filler,
} from "chart.js";

// Register all necessary components for Chart.js
ChartJS.register(
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  BarElement,
  Title,
  Tooltip,
  Legend,
  Filler
);

export default function ChartCard({ title, type, data, options, style }) {
  const ChartComponent = type === "line" ? Line : Bar;

  return (
    <div className="chart-card" style={style}>
      {title && (
        <div className="card-header">
          <h3>{title}</h3>
        </div>
      )}
      <div style={{ position: "relative", height: "300px" }}>
        <ChartComponent data={data} options={options} />
      </div>
    </div>
  );
}
