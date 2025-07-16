import React, { useState, useEffect } from "react";
import { Line, Bar } from "react-chartjs-2";
import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  LogarithmicScale,
  PointElement,
  LineElement,
  BarElement,
  Title,
  Tooltip,
  Legend,
  Filler,
} from "chart.js";

ChartJS.register(
  CategoryScale,
  LinearScale,
  LogarithmicScale,
  PointElement,
  LineElement,
  BarElement,
  Title,
  Tooltip,
  Legend,
  Filler
);

export default function ChartCard({
  title,
  type,
  options,
  data,
  isHistorical = false,
}) {
  const ChartComponent = type === "line" ? Line : Bar;

  const [chartData, setChartData] = useState({ labels: [], datasets: [] });

  useEffect(() => {
    if (isHistorical) {
      const MAX_HISTORY = 30;
      const nowLabel = new Date().toLocaleTimeString();

      setChartData((prevData) => {
        const newLabels = [...(prevData.labels || []), nowLabel].slice(
          -MAX_HISTORY
        );

        const newDatasets = data.datasets.map((newDataset, i) => {
          const oldData = prevData.datasets[i]?.data || [];
          return {
            ...newDataset,
            data: [...oldData, newDataset.data[0]].slice(-MAX_HISTORY),
          };
        });

        return { labels: newLabels, datasets: newDatasets };
      });
    } else {
      setChartData(data);
    }
  }, [data, isHistorical]);

  return (
    <div className="chart-card">
      {title && (
        <div className="card-header">
          <h3>{title}</h3>
        </div>
      )}
      <div style={{ position: "relative", height: "300px" }}>
        <ChartComponent data={chartData} options={options} />
      </div>
    </div>
  );
}
