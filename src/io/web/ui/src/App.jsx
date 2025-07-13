// src/App.js
import React, { useState } from "react";
import Header from "./components/Header";
import PerformanceView from "./views/PerformanceView";
import OperationsView from "./views/OperationsView";
import useApiData from "./hooks/useApiData";
import "./style.css";

export default function App() {
  const [activeView, setActiveView] = useState("performance");

  const { performanceData, operationsData, isLoading, error } = useApiData();

  return (
    <>
      <Header activeView={activeView} setActiveView={setActiveView} />
      <main className="container">
        {isLoading && !performanceData && <div>Loading initial data...</div>}
        {error && <div>Error fetching data: {error.message}</div>}

        <div className={activeView === "performance" ? "view active" : "view"}>
          {performanceData && <PerformanceView data={performanceData} />}
        </div>

        <div className={activeView === "operations" ? "view active" : "view"}>
          {operationsData && <OperationsView data={operationsData} />}
        </div>
      </main>
    </>
  );
}
