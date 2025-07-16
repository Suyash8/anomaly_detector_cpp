import React from "react";

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

export default function Header({ activeView, setActiveView }) {
  return (
    <header className="header">
      <div className="container header-container">
        <div className="logo">
          <ShieldIcon />
          <h1>Anomaly Detector</h1>
        </div>
        <nav>
          <button
            className={`nav-button ${
              activeView === "performance" ? "active" : ""
            }`}
            onClick={() => setActiveView("performance")}
          >
            Performance
          </button>
          <button
            className={`nav-button ${
              activeView === "operations" ? "active" : ""
            }`}
            onClick={() => setActiveView("operations")}
          >
            Operations
          </button>
        </nav>
      </div>
    </header>
  );
}
