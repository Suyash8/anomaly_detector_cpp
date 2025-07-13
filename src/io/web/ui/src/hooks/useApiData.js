import { useState, useEffect } from "react";

const API_POLL_INTERVAL = 2000; // 2 seconds

export default function useApiData() {
  const [performanceData, setPerformanceData] = useState(null);
  const [operationsData, setOperationsData] = useState(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    const fetchData = async () => {
      try {
        const [perfRes, alertsRes, stateRes] = await Promise.all([
          fetch("/api/v1/metrics/performance"),
          fetch("/api/v1/operations/alerts"),
          fetch("/api/v1/operations/state"),
        ]);

        if (!perfRes.ok || !alertsRes.ok || !stateRes.ok) {
          throw new Error("Network response was not ok");
        }

        const perfData = await perfRes.json();
        const alertsData = await alertsRes.json();
        const stateData = await stateRes.json();

        setPerformanceData(perfData);
        setOperationsData({ alerts: alertsData, state: stateData });
      } catch (e) {
        setError(e);
        console.error("Failed to fetch API data:", e);
      } finally {
        setIsLoading(false);
      }
    };

    fetchData(); // Initial fetch
    const intervalId = setInterval(fetchData, API_POLL_INTERVAL);

    return () => clearInterval(intervalId); // Cleanup on component unmount
  }, []);

  return { performanceData, operationsData, isLoading, error };
}
