import { useState, useEffect } from "react";

export function useRuntime(backendRuntimeSeconds) {
  const [runtimeSeconds, setRuntimeSeconds] = useState(0);

  useEffect(() => {
    if (backendRuntimeSeconds != null) {
      setRuntimeSeconds(Math.floor(backendRuntimeSeconds));
    }
  }, [backendRuntimeSeconds]);

  const hours = String(Math.floor(runtimeSeconds / 3600)).padStart(2, "0");
  const minutes = String(Math.floor((runtimeSeconds % 3600) / 60)).padStart(
    2,
    "0"
  );
  const seconds = String(Math.floor(runtimeSeconds % 60)).padStart(2, "0");
  const formattedRuntime = `${hours}:${minutes}:${seconds}`;

  return { formattedRuntime };
}
