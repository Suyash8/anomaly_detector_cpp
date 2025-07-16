export const createInitialLineChartData = (datasets = []) => ({
  labels: [],
  datasets: datasets.map((ds) => ({ ...ds, data: [] })),
});
