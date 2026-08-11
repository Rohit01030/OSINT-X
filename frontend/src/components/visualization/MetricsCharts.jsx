import {
  Chart as ChartJS,
  ArcElement,
  Tooltip,
  Legend,
  CategoryScale,
  LinearScale,
  BarElement,
  Title
} from "chart.js";
import { Doughnut, Bar } from "react-chartjs-2";

ChartJS.register(
  ArcElement,
  Tooltip,
  Legend,
  CategoryScale,
  LinearScale,
  BarElement,
  Title
);

export default function MetricsCharts({ data }) {
  if (!data) {
    return (
      <div className="p-8 text-center text-xs font-mono text-ink-muted bg-base-bg rounded border border-base-border">
        No chart metrics available.
      </div>
    );
  }

  const moduleData = {
    labels: Object.keys(data.module_distribution).map((m) => m.toUpperCase()),
    datasets: [
      {
        label: "Findings Count",
        data: Object.values(data.module_distribution),
        backgroundColor: [
          "#10B981", // Domain (Emerald)
          "#3B82F6", // IP (Blue)
          "#8B5CF6", // Email (Purple)
          "#EC4899", // Username (Pink)
          "#F59E0B", // File (Amber)
          "#EF4444"  // Threat Intel (Red)
        ],
        borderWidth: 1,
        borderColor: "#1F2937"
      }
    ]
  };

  const severityData = {
    labels: Object.keys(data.severity_breakdown),
    datasets: [
      {
        label: "Severity Rating Breakdown",
        data: Object.values(data.severity_breakdown),
        backgroundColor: [
          "#EF4444", // Critical (Red)
          "#F59E0B", // High (Amber)
          "#3B82F6", // Medium (Blue)
          "#10B981"  // Low (Emerald)
        ],
        borderRadius: 4
      }
    ]
  };

  const chartOptions = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: {
        position: "bottom",
        labels: {
          color: "#9CA3AF",
          font: { family: "monospace", size: 11 }
        }
      }
    },
    scales: {
      x: {
        ticks: { color: "#9CA3AF", font: { family: "monospace" } },
        grid: { color: "#374151" }
      },
      y: {
        ticks: { color: "#9CA3AF", font: { family: "monospace" } },
        grid: { color: "#374151" }
      }
    }
  };

  return (
    <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
      {/* Chart 1: Module Finding Distribution */}
      <div className="bg-base-surface border border-base-border rounded-xl p-5 shadow-sm">
        <h3 className="text-xs font-bold font-mono text-ink mb-4 flex items-center justify-between border-b border-base-border pb-2">
          <span>Module Finding Distribution</span>
          <span className="text-signal">{data.total_findings} Total Findings</span>
        </h3>
        <div className="h-64 relative flex items-center justify-center">
          <Doughnut data={moduleData} options={{ ...chartOptions, scales: {} }} />
        </div>
      </div>

      {/* Chart 2: Severity Rating Breakdown */}
      <div className="bg-base-surface border border-base-border rounded-xl p-5 shadow-sm">
        <h3 className="text-xs font-bold font-mono text-ink mb-4 flex items-center justify-between border-b border-base-border pb-2">
          <span>Severity Breakdown Metrics</span>
          <span className="text-ink-muted">CRITICAL / HIGH / MED / LOW</span>
        </h3>
        <div className="h-64 relative">
          <Bar data={severityData} options={chartOptions} />
        </div>
      </div>
    </div>
  );
}
