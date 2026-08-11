import { useState } from "react";
import { generateReport } from "../services/reportService";

export default function ReportGeneratorModal({ isOpen, onClose, investigationId, caseTitle }) {
  const [format, setFormat] = useState("json");
  const [loading, setLoading] = useState(false);
  const [successMsg, setSuccessMsg] = useState(null);
  const [error, setError] = useState(null);

  if (!isOpen) return null;

  const handleGenerate = async () => {
    setLoading(true);
    setError(null);
    setSuccessMsg(null);

    try {
      if (format === "csv") {
        // Blob file download for CSV
        const blobData = await generateReport(investigationId, "csv");
        const url = window.URL.createObjectURL(new Blob([blobData]));
        const link = document.createElement("a");
        link.href = url;
        link.setAttribute("download", `OSINT-X_Report_${caseTitle ? caseTitle.replace(/\s+/g, "_") : "Case"}.csv`);
        document.body.appendChild(link);
        link.click();
        link.remove();
        setSuccessMsg("CSV report generated & downloaded successfully!");
      } else if (format === "pdf") {
        // PDF HTML Executive Briefing popup window
        const resData = await generateReport(investigationId, "pdf");
        const printWin = window.open("", "_blank");
        if (printWin) {
          printWin.document.write(resData);
          printWin.document.close();
        }
        setSuccessMsg("Executive PDF/HTML Intelligence Briefing opened in new browser window!");
      } else {
        // JSON Export file download
        const resData = await generateReport(investigationId, "json");
        const jsonStr = JSON.stringify(resData.report_data || resData, null, 2);
        const blob = new Blob([jsonStr], { type: "application/json" });
        const url = window.URL.createObjectURL(blob);
        const link = document.createElement("a");
        link.href = url;
        link.setAttribute("download", `OSINT-X_Report_${caseTitle ? caseTitle.replace(/\s+/g, "_") : "Case"}.json`);
        document.body.appendChild(link);
        link.click();
        link.remove();
        setSuccessMsg("JSON intelligence report downloaded successfully!");
      }
    } catch (err) {
      setError(err.response?.data?.detail || "Failed to generate report.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm p-4">
      <div className="bg-base-surface border border-base-border rounded-xl p-6 max-w-md w-full shadow-2xl font-mono space-y-5">
        <div className="flex justify-between items-center border-b border-base-border pb-3">
          <div className="flex items-center gap-2">
            <span className="w-2.5 h-2.5 rounded-full bg-signal inline-block" />
            <h3 className="text-sm font-bold text-ink">Generate Intelligence Report</h3>
          </div>
          <button onClick={onClose} className="text-ink-muted hover:text-ink text-xs font-bold">
            ✕
          </button>
        </div>

        <div>
          <div className="text-xs text-ink-muted mb-1">Target Case:</div>
          <div className="p-2.5 bg-base-bg border border-base-border rounded text-ink font-semibold text-xs">
            {caseTitle || "Investigation Case"}
          </div>
        </div>

        <div>
          <label className="text-xs text-ink-muted block mb-2">Select Export Format:</label>
          <div className="grid grid-cols-3 gap-2">
            <button
              onClick={() => setFormat("json")}
              className={`p-3 rounded border text-center transition-colors text-xs ${
                format === "json"
                  ? "bg-signal text-base-bg font-bold border-signal"
                  : "bg-base-bg text-ink-muted border-base-border hover:border-ink"
              }`}
            >
              JSON
              <span className="block text-[10px] opacity-80 mt-0.5">Machine Payload</span>
            </button>
            <button
              onClick={() => setFormat("csv")}
              className={`p-3 rounded border text-center transition-colors text-xs ${
                format === "csv"
                  ? "bg-signal text-base-bg font-bold border-signal"
                  : "bg-base-bg text-ink-muted border-base-border hover:border-ink"
              }`}
            >
              CSV
              <span className="block text-[10px] opacity-80 mt-0.5">Spreadsheet Data</span>
            </button>
            <button
              onClick={() => setFormat("pdf")}
              className={`p-3 rounded border text-center transition-colors text-xs ${
                format === "pdf"
                  ? "bg-signal text-base-bg font-bold border-signal"
                  : "bg-base-bg text-ink-muted border-base-border hover:border-ink"
              }`}
            >
              PDF / HTML
              <span className="block text-[10px] opacity-80 mt-0.5">Executive Briefing</span>
            </button>
          </div>
        </div>

        {error && (
          <div className="p-3 bg-risk-critical/10 border border-risk-critical/30 text-risk-critical rounded text-xs">
            {error}
          </div>
        )}

        {successMsg && (
          <div className="p-3 bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 rounded text-xs">
            {successMsg}
          </div>
        )}

        <div className="flex justify-end gap-3 border-t border-base-border pt-4">
          <button
            onClick={onClose}
            className="px-4 py-2 border border-base-border text-ink-muted hover:text-ink text-xs rounded"
          >
            Close
          </button>
          <button
            onClick={handleGenerate}
            disabled={loading}
            className="px-4 py-2 bg-signal text-base-bg font-bold text-xs rounded hover:bg-signal-dim transition-colors disabled:opacity-50"
          >
            {loading ? "Generating..." : "Generate & Download"}
          </button>
        </div>
      </div>
    </div>
  );
}
