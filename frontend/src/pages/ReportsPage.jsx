import { useState, useEffect } from "react";
import MainLayout from "../layouts/MainLayout";
import ReportGeneratorModal from "../components/ReportGeneratorModal";
import { getInvestigations } from "../services/api";
import { listInvestigationReports } from "../services/reportService";

export default function ReportsPage() {
  const [investigations, setInvestigations] = useState([]);
  const [selectedCaseId, setSelectedCaseId] = useState("");
  const [reports, setReports] = useState([]);
  const [loading, setLoading] = useState(false);
  const [modalOpen, setModalOpen] = useState(false);

  useEffect(() => {
    fetchCaseList();
  }, []);

  useEffect(() => {
    if (selectedCaseId) {
      fetchReportHistory(selectedCaseId);
    }
  }, [selectedCaseId]);

  const fetchCaseList = async () => {
    try {
      const res = await getInvestigations();
      setInvestigations(res);
      if (res.length > 0) setSelectedCaseId(res[0].id);
    } catch {
      // ignore
    }
  };

  const fetchReportHistory = async (caseId) => {
    setLoading(true);
    try {
      const res = await listInvestigationReports(caseId);
      setReports(res);
    } catch {
      setReports([]);
    } finally {
      setLoading(false);
    }
  };

  const selectedCaseObj = investigations.find((i) => i.id === selectedCaseId);

  return (
    <MainLayout>
      <div className="max-w-7xl mx-auto px-6 py-8 space-y-8">
        {/* Header & Export Action Banner */}
        <div className="bg-base-surface border border-base-border rounded-xl p-6 shadow-sm flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-2 mb-1">
              <span className="w-3 h-3 rounded-full bg-signal inline-block animate-pulse" />
              <h1 className="text-xl font-bold font-mono tracking-tight text-ink">
                Intelligence Report Generator
              </h1>
            </div>
            <p className="text-xs font-mono text-ink-muted">
              Export Investigation Cases into Structured JSON, CSV Data, and Executive PDF Briefings
            </p>
          </div>

          <div className="flex items-center gap-3">
            <select
              value={selectedCaseId}
              onChange={(e) => setSelectedCaseId(e.target.value)}
              className="px-3 py-2 bg-base-bg border border-base-border rounded text-xs font-mono text-ink focus:outline-none focus:border-signal min-w-[200px]"
            >
              {investigations.length > 0 ? (
                investigations.map((inv) => (
                  <option key={inv.id} value={inv.id}>
                    {inv.title} ({inv.status})
                  </option>
                ))
              ) : (
                <option value="">No cases available</option>
              )}
            </select>

            <button
              onClick={() => setModalOpen(true)}
              disabled={!selectedCaseId}
              className="px-4 py-2 bg-signal text-base-bg font-mono font-bold text-xs rounded hover:bg-signal-dim transition-colors disabled:opacity-50 flex items-center gap-1.5"
            >
              Export Report
            </button>
          </div>
        </div>

        {/* Generated Reports History Log Table */}
        <div className="bg-base-surface border border-base-border rounded-xl p-6 shadow-sm space-y-4">
          <div className="flex justify-between items-center border-b border-base-border pb-3">
            <h2 className="text-sm font-bold font-mono text-ink flex items-center gap-2">
              <span className="text-signal">#</span> Report Export Audit History
            </h2>
            <span className="text-xs font-mono text-ink-muted">
              Total Logged Exports: <strong className="text-ink">{reports.length}</strong>
            </span>
          </div>

          {loading ? (
            <div className="py-8 text-center text-xs font-mono text-ink-muted">
              <div className="inline-block animate-spin h-5 w-5 border-2 border-signal border-t-transparent rounded-full mb-2" />
              <p>Loading report history...</p>
            </div>
          ) : reports.length > 0 ? (
            <div className="overflow-x-auto">
              <table className="w-full text-left font-mono text-xs text-ink-muted">
                <thead className="bg-base-bg border-b border-base-border text-ink text-[11px] uppercase">
                  <tr>
                    <th className="p-3">Report ID</th>
                    <th className="p-3">Format</th>
                    <th className="p-3">Summary</th>
                    <th className="p-3">Generated At</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-base-border">
                  {reports.map((rep) => (
                    <tr key={rep.id} className="hover:bg-base-bg/50 transition-colors">
                      <td className="p-3 font-bold text-ink">{rep.id.slice(0, 8)}...</td>
                      <td className="p-3">
                        <span className="px-2 py-0.5 bg-signal/20 text-signal rounded text-[10px] uppercase font-bold">
                          {rep.report_type}
                        </span>
                      </td>
                      <td className="p-3">{rep.content_summary || "Investigation Report Export"}</td>
                      <td className="p-3">{rep.created_at ? new Date(rep.created_at).toLocaleString() : "N/A"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <div className="p-8 text-center text-xs font-mono text-ink-muted bg-base-bg rounded border border-base-border">
              No report export logs found for this investigation case. Click "Export Report" to generate one.
            </div>
          )}
        </div>
      </div>

      <ReportGeneratorModal
        isOpen={modalOpen}
        onClose={() => setModalOpen(false)}
        investigationId={selectedCaseId}
        caseTitle={selectedCaseObj?.title}
      />
    </MainLayout>
  );
}
