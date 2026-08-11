import { useState, useEffect } from "react";
import MainLayout from "../layouts/MainLayout";
import { getAuditLogs, getAuditStats } from "../services/auditService";

export default function AuditLogsPage() {
  const [logs, setLogs] = useState([]);
  const [total, setTotal] = useState(0);
  const [stats, setStats] = useState(null);
  const [skip, setSkip] = useState(0);
  const limit = 20;
  const [actionFilter, setActionFilter] = useState("all");
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchLogs();
    fetchStats();
  }, [skip, actionFilter]);

  const fetchLogs = async () => {
    setLoading(true);
    try {
      const filter = actionFilter === "all" ? null : actionFilter;
      const res = await getAuditLogs(skip, limit, filter);
      setLogs(res.logs || []);
      setTotal(res.total || 0);
    } catch {
      setLogs([]);
    } finally {
      setLoading(false);
    }
  };

  const fetchStats = async () => {
    try {
      const res = await getAuditStats();
      setStats(res);
    } catch {
      // ignore
    }
  };

  const handleNext = () => {
    if (skip + limit < total) setSkip(skip + limit);
  };

  const handlePrev = () => {
    if (skip >= limit) setSkip(skip - limit);
  };

  return (
    <MainLayout>
      <div className="max-w-7xl mx-auto px-6 py-8 space-y-8">
        {/* Header & Security Audit Metric Summary */}
        <div className="bg-base-surface border border-base-border rounded-xl p-6 shadow-sm flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-2 mb-1">
              <span className="w-3 h-3 rounded-full bg-signal inline-block animate-pulse" />
              <h1 className="text-xl font-bold font-mono tracking-tight text-ink">
                Enterprise Security Audit Logs
              </h1>
            </div>
            <p className="text-xs font-mono text-ink-muted">
              Real-time User Activity Logging • Security Hardening Headers Active • Compliance Trail
            </p>
          </div>

          <div className="flex items-center gap-3">
            <div className="px-3 py-1.5 bg-base-bg border border-base-border rounded font-mono text-xs text-ink-muted">
              Total Log Entries: <strong className="text-signal">{total}</strong>
            </div>
          </div>
        </div>

        {/* Action Filter Toolbar */}
        <div className="flex flex-wrap items-center justify-between gap-2 border-b border-base-border pb-3 font-mono text-xs">
          <div className="flex flex-wrap gap-1.5">
            {["all", "LOGIN", "REGISTER", "ANALYZE_DOMAIN", "PORT_SCAN", "GENERATE_REPORT", "VIEW_AUDIT_LOGS"].map((act) => (
              <button
                key={act}
                onClick={() => {
                  setActionFilter(act);
                  setSkip(0);
                }}
                className={`px-3 py-1 rounded transition-colors ${
                  actionFilter === act
                    ? "bg-signal text-base-bg font-bold"
                    : "text-ink-muted hover:text-ink border border-base-border bg-base-surface"
                }`}
              >
                {act}
              </button>
            ))}
          </div>

          <div className="text-ink-muted">
            Page {Math.floor(skip / limit) + 1} of {Math.max(1, Math.ceil(total / limit))}
          </div>
        </div>

        {/* Audit Log Table */}
        <div className="bg-base-surface border border-base-border rounded-xl p-6 shadow-sm space-y-4 font-mono text-xs">
          {loading ? (
            <div className="py-12 text-center text-ink-muted">
              <div className="inline-block animate-spin h-6 w-6 border-2 border-signal border-t-transparent rounded-full mb-3" />
              <p>Fetching security audit trail logs...</p>
            </div>
          ) : logs.length > 0 ? (
            <div className="overflow-x-auto">
              <table className="w-full text-left text-ink-muted">
                <thead className="bg-base-bg border-b border-base-border text-ink text-[11px] uppercase">
                  <tr>
                    <th className="p-3">Timestamp</th>
                    <th className="p-3">Action</th>
                    <th className="p-3">User ID</th>
                    <th className="p-3">Target Details</th>
                    <th className="p-3">IP Address</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-base-border">
                  {logs.map((log) => (
                    <tr key={log.id} className="hover:bg-base-bg/50 transition-colors">
                      <td className="p-3 text-[11px]">
                        {log.timestamp ? new Date(log.timestamp).toLocaleString() : "N/A"}
                      </td>
                      <td className="p-3">
                        <span
                          className={`px-2.5 py-0.5 rounded text-[10px] uppercase font-bold ${
                            log.action.includes("PORT_SCAN") || log.action.includes("REGISTER")
                              ? "bg-amber-500/20 text-amber-400"
                              : "bg-signal/20 text-signal"
                          }`}
                        >
                          {log.action}
                        </span>
                      </td>
                      <td className="p-3 text-ink font-semibold">{log.user_id?.slice(0, 8)}...</td>
                      <td className="p-3 text-ink-muted">{log.target || "N/A"}</td>
                      <td className="p-3 text-[11px]">{log.ip_address || "127.0.0.1"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <div className="p-8 text-center text-ink-muted bg-base-bg rounded border border-base-border">
              No audit log records found for this filter.
            </div>
          )}

          {/* Pagination Toolbar */}
          <div className="flex justify-between items-center border-t border-base-border pt-4 text-xs">
            <button
              onClick={handlePrev}
              disabled={skip === 0}
              className="px-4 py-1.5 border border-base-border text-ink-muted hover:text-ink rounded disabled:opacity-40"
            >
              ← Previous
            </button>
            <span className="text-ink-muted">
              Showing {logs.length > 0 ? skip + 1 : 0} - {Math.min(skip + limit, total)} of {total} records
            </span>
            <button
              onClick={handleNext}
              disabled={skip + limit >= total}
              className="px-4 py-1.5 border border-base-border text-ink-muted hover:text-ink rounded disabled:opacity-40"
            >
              Next →
            </button>
          </div>
        </div>
      </div>
    </MainLayout>
  );
}
