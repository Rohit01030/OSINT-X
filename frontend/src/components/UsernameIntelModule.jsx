import { useState } from "react";
import { analyzeUsername } from "../services/api";

export default function UsernameIntelModule({ investigationId, onScanComplete }) {
  const [targetUsername, setTargetUsername] = useState("");
  const [scanning, setScanning] = useState(false);
  const [error, setError] = useState("");
  const [scanResult, setScanResult] = useState(null);
  const [filterFoundOnly, setFilterFoundOnly] = useState(false);

  const handleRunScan = async (e) => {
    e.preventDefault();
    if (!targetUsername.trim()) {
      setError("Please enter a username to investigate (e.g. torvalds).");
      return;
    }

    setError("");
    setScanning(true);
    setScanResult(null);

    try {
      const data = await analyzeUsername(investigationId, targetUsername.trim());
      setScanResult(data);
      if (onScanComplete) onScanComplete(data);
    } catch (err) {
      console.error("Username scan error:", err);
      setError(err.response?.data?.detail || "Username search failed. Please try again.");
    } finally {
      setScanning(false);
    }
  };

  const results = scanResult?.results || [];
  const displayedResults = filterFoundOnly ? results.filter((r) => r.exists) : results;

  return (
    <div className="bg-base-surface border border-base-border rounded-lg p-6 space-y-6">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-base-border pb-6">
        <div>
          <div className="flex items-center gap-2">
            <span className="text-signal text-xl">👤</span>
            <h3 className="font-mono text-lg font-bold text-ink">Username Footprinting Engine</h3>
          </div>
          <p className="text-xs font-mono text-ink-muted mt-1">
            Enumerate public user accounts and social profiles across developer and social media platforms
          </p>
        </div>
      </div>

      {/* Input */}
      <form onSubmit={handleRunScan} className="flex flex-col sm:flex-row gap-3">
        <input
          type="text"
          placeholder="Target username (e.g. johndoe, secops_lead)..."
          value={targetUsername}
          onChange={(e) => setTargetUsername(e.target.value)}
          disabled={scanning}
          className="flex-1 px-4 py-2.5 bg-base-bg border border-base-border rounded-md text-sm font-mono text-ink placeholder:text-ink-muted/50 focus:border-signal"
        />
        <button
          type="submit"
          disabled={scanning}
          className="px-6 py-2.5 bg-signal text-base-bg font-mono text-xs font-bold rounded-md hover:bg-signal-dim transition-colors disabled:opacity-50 flex items-center justify-center gap-2"
        >
          {scanning ? (
            <>
              <div className="animate-spin h-4 w-4 border-2 border-base-bg border-t-transparent rounded-full" />
              <span>Scanning Platforms...</span>
            </>
          ) : (
            <span>Search Username</span>
          )}
        </button>
      </form>

      {error && (
        <div className="p-4 bg-risk-critical/10 border border-risk-critical/30 text-risk-critical text-xs font-mono rounded-md">
          {error}
        </div>
      )}

      {/* Results */}
      {scanResult && (
        <div className="space-y-6 pt-2">
          {/* Summary metrics & filter bar */}
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 bg-base-bg border border-base-border rounded-md p-4 font-mono text-xs">
            <div className="flex items-center gap-6">
              <div>
                <span className="text-ink-muted block text-[10px] uppercase">Platforms Queried</span>
                <span className="text-ink font-bold text-sm">{scanResult.total_checked || 0}</span>
              </div>
              <div>
                <span className="text-ink-muted block text-[10px] uppercase">Profiles Discovered</span>
                <span className="text-signal font-bold text-sm">{scanResult.total_found || 0}</span>
              </div>
            </div>

            <div className="flex items-center gap-2">
              <label className="flex items-center gap-2 text-ink-muted cursor-pointer">
                <input
                  type="checkbox"
                  checked={filterFoundOnly}
                  onChange={(e) => setFilterFoundOnly(e.target.checked)}
                  className="rounded border-base-border text-signal focus:ring-signal"
                />
                <span>Show found profiles only</span>
              </label>
            </div>
          </div>

          {/* Platforms Grid */}
          <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-3">
            {displayedResults.map((item, idx) => (
              <div
                key={idx}
                className={`p-4 rounded-lg border font-mono text-xs transition-colors flex flex-col justify-between ${
                  item.exists
                    ? "bg-base-bg border-signal/40 hover:border-signal"
                    : "bg-base-bg/50 border-base-border opacity-70"
                }`}
              >
                <div>
                  <div className="flex items-center justify-between mb-2">
                    <span className="font-bold text-ink text-sm capitalize">{item.platform}</span>
                    <span
                      className={`px-2 py-0.5 rounded text-[10px] uppercase font-bold ${
                        item.exists
                          ? "bg-emerald-500/20 text-emerald-400 border border-emerald-500/30"
                          : "bg-base-border text-ink-muted"
                      }`}
                    >
                      {item.exists ? "Active Account" : "Not Found"}
                    </span>
                  </div>
                  <p className="text-[11px] text-ink-muted break-all line-clamp-1">{item.url}</p>
                </div>

                {item.exists && (
                  <div className="mt-3 pt-2 border-t border-base-border/50 flex justify-end">
                    <a
                      href={item.url}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-signal hover:underline text-[11px] font-bold flex items-center gap-1"
                    >
                      View Profile ↗
                    </a>
                  </div>
                )}
              </div>
            ))}
          </div>

          {displayedResults.length === 0 && (
            <div className="p-8 text-center bg-base-bg border border-base-border rounded-md text-ink-muted font-mono text-xs">
              No profiles matched the current filter.
            </div>
          )}
        </div>
      )}
    </div>
  );
}
