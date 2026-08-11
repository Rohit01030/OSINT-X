import { useState, useEffect } from "react";
import MainLayout from "../layouts/MainLayout";
import { getAiHealth, naturalLanguageSearch, correlateIocs } from "../services/aiService";
import { getInvestigations } from "../services/api";

export default function AiAssistantPage() {
  const [health, setHealth] = useState(null);
  const [loadingHealth, setLoadingHealth] = useState(true);
  const [nlQuery, setNlQuery] = useState("");
  const [searchResults, setSearchResults] = useState(null);
  const [searching, setSearching] = useState(false);
  const [searchError, setSearchError] = useState(null);

  const [investigations, setInvestigations] = useState([]);
  const [selectedCaseId, setSelectedCaseId] = useState("");
  const [correlationData, setCorrelationData] = useState(null);
  const [correlating, setCorrelating] = useState(false);

  useEffect(() => {
    fetchHealth();
    fetchCaseList();
  }, []);

  const fetchHealth = async () => {
    try {
      const res = await getAiHealth();
      setHealth(res);
    } catch {
      setHealth({ status: "fallback_mode", available: false, ollama_model: "llama3:8b (offline fallback)" });
    } finally {
      setLoadingHealth(false);
    }
  };

  const fetchCaseList = async () => {
    try {
      const res = await getInvestigations();
      setInvestigations(res);
      if (res.length > 0) setSelectedCaseId(res[0].id);
    } catch {
      // ignore
    }
  };

  const handleNlSearch = async (e) => {
    e.preventDefault();
    if (!nlQuery.trim()) return;
    setSearching(true);
    setSearchError(null);
    try {
      const res = await naturalLanguageSearch(nlQuery);
      setSearchResults(res);
    } catch (err) {
      setSearchError(err.response?.data?.detail || "Search failed.");
    } finally {
      setSearching(false);
    }
  };

  const handleCorrelate = async () => {
    if (!selectedCaseId) return;
    setCorrelating(true);
    try {
      const res = await correlateIocs(selectedCaseId);
      setCorrelationData(res);
    } catch {
      setCorrelationData({ correlations: [] });
    } finally {
      setCorrelating(false);
    }
  };

  return (
    <MainLayout>
      <div className="max-w-7xl mx-auto px-6 py-8 space-y-8">
        {/* Header Banner */}
        <div className="bg-base-surface border border-base-border rounded-xl p-6 shadow-sm">
          <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
            <div>
              <div className="flex items-center gap-2 mb-1">
                <span className="w-3 h-3 rounded-full bg-signal inline-block animate-pulse" />
                <h1 className="text-xl font-bold font-mono tracking-tight text-ink">
                  Local AI Investigation Assistant
                </h1>
              </div>
              <p className="text-xs font-mono text-ink-muted">
                Ollama REST API integration • 100% Local Inference • Zero API Keys Required • Rule-Based Core Safety
              </p>
            </div>

            <div className="flex items-center gap-3">
              {loadingHealth ? (
                <span className="text-xs font-mono text-ink-muted">Checking Ollama engine status...</span>
              ) : (
                <div className="px-3 py-1.5 bg-base-bg border border-base-border rounded text-xs font-mono flex items-center gap-2">
                  <span
                    className={`w-2 h-2 rounded-full ${
                      health?.available ? "bg-emerald-500" : "bg-amber-500"
                    }`}
                  />
                  <span>
                    Status: <strong className="text-ink">{health?.available ? "Ollama Connected" : "Simulation Fallback"}</strong>
                  </span>
                </div>
              )}
            </div>
          </div>
        </div>

        {/* Grid Container */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
          {/* Section 1: Natural Language Search */}
          <div className="bg-base-surface border border-base-border rounded-xl p-6 shadow-sm flex flex-col justify-between">
            <div>
              <h2 className="text-sm font-bold font-mono text-ink mb-1 flex items-center gap-2">
                <span className="text-signal">#</span> Natural Language Case Query
              </h2>
              <p className="text-xs font-mono text-ink-muted mb-4">
                Ask in natural language to search and filter active or archived investigation cases.
              </p>

              <form onSubmit={handleNlSearch} className="flex gap-2 mb-4">
                <input
                  type="text"
                  value={nlQuery}
                  onChange={(e) => setNlQuery(e.target.value)}
                  placeholder="e.g. active phishing cases with domain findings..."
                  className="flex-1 px-3 py-2 bg-base-bg border border-base-border rounded text-xs font-mono text-ink focus:outline-none focus:border-signal"
                />
                <button
                  type="submit"
                  disabled={searching}
                  className="px-4 py-2 bg-signal text-base-bg font-mono font-medium text-xs rounded hover:bg-signal-dim transition-colors disabled:opacity-50"
                >
                  {searching ? "Searching..." : "Execute Query"}
                </button>
              </form>

              {searchError && (
                <div className="p-3 bg-risk-critical/10 border border-risk-critical/30 text-risk-critical rounded text-xs font-mono mb-3">
                  {searchError}
                </div>
              )}

              {searchResults && (
                <div className="space-y-3 font-mono text-xs">
                  <div className="p-2.5 bg-base-bg border border-base-border rounded flex justify-between text-ink-muted">
                    <span>Query: <strong className="text-ink">"{searchResults.raw_query}"</strong></span>
                    <span>Matches: <strong className="text-signal">{searchResults.total_matches}</strong></span>
                  </div>

                  {searchResults.matches.length > 0 ? (
                    <div className="space-y-2 max-h-60 overflow-y-auto pr-1">
                      {searchResults.matches.map((item) => (
                        <div key={item.id} className="p-3 bg-base-bg border border-base-border rounded flex justify-between items-center">
                          <div>
                            <div className="font-bold text-ink">{item.title}</div>
                            <div className="text-[11px] text-ink-muted">Status: {item.status}</div>
                          </div>
                          <span className="px-2 py-0.5 bg-base-surface border border-base-border rounded text-[10px] text-signal font-mono">
                            ID: {item.id.slice(0, 8)}...
                          </span>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <div className="p-4 text-center text-ink-muted text-xs bg-base-bg rounded border border-base-border">
                      No matching cases found for this query.
                    </div>
                  )}
                </div>
              )}
            </div>
          </div>

          {/* Section 2: Cross-Investigation IOC Correlation Explorer */}
          <div className="bg-base-surface border border-base-border rounded-xl p-6 shadow-sm flex flex-col justify-between">
            <div>
              <h2 className="text-sm font-bold font-mono text-ink mb-1 flex items-center gap-2">
                <span className="text-signal">#</span> Cross-Case IOC Correlation
              </h2>
              <p className="text-xs font-mono text-ink-muted mb-4">
                Analyze cross-case overlapping IPs, domains, hashes, and tags across all investigations.
              </p>

              <div className="flex gap-2 mb-4">
                <select
                  value={selectedCaseId}
                  onChange={(e) => setSelectedCaseId(e.target.value)}
                  className="flex-1 px-3 py-2 bg-base-bg border border-base-border rounded text-xs font-mono text-ink focus:outline-none focus:border-signal"
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
                  onClick={handleCorrelate}
                  disabled={correlating || !selectedCaseId}
                  className="px-4 py-2 bg-signal text-base-bg font-mono font-medium text-xs rounded hover:bg-signal-dim transition-colors disabled:opacity-50"
                >
                  {correlating ? "Analyzing..." : "Correlate Case"}
                </button>
              </div>

              {correlationData && (
                <div className="space-y-3 font-mono text-xs">
                  <div className="p-2.5 bg-base-bg border border-base-border rounded flex justify-between text-ink-muted">
                    <span>Correlations Detected</span>
                    <span className="text-signal font-bold">{correlationData.total_correlations_found}</span>
                  </div>

                  {correlationData.correlations.length > 0 ? (
                    <div className="space-y-2 max-h-60 overflow-y-auto pr-1">
                      {correlationData.correlations.map((corr, idx) => (
                        <div key={idx} className="p-3 bg-base-bg border border-base-border rounded">
                          <div className="flex justify-between items-center mb-1">
                            <span className="font-bold text-ink">{corr.target_investigation_title}</span>
                            <span className="px-2 py-0.5 bg-signal/20 text-signal rounded text-[10px] font-bold">
                              {corr.confidence} CONFIDENCE
                            </span>
                          </div>
                          <div className="text-[11px] text-ink-muted">
                            Type: {corr.correlation_type} | Shared: {corr.matched_values.join(", ")}
                          </div>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <div className="p-4 text-center text-ink-muted text-xs bg-base-bg rounded border border-base-border">
                      No cross-investigation IOC or tag correlations detected for this case.
                    </div>
                  )}
                </div>
              )}
            </div>
          </div>
        </div>
      </div>
    </MainLayout>
  );
}
