import { useState } from "react";
import { summarizeInvestigation, explainRiskScore, getMitreAttackMapping } from "../services/aiService";

export default function AiSummaryCard({ investigationId, title }) {
  const [activeTab, setActiveTab] = useState("summary");
  const [summaryData, setSummaryData] = useState(null);
  const [riskData, setRiskData] = useState(null);
  const [mitreData, setMitreData] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  const fetchSummary = async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await summarizeInvestigation(investigationId);
      setSummaryData(res);
    } catch (err) {
      setError(err.response?.data?.detail || "Failed to generate AI summary.");
    } finally {
      setLoading(false);
    }
  };

  const fetchRisk = async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await explainRiskScore(investigationId);
      setRiskData(res);
    } catch (err) {
      setError(err.response?.data?.detail || "Failed to calculate risk score.");
    } finally {
      setLoading(false);
    }
  };

  const fetchMitre = async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await getMitreAttackMapping(investigationId);
      setMitreData(res);
    } catch (err) {
      setError(err.response?.data?.detail || "Failed to fetch MITRE ATT&CK mapping.");
    } finally {
      setLoading(false);
    }
  };

  const handleTabChange = (tab) => {
    setActiveTab(tab);
    if (tab === "summary" && !summaryData) fetchSummary();
    if (tab === "risk" && !riskData) fetchRisk();
    if (tab === "mitre" && !mitreData) fetchMitre();
  };

  return (
    <div className="bg-base-surface border border-base-border rounded-lg p-5 shadow-sm">
      <div className="flex items-center justify-between border-b border-base-border pb-4 mb-4">
        <div className="flex items-center gap-2">
          <span className="w-2.5 h-2.5 rounded-full bg-signal animate-pulse" />
          <h3 className="font-mono text-sm font-semibold tracking-wide text-ink">
            Local AI Engine — <span className="text-signal">{title || "Investigation"}</span>
          </h3>
        </div>
        <div className="flex gap-2">
          <button
            onClick={() => handleTabChange("summary")}
            className={`px-3 py-1 text-xs font-mono rounded transition-colors ${
              activeTab === "summary" ? "bg-signal text-base-bg font-medium" : "text-ink-muted hover:text-ink border border-base-border"
            }`}
          >
            AI Summary
          </button>
          <button
            onClick={() => handleTabChange("risk")}
            className={`px-3 py-1 text-xs font-mono rounded transition-colors ${
              activeTab === "risk" ? "bg-signal text-base-bg font-medium" : "text-ink-muted hover:text-ink border border-base-border"
            }`}
          >
            Risk Breakdown
          </button>
          <button
            onClick={() => handleTabChange("mitre")}
            className={`px-3 py-1 text-xs font-mono rounded transition-colors ${
              activeTab === "mitre" ? "bg-signal text-base-bg font-medium" : "text-ink-muted hover:text-ink border border-base-border"
            }`}
          >
            MITRE ATT&CK
          </button>
        </div>
      </div>

      {loading && (
        <div className="py-8 text-center text-xs font-mono text-ink-muted">
          <div className="inline-block animate-spin h-5 w-5 border-2 border-signal border-t-transparent rounded-full mb-2" />
          <p>Processing intelligence with local Ollama engine...</p>
        </div>
      )}

      {error && (
        <div className="p-3 bg-risk-critical/10 border border-risk-critical/30 text-risk-critical rounded text-xs font-mono mb-3">
          {error}
        </div>
      )}

      {!loading && activeTab === "summary" && (
        <div>
          {summaryData ? (
            <div className="space-y-3 font-mono text-xs text-ink-muted">
              <div className="flex justify-between items-center bg-base-bg p-2.5 rounded border border-base-border">
                <span>Model: <strong className="text-ink">{summaryData.model_used}</strong></span>
                <span className="text-signal">{summaryData.offline_fallback ? "Fallback Simulation Mode" : "Ollama Active"}</span>
              </div>
              <div className="p-3 bg-base-bg rounded border border-base-border text-ink whitespace-pre-wrap leading-relaxed">
                {summaryData.summary}
              </div>
            </div>
          ) : (
            <div className="text-center py-6">
              <p className="text-xs font-mono text-ink-muted mb-3">Click below to generate local AI executive summary.</p>
              <button
                onClick={fetchSummary}
                className="px-4 py-1.5 bg-signal text-base-bg font-mono text-xs rounded hover:bg-signal-dim transition-colors"
              >
                Generate Executive Summary
              </button>
            </div>
          )}
        </div>
      )}

      {!loading && activeTab === "risk" && (
        <div>
          {riskData ? (
            <div className="space-y-4 font-mono text-xs">
              <div className="flex items-center justify-between p-3 bg-base-bg rounded border border-base-border">
                <div>
                  <span className="text-ink-muted block text-[11px]">Deterministic Risk Score</span>
                  <span className="text-lg font-bold text-ink">{riskData.risk_score} / 10.0</span>
                </div>
                <span
                  className={`px-3 py-1 rounded text-xs font-bold ${
                    riskData.risk_level === "CRITICAL"
                      ? "bg-risk-critical text-white"
                      : riskData.risk_level === "HIGH"
                      ? "bg-amber-500 text-black"
                      : "bg-signal/20 text-signal"
                  }`}
                >
                  {riskData.risk_level}
                </span>
              </div>

              <div>
                <h4 className="text-ink font-semibold mb-2">Identified Risk Factors:</h4>
                {riskData.risk_factors.length > 0 ? (
                  <ul className="space-y-1.5 list-disc list-inside text-ink-muted">
                    {riskData.risk_factors.map((factor, idx) => (
                      <li key={idx}>{factor}</li>
                    ))}
                  </ul>
                ) : (
                  <p className="text-ink-muted">No high-risk security factors detected.</p>
                )}
              </div>

              <div className="p-3 bg-base-bg rounded border border-base-border">
                <span className="text-signal font-semibold block mb-1">Local AI Explanation:</span>
                <p className="text-ink whitespace-pre-wrap leading-relaxed">{riskData.explanation}</p>
              </div>
            </div>
          ) : (
            <div className="text-center py-6">
              <p className="text-xs font-mono text-ink-muted mb-3">Click below to compute risk score & AI explanation.</p>
              <button
                onClick={fetchRisk}
                className="px-4 py-1.5 bg-signal text-base-bg font-mono text-xs rounded hover:bg-signal-dim transition-colors"
              >
                Calculate Risk Explanation
              </button>
            </div>
          )}
        </div>
      )}

      {!loading && activeTab === "mitre" && (
        <div>
          {mitreData ? (
            <div className="space-y-3 font-mono text-xs">
              <div className="text-ink-muted mb-2">
                Mapped <strong className="text-ink">{mitreData.total_techniques_mapped}</strong> MITRE ATT&CK technique(s) based on findings:
              </div>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                {mitreData.mitre_attack_matrix.map((tech, idx) => (
                  <div key={idx} className="p-3 bg-base-bg rounded border border-base-border">
                    <div className="flex justify-between items-center mb-1">
                      <span className="font-bold text-signal">{tech.technique_id}</span>
                      <span className="text-[10px] px-2 py-0.5 bg-base-surface border border-base-border rounded text-ink-muted">
                        {tech.tactic}
                      </span>
                    </div>
                    <div className="font-semibold text-ink mb-1">{tech.technique_name}</div>
                    <p className="text-[11px] text-ink-muted leading-relaxed">{tech.description}</p>
                  </div>
                ))}
              </div>
            </div>
          ) : (
            <div className="text-center py-6">
              <p className="text-xs font-mono text-ink-muted mb-3">Click below to map findings to MITRE ATT&CK Matrix.</p>
              <button
                onClick={fetchMitre}
                className="px-4 py-1.5 bg-signal text-base-bg font-mono text-xs rounded hover:bg-signal-dim transition-colors"
              >
                Fetch MITRE ATT&CK Mapping
              </button>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
