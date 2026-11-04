import { useState } from "react";
import { analyzeThreatIntel } from "../services/api";

export default function ThreatIntelModule({ investigationId, onScanComplete }) {
  const [targetIndicator, setTargetIndicator] = useState("");
  const [scanning, setScanning] = useState(false);
  const [error, setError] = useState("");
  const [scanResult, setScanResult] = useState(null);
  const [activeTab, setActiveTab] = useState("summary");

  const handleRunScan = async (e) => {
    e.preventDefault();
    if (!targetIndicator.trim()) {
      setError("Please enter a target indicator (IP, Domain, or Hash).");
      return;
    }

    setError("");
    setScanning(true);
    setScanResult(null);

    try {
      const data = await analyzeThreatIntel(investigationId, targetIndicator.trim());
      setScanResult(data);
      if (onScanComplete) onScanComplete(data);
    } catch (err) {
      console.error("Threat intel error:", err);
      setError(err.response?.data?.detail || "Threat intel lookup failed. Please try again.");
    } finally {
      setScanning(false);
    }
  };

  const getThreatBadge = (level) => {
    switch (level?.toLowerCase()) {
      case "clean":
      case "low":
        return "bg-risk-low/20 text-risk-low border-risk-low/40";
      case "medium":
      case "suspicious":
        return "bg-risk-medium/20 text-risk-medium border-risk-medium/40";
      case "high":
      case "critical":
      case "malicious":
        return "bg-risk-critical/20 text-risk-critical border-risk-critical/40";
      default:
        return "bg-base-border text-ink-muted border-base-border";
    }
  };

  const getScoreColor = (score) => {
    if (score >= 80) return "text-emerald-400";
    if (score >= 50) return "text-risk-medium";
    return "text-risk-critical";
  };

  const vt = scanResult?.virustotal || {};
  const vtStats = vt?.data?.attributes?.last_analysis_stats || {};
  const abuse = scanResult?.abuseipdb || {};
  const shodan = scanResult?.shodan || {};

  return (
    <div className="bg-base-surface border border-base-border rounded-lg p-6 space-y-6">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-base-border pb-6">
        <div>
          <div className="flex items-center gap-2">
            <span className="text-signal text-xl">🛡️</span>
            <h3 className="font-mono text-lg font-bold text-ink">Multi-Feed Threat Intelligence</h3>
          </div>
          <p className="text-xs font-mono text-ink-muted mt-1">
            Aggregated reputation auditing via VirusTotal v3, AbuseIPDB, and Shodan (Live & Simulation Feeds)
          </p>
        </div>
      </div>

      {/* Input */}
      <form onSubmit={handleRunScan} className="flex flex-col sm:flex-row gap-3">
        <input
          type="text"
          placeholder="Indicator of Compromise (IP, Domain, or Hash)..."
          value={targetIndicator}
          onChange={(e) => setTargetIndicator(e.target.value)}
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
              <span>Querying Threat Feeds...</span>
            </>
          ) : (
            <span>Lookup Indicator</span>
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
          {/* Top Metrics */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
            <div className="bg-base-bg border border-base-border rounded-md p-3">
              <span className="text-[10px] font-mono text-ink-muted block uppercase">Indicator Type</span>
              <span className="font-mono text-sm font-bold text-ink uppercase">
                {scanResult.target_type || "Generic"}
              </span>
            </div>
            <div className="bg-base-bg border border-base-border rounded-md p-3">
              <span className="text-[10px] font-mono text-ink-muted block uppercase">Overall Threat Level</span>
              <span className={`inline-block px-2 py-0.5 text-xs font-mono font-bold rounded border mt-0.5 ${getThreatBadge(scanResult.threat_level)}`}>
                {scanResult.threat_level || "Clean"}
              </span>
            </div>
            <div className="bg-base-bg border border-base-border rounded-md p-3">
              <span className="text-[10px] font-mono text-ink-muted block uppercase">VirusTotal Detections</span>
              <span className={`font-mono text-sm font-bold ${
                (vtStats.malicious || 0) > 0 ? "text-risk-critical" : "text-emerald-400"
              }`}>
                {vtStats.malicious || 0} / {(vtStats.malicious || 0) + (vtStats.harmless || 0) + (vtStats.undetected || 0)} Vendors
              </span>
            </div>
            <div className="bg-base-bg border border-base-border rounded-md p-3">
              <span className="text-[10px] font-mono text-ink-muted block uppercase">Abuse Confidence</span>
              <span className={`font-mono text-sm font-bold ${
                (abuse.abuse_confidence_score ?? abuse.data?.abuseConfidenceScore ?? 0) > 20 ? "text-risk-critical" : "text-ink"
              }`}>
                {abuse.abuse_confidence_score ?? abuse.data?.abuseConfidenceScore ?? 0}%
              </span>
            </div>
          </div>

          {/* Subtabs */}
          <div className="flex items-center gap-2 border-b border-base-border">
            {["summary", "virustotal", "abuseipdb", "shodan"].map((tab) => (
              <button
                key={tab}
                onClick={() => setActiveTab(tab)}
                className={`px-3 py-1.5 text-xs font-mono uppercase tracking-wide border-b-2 -mb-px transition-colors ${
                  activeTab === tab
                    ? "border-signal text-signal font-bold"
                    : "border-transparent text-ink-muted hover:text-ink"
                }`}
              >
                {tab}
              </button>
            ))}
          </div>

          {/* TAB 1: SUMMARY */}
          {activeTab === "summary" && (
            <div className="bg-base-bg border border-base-border rounded-md p-4 space-y-3 font-mono text-xs">
              <div className="flex justify-between py-1 border-b border-base-border/50">
                <span className="text-ink-muted">Audited Indicator:</span>
                <span className="text-ink font-bold break-all">{scanResult.target}</span>
              </div>
              <div className="flex justify-between py-1 border-b border-base-border/50">
                <span className="text-ink-muted">Unified Safety Score:</span>
                <span className={`font-bold ${getScoreColor(scanResult.unified_score ?? 100)}`}>
                  {scanResult.unified_score ?? 100} / 100
                </span>
              </div>
              <div className="flex justify-between py-1 border-b border-base-border/50">
                <span className="text-ink-muted">Shodan Open Ports Discovered:</span>
                <span className="text-ink font-bold">
                  {shodan.ports && shodan.ports.length > 0 ? shodan.ports.join(", ") : "None reported"}
                </span>
              </div>
              <div className="flex justify-between py-1">
                <span className="text-ink-muted">Scan Timestamp:</span>
                <span className="text-ink">{scanResult.scanned_at ? new Date(scanResult.scanned_at).toLocaleString() : "Just now"}</span>
              </div>
            </div>
          )}

          {/* TAB 2: VIRUSTOTAL */}
          {activeTab === "virustotal" && (
            <div className="bg-base-bg border border-base-border rounded-md p-4 space-y-4 font-mono text-xs">
              <div className="flex items-center justify-between">
                <span className="font-bold text-ink">VirusTotal v3 Reputation Engine</span>
                <span className="text-ink-muted text-[11px]">
                  {vt.simulated ? "(Simulation Mode — No API Key Configured)" : "(Live API Feed)"}
                </span>
              </div>

              <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
                <div className="p-2 bg-base-surface rounded border border-base-border">
                  <span className="text-risk-critical block font-bold text-base">{vtStats.malicious || 0}</span>
                  <span className="text-ink-muted text-[10px]">Malicious</span>
                </div>
                <div className="p-2 bg-base-surface rounded border border-base-border">
                  <span className="text-risk-medium block font-bold text-base">{vtStats.suspicious || 0}</span>
                  <span className="text-ink-muted text-[10px]">Suspicious</span>
                </div>
                <div className="p-2 bg-base-surface rounded border border-base-border">
                  <span className="text-emerald-400 block font-bold text-base">{vtStats.harmless || 0}</span>
                  <span className="text-ink-muted text-[10px]">Harmless</span>
                </div>
                <div className="p-2 bg-base-surface rounded border border-base-border">
                  <span className="text-ink-muted block font-bold text-base">{vtStats.undetected || 0}</span>
                  <span className="text-ink-muted text-[10px]">Undetected</span>
                </div>
              </div>
            </div>
          )}

          {/* TAB 3: ABUSEIPDB */}
          {activeTab === "abuseipdb" && (
            <div className="bg-base-bg border border-base-border rounded-md p-4 space-y-3 font-mono text-xs">
              <div className="flex items-center justify-between pb-2 border-b border-base-border/50">
                <span className="font-bold text-ink">AbuseIPDB Database Feed</span>
                <span className="text-ink-muted text-[11px]">
                  {abuse.simulated ? "(Simulation Mode)" : "(Live Feed)"}
                </span>
              </div>
              <div className="flex justify-between py-1">
                <span className="text-ink-muted">Confidence Score:</span>
                <span className="text-ink font-bold">{abuse.abuse_confidence_score ?? 0}%</span>
              </div>
              <div className="flex justify-between py-1">
                <span className="text-ink-muted">Total Community Reports:</span>
                <span className="text-ink">{abuse.total_reports ?? 0}</span>
              </div>
              <div className="flex justify-between py-1">
                <span className="text-ink-muted">Country Code:</span>
                <span className="text-ink">{abuse.country_code || "N/A"}</span>
              </div>
              <div className="flex justify-between py-1">
                <span className="text-ink-muted">Whitelisted Host:</span>
                <span className="text-ink">{abuse.is_whitelisted ? "Yes" : "No"}</span>
              </div>
            </div>
          )}

          {/* TAB 4: SHODAN */}
          {activeTab === "shodan" && (
            <div className="bg-base-bg border border-base-border rounded-md p-4 space-y-3 font-mono text-xs">
              <div className="flex items-center justify-between pb-2 border-b border-base-border/50">
                <span className="font-bold text-ink">Shodan Internet Reconnaissance</span>
                <span className="text-ink-muted text-[11px]">
                  {shodan.simulated ? "(Simulation Mode)" : "(Live Feed)"}
                </span>
              </div>
              <div className="flex justify-between py-1">
                <span className="text-ink-muted">Organization:</span>
                <span className="text-ink font-bold">{shodan.org || "N/A"}</span>
              </div>
              <div className="flex justify-between py-1">
                <span className="text-ink-muted">Operating System:</span>
                <span className="text-ink">{shodan.os || "N/A"}</span>
              </div>
              <div className="flex justify-between py-1">
                <span className="text-ink-muted">Indexed Exposed Ports:</span>
                <span className="text-signal font-bold">
                  {shodan.ports && shodan.ports.length > 0 ? shodan.ports.join(", ") : "None"}
                </span>
              </div>
              {shodan.hostnames && shodan.hostnames.length > 0 && (
                <div className="pt-2">
                  <span className="text-ink-muted block mb-1">Hostnames:</span>
                  <div className="flex flex-wrap gap-1">
                    {shodan.hostnames.map((h, i) => (
                      <span key={i} className="px-2 py-0.5 bg-base-surface border border-base-border rounded text-[11px]">
                        {h}
                      </span>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
