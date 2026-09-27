import { useState } from "react";
import { analyzeIp } from "../services/api";

export default function IpIntelModule({ investigationId, onScanComplete }) {
  const [targetIp, setTargetIp] = useState("");
  const [consentConfirmed, setConsentConfirmed] = useState(false);
  const [scanning, setScanning] = useState(false);
  const [error, setError] = useState("");
  const [scanResult, setScanResult] = useState(null);
  const [activeTab, setActiveTab] = useState("summary");

  const handleRunScan = async (e) => {
    e.preventDefault();
    if (!targetIp.trim()) {
      setError("Please enter a valid IP address (e.g. 8.8.8.8).");
      return;
    }

    setError("");
    setScanning(true);
    setScanResult(null);

    try {
      const data = await analyzeIp(investigationId, targetIp.trim(), consentConfirmed);
      setScanResult(data);
      if (onScanComplete) onScanComplete(data);
    } catch (err) {
      console.error("IP scan error:", err);
      setError(err.response?.data?.detail || "IP scan failed. Please verify the IP address and try again.");
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

  const geo = scanResult?.geoip || {};
  const reputation = scanResult?.reputation || {};
  const ports = scanResult?.open_ports || [];

  return (
    <div className="bg-base-surface border border-base-border rounded-lg p-6 space-y-6">
      {/* Module Header & Input Form */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-base-border pb-6">
        <div>
          <div className="flex items-center gap-2">
            <span className="text-signal text-xl">🖥️</span>
            <h3 className="font-mono text-lg font-bold text-ink">IP Intelligence & Consent Gate</h3>
          </div>
          <p className="text-xs font-mono text-ink-muted mt-1">
            Passive GeoIP, ASN, and Reputation auditing + Consent-gated TCP port scanning
          </p>
        </div>
      </div>

      <form onSubmit={handleRunScan} className="space-y-4">
        <div className="flex flex-col sm:flex-row gap-3">
          <input
            type="text"
            placeholder="Target IP address (e.g. 1.1.1.1, 8.8.8.8)..."
            value={targetIp}
            onChange={(e) => setTargetIp(e.target.value)}
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
                <span>Auditing IP...</span>
              </>
            ) : (
              <span>Start IP Recon</span>
            )}
          </button>
        </div>

        {/* Consent Gate Checkbox */}
        <div className="p-3.5 bg-base-bg border border-base-border rounded-md flex items-start gap-3">
          <input
            type="checkbox"
            id="consent-check"
            checked={consentConfirmed}
            onChange={(e) => setConsentConfirmed(e.target.checked)}
            className="mt-1 h-4 w-4 rounded border-base-border text-signal focus:ring-signal"
          />
          <label htmlFor="consent-check" className="text-xs font-mono text-ink cursor-pointer select-none">
            <strong className="text-signal">Authorization Consent Gate:</strong> I confirm that I am explicitly authorized to conduct active TCP port scanning against this IP address.
            <span className="block text-[11px] text-ink-muted mt-0.5">
              If checked, port scan findings will be recorded into the persistent <code>consent_logs</code> audit trail.
            </span>
          </label>
        </div>
      </form>

      {error && (
        <div className="p-4 bg-risk-critical/10 border border-risk-critical/30 text-risk-critical text-xs font-mono rounded-md">
          {error}
        </div>
      )}

      {/* SCAN RESULTS DISPLAY */}
      {scanResult && (
        <div className="space-y-6 pt-2">
          {/* Top Metric Cards */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
            <div className="bg-base-bg border border-base-border rounded-md p-3">
              <span className="text-[10px] font-mono text-ink-muted block uppercase">Country / City</span>
              <span className="font-mono text-sm font-bold text-ink">
                {geo.country ? `${geo.country} (${geo.city || "N/A"})` : "Unknown"}
              </span>
            </div>
            <div className="bg-base-bg border border-base-border rounded-md p-3">
              <span className="text-[10px] font-mono text-ink-muted block uppercase">ASN / ISP</span>
              <span className="font-mono text-sm font-bold text-ink truncate block" title={geo.isp || ""}>
                {geo.isp || geo.asn || "N/A"}
              </span>
            </div>
            <div className="bg-base-bg border border-base-border rounded-md p-3">
              <span className="text-[10px] font-mono text-ink-muted block uppercase">Threat Level</span>
              <span className={`inline-block px-2 py-0.5 text-xs font-mono font-bold rounded border mt-0.5 ${getThreatBadge(reputation.threat_level)}`}>
                {reputation.threat_level || "Clean"}
              </span>
            </div>
            <div className="bg-base-bg border border-base-border rounded-md p-3">
              <span className="text-[10px] font-mono text-ink-muted block uppercase">Open Ports Audited</span>
              <span className="font-mono text-sm font-bold text-signal">
                {scanResult.consent_confirmed ? `${ports.length} Open` : "Consent Required"}
              </span>
            </div>
          </div>

          {/* Subtabs */}
          <div className="flex items-center gap-2 border-b border-base-border">
            {["summary", "geoip", "ports", "reputation"].map((tab) => (
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
                <span className="text-ink-muted">Target IP:</span>
                <span className="text-ink font-bold">{scanResult.target}</span>
              </div>
              <div className="flex justify-between py-1 border-b border-base-border/50">
                <span className="text-ink-muted">Coordinates (Lat, Lon):</span>
                <span className="text-ink">{geo.lat && geo.lon ? `${geo.lat}, ${geo.lon}` : "N/A"}</span>
              </div>
              <div className="flex justify-between py-1 border-b border-base-border/50">
                <span className="text-ink-muted">Timezone:</span>
                <span className="text-ink">{geo.timezone || "N/A"}</span>
              </div>
              <div className="flex justify-between py-1 border-b border-base-border/50">
                <span className="text-ink-muted">Active Consent Logged:</span>
                <span className={scanResult.consent_logged ? "text-signal font-bold" : "text-ink-muted"}>
                  {scanResult.consent_logged ? "Yes (Logged to Audit Table)" : "No (Passive Scan Only)"}
                </span>
              </div>
              <div className="flex justify-between py-1">
                <span className="text-ink-muted">Scan Timestamp:</span>
                <span className="text-ink">{scanResult.scanned_at ? new Date(scanResult.scanned_at).toLocaleString() : "Just now"}</span>
              </div>
            </div>
          )}

          {/* TAB 2: GEOIP & NETWORK */}
          {activeTab === "geoip" && (
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 font-mono text-xs">
              <div className="bg-base-bg border border-base-border rounded-md p-4 space-y-2">
                <h4 className="font-bold text-signal mb-2">Geographic Location</h4>
                <p><span className="text-ink-muted">Country:</span> {geo.country} ({geo.country_code})</p>
                <p><span className="text-ink-muted">Region:</span> {geo.region || "N/A"}</p>
                <p><span className="text-ink-muted">City:</span> {geo.city || "N/A"}</p>
                <p><span className="text-ink-muted">Postal Code:</span> {geo.zip || "N/A"}</p>
              </div>
              <div className="bg-base-bg border border-base-border rounded-md p-4 space-y-2">
                <h4 className="font-bold text-signal mb-2">Autonomous System & Network</h4>
                <p><span className="text-ink-muted">ISP:</span> {geo.isp || "N/A"}</p>
                <p><span className="text-ink-muted">Organization:</span> {geo.org || "N/A"}</p>
                <p><span className="text-ink-muted">ASN:</span> {geo.asn || "N/A"}</p>
                <p><span className="text-ink-muted">Timezone:</span> {geo.timezone || "N/A"}</p>
              </div>
            </div>
          )}

          {/* TAB 3: OPEN PORTS */}
          {activeTab === "ports" && (
            <div className="space-y-3 font-mono text-xs">
              {!scanResult.consent_confirmed ? (
                <div className="p-6 text-center bg-base-bg border border-base-border rounded-md text-ink-muted">
                  <p className="font-bold text-ink mb-1">Port Scan Locked</p>
                  <p>Check the "Authorization Consent Gate" above to permit active TCP port enumeration on this host.</p>
                </div>
              ) : ports.length === 0 ? (
                <div className="p-6 text-center bg-base-bg border border-base-border rounded-md text-ink-muted">
                  No standard open ports discovered during reconnaissance.
                </div>
              ) : (
                <div className="overflow-x-auto border border-base-border rounded-md">
                  <table className="w-full text-left">
                    <thead className="bg-base-bg border-b border-base-border text-ink-muted uppercase text-[11px]">
                      <tr>
                        <th className="p-3">Port</th>
                        <th className="p-3">Service</th>
                        <th className="p-3">State</th>
                        <th className="p-3">Service Banner</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-base-border/50 bg-base-bg">
                      {ports.map((p, idx) => (
                        <tr key={idx} className="hover:bg-base-surface">
                          <td className="p-3 font-bold text-signal">{p.port}</td>
                          <td className="p-3 text-ink">{p.service}</td>
                          <td className="p-3">
                            <span className="px-2 py-0.5 rounded bg-emerald-500/20 text-emerald-400 border border-emerald-500/30 text-[10px] uppercase">
                              {p.state}
                            </span>
                          </td>
                          <td className="p-3 text-ink-muted truncate max-w-xs">{p.banner || "No banner response"}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          )}

          {/* TAB 4: REPUTATION */}
          {activeTab === "reputation" && (
            <div className="bg-base-bg border border-base-border rounded-md p-4 space-y-3 font-mono text-xs">
              <div className="flex justify-between py-1 border-b border-base-border/50">
                <span className="text-ink-muted">Reputation Score:</span>
                <span className="text-ink font-bold">{reputation.score ?? 100} / 100</span>
              </div>
              <div className="flex justify-between py-1 border-b border-base-border/50">
                <span className="text-ink-muted">Threat Classification:</span>
                <span className={`px-2 py-0.5 rounded border text-[11px] font-bold ${getThreatBadge(reputation.threat_level)}`}>
                  {reputation.threat_level || "Clean"}
                </span>
              </div>
              <div className="flex justify-between py-1">
                <span className="text-ink-muted">Abuse Confidence Score:</span>
                <span className="text-ink">{reputation.abuse_confidence_score ?? 0}%</span>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
