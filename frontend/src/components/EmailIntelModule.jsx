import { useState } from "react";
import { analyzeEmail } from "../services/api";

export default function EmailIntelModule({ investigationId, onScanComplete }) {
  const [targetEmail, setTargetEmail] = useState("");
  const [scanning, setScanning] = useState(false);
  const [error, setError] = useState("");
  const [scanResult, setScanResult] = useState(null);
  const [activeTab, setActiveTab] = useState("summary");

  const handleRunScan = async (e) => {
    e.preventDefault();
    if (!targetEmail.trim()) {
      setError("Please enter an email address (e.g. analyst@example.com).");
      return;
    }

    setError("");
    setScanning(true);
    setScanResult(null);

    try {
      const data = await analyzeEmail(investigationId, targetEmail.trim());
      setScanResult(data);
      if (onScanComplete) onScanComplete(data);
    } catch (err) {
      console.error("Email scan error:", err);
      setError(err.response?.data?.detail || "Email analysis failed. Please verify the address and try again.");
    } finally {
      setScanning(false);
    }
  };

  const dnsSec = scanResult?.dns_security || {};
  const breaches = scanResult?.breaches || {};

  return (
    <div className="bg-base-surface border border-base-border rounded-lg p-6 space-y-6">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-base-border pb-6">
        <div>
          <div className="flex items-center gap-2">
            <span className="text-signal text-xl">✉️</span>
            <h3 className="font-mono text-lg font-bold text-ink">Email Intelligence & Breach Recon</h3>
          </div>
          <p className="text-xs font-mono text-ink-muted mt-1">
            SPF/DKIM/DMARC email security posture, disposable mailbox detection, and compromise verification
          </p>
        </div>
      </div>

      {/* Input */}
      <form onSubmit={handleRunScan} className="flex flex-col sm:flex-row gap-3">
        <input
          type="email"
          placeholder="Target email address (e.g. user@targetcompany.com)..."
          value={targetEmail}
          onChange={(e) => setTargetEmail(e.target.value)}
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
              <span>Auditing Email...</span>
            </>
          ) : (
            <span>Inspect Email</span>
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
          {/* Metric Cards */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
            <div className="bg-base-bg border border-base-border rounded-md p-3">
              <span className="text-[10px] font-mono text-ink-muted block uppercase">Domain</span>
              <span className="font-mono text-sm font-bold text-ink truncate block">
                {scanResult.domain || "N/A"}
              </span>
            </div>
            <div className="bg-base-bg border border-base-border rounded-md p-3">
              <span className="text-[10px] font-mono text-ink-muted block uppercase">Disposable Check</span>
              <span className={`inline-block px-2 py-0.5 text-xs font-mono font-bold rounded border mt-0.5 ${
                scanResult.is_disposable
                  ? "bg-risk-critical/20 text-risk-critical border-risk-critical/40"
                  : "bg-risk-low/20 text-risk-low border-risk-low/40"
              }`}>
                {scanResult.is_disposable ? "Disposable / Burner" : "Legitimate Mailbox"}
              </span>
            </div>
            <div className="bg-base-bg border border-base-border rounded-md p-3">
              <span className="text-[10px] font-mono text-ink-muted block uppercase">SPF & DMARC Posture</span>
              <span className={`inline-block px-2 py-0.5 text-xs font-mono font-bold rounded border mt-0.5 ${
                dnsSec.has_spf && dnsSec.has_dmarc
                  ? "bg-risk-low/20 text-risk-low border-risk-low/40"
                  : "bg-risk-medium/20 text-risk-medium border-risk-medium/40"
              }`}>
                {dnsSec.has_spf && dnsSec.has_dmarc ? "Protected" : "Weak Configuration"}
              </span>
            </div>
            <div className="bg-base-bg border border-base-border rounded-md p-3">
              <span className="text-[10px] font-mono text-ink-muted block uppercase">Known Breaches</span>
              <span className={`font-mono text-sm font-bold ${
                (breaches.total_breaches || 0) > 0 ? "text-risk-critical" : "text-emerald-400"
              }`}>
                {breaches.total_breaches || 0} Incident{(breaches.total_breaches || 0) === 1 ? "" : "s"}
              </span>
            </div>
          </div>

          {/* Subtabs */}
          <div className="flex items-center gap-2 border-b border-base-border">
            {["summary", "dns_security", "breaches"].map((tab) => (
              <button
                key={tab}
                onClick={() => setActiveTab(tab)}
                className={`px-3 py-1.5 text-xs font-mono uppercase tracking-wide border-b-2 -mb-px transition-colors ${
                  activeTab === tab
                    ? "border-signal text-signal font-bold"
                    : "border-transparent text-ink-muted hover:text-ink"
                }`}
              >
                {tab.replace("_", " ")}
              </button>
            ))}
          </div>

          {/* TAB 1: SUMMARY */}
          {activeTab === "summary" && (
            <div className="bg-base-bg border border-base-border rounded-md p-4 space-y-3 font-mono text-xs">
              <div className="flex justify-between py-1 border-b border-base-border/50">
                <span className="text-ink-muted">Audited Email:</span>
                <span className="text-ink font-bold">{scanResult.target}</span>
              </div>
              <div className="flex justify-between py-1 border-b border-base-border/50">
                <span className="text-ink-muted">Syntax Validity:</span>
                <span className="text-emerald-400 font-bold">{scanResult.is_valid_format ? "Valid" : "Invalid"}</span>
              </div>
              <div className="flex justify-between py-1 border-b border-base-border/50">
                <span className="text-ink-muted">Deliverability (MX):</span>
                <span className="text-ink font-bold">
                  {dnsSec.mx_records && dnsSec.mx_records.length > 0
                    ? `${dnsSec.mx_records.length} MX Server(s) Configured`
                    : "No MX Records"}
                </span>
              </div>
              <div className="flex justify-between py-1">
                <span className="text-ink-muted">Scan Timestamp:</span>
                <span className="text-ink">{scanResult.scanned_at ? new Date(scanResult.scanned_at).toLocaleString() : "Just now"}</span>
              </div>
            </div>
          )}

          {/* TAB 2: DNS SECURITY */}
          {activeTab === "dns_security" && (
            <div className="space-y-4 font-mono text-xs">
              <div className="bg-base-bg border border-base-border rounded-md p-4 space-y-2">
                <div className="flex items-center justify-between">
                  <span className="font-bold text-ink">Sender Policy Framework (SPF)</span>
                  <span className={`px-2 py-0.5 rounded text-[10px] uppercase ${
                    dnsSec.has_spf ? "bg-emerald-500/20 text-emerald-400" : "bg-risk-critical/20 text-risk-critical"
                  }`}>
                    {dnsSec.has_spf ? "Configured" : "Missing"}
                  </span>
                </div>
                <div className="p-2 bg-base-surface rounded text-ink-muted break-all">
                  {dnsSec.spf_record || "No SPF TXT record published for this domain."}
                </div>
              </div>

              <div className="bg-base-bg border border-base-border rounded-md p-4 space-y-2">
                <div className="flex items-center justify-between">
                  <span className="font-bold text-ink">DMARC Policy</span>
                  <span className={`px-2 py-0.5 rounded text-[10px] uppercase ${
                    dnsSec.has_dmarc ? "bg-emerald-500/20 text-emerald-400" : "bg-risk-critical/20 text-risk-critical"
                  }`}>
                    {dnsSec.has_dmarc ? "Enforced" : "Missing"}
                  </span>
                </div>
                <div className="p-2 bg-base-surface rounded text-ink-muted break-all">
                  {dnsSec.dmarc_record || "No DMARC record found at _dmarc." + scanResult.domain}
                </div>
              </div>

              {dnsSec.mx_records && dnsSec.mx_records.length > 0 && (
                <div className="bg-base-bg border border-base-border rounded-md p-4 space-y-2">
                  <span className="font-bold text-ink block mb-1">Mail Exchange (MX) Hostnames</span>
                  <ul className="space-y-1 list-disc list-inside text-ink-muted">
                    {dnsSec.mx_records.map((mx, idx) => (
                      <li key={idx}>
                        <span className="text-signal font-bold">[{mx.preference}]</span> {mx.exchange}
                      </li>
                    ))}
                  </ul>
                </div>
              )}
            </div>
          )}

          {/* TAB 3: BREACHES */}
          {activeTab === "breaches" && (
            <div className="space-y-3 font-mono text-xs">
              {(breaches.total_breaches || 0) === 0 ? (
                <div className="p-6 text-center bg-base-bg border border-base-border rounded-md text-emerald-400">
                  ✓ No public security breaches associated with this identity in monitored repositories.
                </div>
              ) : (
                <div className="space-y-2">
                  <div className="p-3 bg-risk-critical/10 border border-risk-critical/30 rounded text-risk-critical">
                    ⚠️ This email was found in {breaches.total_breaches} security breach incidents:
                  </div>
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                    {(breaches.breach_names || []).map((bName, idx) => (
                      <div key={idx} className="p-3 bg-base-bg border border-base-border rounded">
                        <span className="font-bold text-ink block">{bName}</span>
                        <span className="text-[11px] text-ink-muted">Compromised repository record</span>
                      </div>
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
