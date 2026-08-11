import { useState } from "react";
import { analyzeDomain } from "../services/api";

export default function DomainIntelModule({ investigationId, onScanComplete }) {
  const [targetDomain, setTargetDomain] = useState("");
  const [scanning, setScanning] = useState(false);
  const [error, setError] = useState("");
  const [scanResult, setScanResult] = useState(null);
  const [activeTab, setActiveTab] = useState("summary");

  const handleRunScan = async (e) => {
    e.preventDefault();
    if (!targetDomain.trim()) {
      setError("Please enter a valid domain (e.g. example.com).");
      return;
    }

    // Clean protocol or path
    let cleaned = targetDomain.trim().toLowerCase();
    cleaned = cleaned.replace(/^https?:\/\//, "").split("/")[0];

    setError("");
    setScanning(true);
    setScanResult(null);

    try {
      const data = await analyzeDomain(investigationId, cleaned);
      setScanResult(data);
      if (onScanComplete) onScanComplete(data);
    } catch (err) {
      console.error("Domain scan error:", err);
      setError(err.response?.data?.detail || "Domain scan failed. Please verify the domain and try again.");
    } finally {
      setScanning(false);
    }
  };

  const getScoreBadge = (score) => {
    switch (score) {
      case "A+":
      case "A":
        return "bg-risk-low/20 text-risk-low border-risk-low/40";
      case "B":
        return "bg-signal/20 text-signal border-signal/40";
      case "C":
        return "bg-risk-medium/20 text-risk-medium border-risk-medium/40";
      case "D":
        return "bg-risk-high/20 text-risk-high border-risk-high/40";
      default:
        return "bg-risk-critical/20 text-risk-critical border-risk-critical/40";
    }
  };

  return (
    <div className="bg-base-surface border border-base-border rounded-lg p-6 space-y-6">
      {/* Module Header & Input Form */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-base-border pb-6">
        <div>
          <div className="flex items-center gap-2">
            <span className="text-signal text-xl">🌐</span>
            <h2 className="text-xl font-mono font-bold text-ink">Domain Intelligence Module</h2>
          </div>
          <p className="text-xs text-ink-muted mt-1 font-mono">
            WHOIS, DNS records, SSL cert, Security Headers, Tech Stack, and Subdomain enum.
          </p>
        </div>

        <form onSubmit={handleRunScan} className="flex items-center gap-2 max-w-md w-full">
          <input
            type="text"
            required
            placeholder="target-domain.com"
            value={targetDomain}
            onChange={(e) => setTargetDomain(e.target.value)}
            disabled={scanning}
            className="flex-1 px-3.5 py-2 bg-base-bg border border-base-border rounded-md text-sm text-ink placeholder:text-ink-muted/50 focus:border-signal font-mono disabled:opacity-50"
          />
          <button
            type="submit"
            disabled={scanning}
            className="px-4 py-2 bg-signal text-base-bg font-mono font-semibold text-sm rounded-md hover:bg-signal-dim transition-colors disabled:opacity-50 flex items-center gap-2 whitespace-nowrap"
          >
            {scanning ? (
              <>
                <span className="inline-block animate-spin h-3.5 w-3.5 border-2 border-base-bg border-t-transparent rounded-full" />
                Scanning...
              </>
            ) : (
              "Run Scan"
            )}
          </button>
        </form>
      </div>

      {error && (
        <div className="p-3 bg-risk-critical/10 border border-risk-critical/30 text-risk-critical text-xs font-mono rounded-md">
          ⚠️ {error}
        </div>
      )}

      {/* Results View */}
      {scanResult && (
        <div className="space-y-6">
          {/* Navigation Tabs */}
          <div className="flex items-center gap-1 border-b border-base-border overflow-x-auto">
            {[
              { id: "summary", label: "Overview" },
              { id: "whois", label: "WHOIS & Reg" },
              { id: "dns", label: "DNS Records" },
              { id: "ssl", label: "SSL / TLS Cert" },
              { id: "headers", label: "Security & Tech" },
              { id: "subdomains", label: `Subdomains (${scanResult.subdomains?.length || 0})` },
            ].map((tab) => (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={`px-4 py-2.5 text-xs font-mono font-medium border-b-2 transition-colors whitespace-nowrap ${
                  activeTab === tab.id
                    ? "border-signal text-signal bg-signal/5"
                    : "border-transparent text-ink-muted hover:text-ink"
                }`}
              >
                {tab.label}
              </button>
            ))}
          </div>

          {/* TAB 1: OVERVIEW */}
          {activeTab === "summary" && (
            <div className="space-y-6">
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                <div className="bg-base-bg p-4 rounded border border-base-border">
                  <span className="text-xs font-mono text-ink-muted uppercase">Security Header Grade</span>
                  <div className="mt-2 flex items-center gap-2">
                    <span className={`px-3 py-1 text-xl font-mono font-bold rounded border ${getScoreBadge(scanResult.summary?.security_score)}`}>
                      {scanResult.summary?.security_score || "F"}
                    </span>
                  </div>
                </div>

                <div className="bg-base-bg p-4 rounded border border-base-border">
                  <span className="text-xs font-mono text-ink-muted uppercase">A Records</span>
                  <p className="text-2xl font-mono font-bold text-ink mt-1">{scanResult.summary?.a_records_count}</p>
                </div>

                <div className="bg-base-bg p-4 rounded border border-base-border">
                  <span className="text-xs font-mono text-ink-muted uppercase">SSL Cert Status</span>
                  <p className="mt-1">
                    {scanResult.summary?.ssl_valid ? (
                      <span className="px-2.5 py-1 text-xs font-mono rounded bg-risk-low/20 text-risk-low border border-risk-low/40">Valid</span>
                    ) : (
                      <span className="px-2.5 py-1 text-xs font-mono rounded bg-risk-critical/20 text-risk-critical border border-risk-critical/40">Invalid / No TLS</span>
                    )}
                  </p>
                </div>

                <div className="bg-base-bg p-4 rounded border border-base-border">
                  <span className="text-xs font-mono text-ink-muted uppercase">Subdomains Discovered</span>
                  <p className="text-2xl font-mono font-bold text-signal mt-1">{scanResult.summary?.subdomains_found}</p>
                </div>
              </div>

              <div className="bg-base-bg p-4 rounded border border-base-border space-y-2 font-mono text-xs">
                <div className="flex justify-between">
                  <span className="text-ink-muted">Target Domain:</span>
                  <span className="text-signal font-bold">{scanResult.target}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-ink-muted">Scanned Timestamp:</span>
                  <span className="text-ink">{new Date(scanResult.scanned_at).toLocaleString()}</span>
                </div>
              </div>
            </div>
          )}

          {/* TAB 2: WHOIS */}
          {activeTab === "whois" && (
            <div className="bg-base-bg p-5 rounded border border-base-border space-y-4 font-mono text-xs">
              <h3 className="text-sm font-bold text-signal uppercase border-b border-base-border pb-2">Domain WHOIS / RDAP Details</h3>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <span className="text-ink-muted block mb-1">Registrar:</span>
                  <span className="text-ink bg-base-surface px-2.5 py-1 rounded border border-base-border block">
                    {scanResult.whois?.registrar || "Not disclosed / Unknown"}
                  </span>
                </div>

                <div>
                  <span className="text-ink-muted block mb-1">Creation Date:</span>
                  <span className="text-ink bg-base-surface px-2.5 py-1 rounded border border-base-border block">
                    {scanResult.whois?.creation_date || "N/A"}
                  </span>
                </div>

                <div>
                  <span className="text-ink-muted block mb-1">Expiration Date:</span>
                  <span className="text-ink bg-base-surface px-2.5 py-1 rounded border border-base-border block">
                    {scanResult.whois?.expiration_date || "N/A"}
                  </span>
                </div>

                <div>
                  <span className="text-ink-muted block mb-1">Updated Date:</span>
                  <span className="text-ink bg-base-surface px-2.5 py-1 rounded border border-base-border block">
                    {scanResult.whois?.updated_date || "N/A"}
                  </span>
                </div>
              </div>

              {scanResult.whois?.name_servers && scanResult.whois.name_servers.length > 0 && (
                <div>
                  <span className="text-ink-muted block mb-1">Name Servers:</span>
                  <div className="flex flex-wrap gap-2">
                    {scanResult.whois.name_servers.map((ns) => (
                      <span key={ns} className="px-2.5 py-1 bg-base-surface border border-base-border text-ink rounded">
                        {ns}
                      </span>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}

          {/* TAB 3: DNS RECORDS */}
          {activeTab === "dns" && (
            <div className="space-y-4 font-mono text-xs">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="bg-base-bg p-4 rounded border border-base-border">
                  <h4 className="text-signal font-bold mb-2">A Records (IPv4)</h4>
                  {scanResult.dns?.A?.length ? (
                    <ul className="space-y-1">
                      {scanResult.dns.A.map((ip) => (
                        <li key={ip} className="text-ink flex items-center justify-between bg-base-surface px-2.5 py-1 rounded">
                          <span>{ip}</span>
                          {scanResult.dns.PTR?.[ip] && (
                            <span className="text-ink-muted text-[10px]">({scanResult.dns.PTR[ip]})</span>
                          )}
                        </li>
                      ))}
                    </ul>
                  ) : (
                    <p className="text-ink-muted">No A records found.</p>
                  )}
                </div>

                <div className="bg-base-bg p-4 rounded border border-base-border">
                  <h4 className="text-signal font-bold mb-2">MX Records (Mail Exchangers)</h4>
                  {scanResult.dns?.MX?.length ? (
                    <ul className="space-y-1">
                      {scanResult.dns.MX.map((mx, idx) => (
                        <li key={idx} className="text-ink bg-base-surface px-2.5 py-1 rounded flex justify-between">
                          <span>{mx.exchange}</span>
                          <span className="text-ink-muted">prio: {mx.preference}</span>
                        </li>
                      ))}
                    </ul>
                  ) : (
                    <p className="text-ink-muted">No MX records found.</p>
                  )}
                </div>

                <div className="bg-base-bg p-4 rounded border border-base-border">
                  <h4 className="text-signal font-bold mb-2">NS Records (Name Servers)</h4>
                  {scanResult.dns?.NS?.length ? (
                    <ul className="space-y-1">
                      {scanResult.dns.NS.map((ns) => (
                        <li key={ns} className="text-ink bg-base-surface px-2.5 py-1 rounded">{ns}</li>
                      ))}
                    </ul>
                  ) : (
                    <p className="text-ink-muted">No NS records found.</p>
                  )}
                </div>

                <div className="bg-base-bg p-4 rounded border border-base-border">
                  <h4 className="text-signal font-bold mb-2">TXT Records</h4>
                  {scanResult.dns?.TXT?.length ? (
                    <ul className="space-y-1 max-h-40 overflow-y-auto">
                      {scanResult.dns.TXT.map((txt, idx) => (
                        <li key={idx} className="text-ink bg-base-surface p-2 rounded break-all">{txt}</li>
                      ))}
                    </ul>
                  ) : (
                    <p className="text-ink-muted">No TXT records found.</p>
                  )}
                </div>
              </div>
            </div>
          )}

          {/* TAB 4: SSL CERTIFICATE */}
          {activeTab === "ssl" && (
            <div className="bg-base-bg p-5 rounded border border-base-border space-y-4 font-mono text-xs">
              <h3 className="text-sm font-bold text-signal uppercase border-b border-base-border pb-2">SSL/TLS Certificate Inspection</h3>
              {scanResult.ssl?.valid ? (
                <div className="space-y-3">
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <div>
                      <span className="text-ink-muted block mb-1">Issuer Common Name:</span>
                      <span className="text-ink bg-base-surface px-2.5 py-1 rounded border border-base-border block">
                        {scanResult.ssl.issuer?.commonName || scanResult.ssl.issuer?.organizationName || "Unknown"}
                      </span>
                    </div>

                    <div>
                      <span className="text-ink-muted block mb-1">Days Remaining:</span>
                      <span className="text-risk-low bg-base-surface px-2.5 py-1 rounded border border-base-border block font-bold">
                        {scanResult.ssl.days_remaining} days
                      </span>
                    </div>

                    <div>
                      <span className="text-ink-muted block mb-1">Valid From:</span>
                      <span className="text-ink bg-base-surface px-2.5 py-1 rounded border border-base-border block">
                        {scanResult.ssl.valid_from}
                      </span>
                    </div>

                    <div>
                      <span className="text-ink-muted block mb-1">Valid Until:</span>
                      <span className="text-ink bg-base-surface px-2.5 py-1 rounded border border-base-border block">
                        {scanResult.ssl.valid_to}
                      </span>
                    </div>
                  </div>

                  {scanResult.ssl.sans?.length > 0 && (
                    <div>
                      <span className="text-ink-muted block mb-1">Subject Alternative Names (SANs):</span>
                      <div className="flex flex-wrap gap-1.5 max-h-36 overflow-y-auto p-2 bg-base-surface rounded border border-base-border">
                        {scanResult.ssl.sans.map((san) => (
                          <span key={san} className="px-2 py-0.5 bg-base-bg border border-base-border text-ink text-[11px] rounded">
                            {san}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              ) : (
                <p className="text-risk-critical">SSL Audit Failed: {scanResult.ssl?.error || "Could not establish TLS session."}</p>
              )}
            </div>
          )}

          {/* TAB 5: SECURITY HEADERS & TECH */}
          {activeTab === "headers" && (
            <div className="space-y-4 font-mono text-xs">
              <div className="bg-base-bg p-5 rounded border border-base-border space-y-3">
                <h3 className="text-sm font-bold text-signal uppercase border-b border-base-border pb-2">Detected Tech Stack</h3>
                {scanResult.http?.tech_stack?.length ? (
                  <div className="flex flex-wrap gap-2">
                    {scanResult.http.tech_stack.map((tech) => (
                      <span key={tech} className="px-3 py-1 bg-signal/15 text-signal border border-signal/30 font-bold rounded">
                        ⚡ {tech}
                      </span>
                    ))}
                  </div>
                ) : (
                  <p className="text-ink-muted">No explicit technology signature detected in headers.</p>
                )}
              </div>

              <div className="bg-base-bg p-5 rounded border border-base-border space-y-3">
                <h3 className="text-sm font-bold text-signal uppercase border-b border-base-border pb-2">HTTP Security Headers Checklist</h3>
                <div className="space-y-2">
                  {Object.entries(scanResult.http?.security_headers || {}).map(([hdr, info]) => (
                    <div key={hdr} className="flex items-center justify-between p-2.5 bg-base-surface rounded border border-base-border">
                      <span className="font-bold text-ink">{hdr}</span>
                      {info.present ? (
                        <span className="px-2 py-0.5 bg-risk-low/20 text-risk-low border border-risk-low/40 rounded text-[11px]">
                          PASS: {info.value?.slice(0, 30)}...
                        </span>
                      ) : (
                        <span className="px-2 py-0.5 bg-risk-critical/20 text-risk-critical border border-risk-critical/40 rounded text-[11px]">
                          MISSING
                        </span>
                      )}
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}

          {/* TAB 6: SUBDOMAINS */}
          {activeTab === "subdomains" && (
            <div className="bg-base-bg p-5 rounded border border-base-border space-y-3 font-mono text-xs">
              <h3 className="text-sm font-bold text-signal uppercase border-b border-base-border pb-2">
                Discovered Subdomains ({scanResult.subdomains?.length || 0})
              </h3>
              {scanResult.subdomains?.length ? (
                <div className="max-h-80 overflow-y-auto space-y-1.5">
                  {scanResult.subdomains.map((sub, idx) => (
                    <div key={idx} className="flex items-center justify-between p-2 bg-base-surface rounded border border-base-border">
                      <span className="text-ink font-bold">{sub.subdomain}</span>
                      <span className={sub.ip ? "text-signal" : "text-ink-muted"}>
                        {sub.ip || "No A Record"}
                      </span>
                    </div>
                  ))}
                </div>
              ) : (
                <p className="text-ink-muted">No subdomains discovered via Certificate Transparency logs.</p>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
