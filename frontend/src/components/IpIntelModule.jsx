import { useState, useEffect, useRef } from "react";
import { analyzeIp } from "../services/api";

/* ------------------------------------------------------------------ */
/* Lazy Leaflet loader — avoids SSR issues & keeps bundle clean       */
/* ------------------------------------------------------------------ */
let L = null;
let leafletLoaded = false;

function ensureLeafletCSS() {
  if (typeof document === "undefined") return;
  if (document.getElementById("leaflet-css")) return;
  const link = document.createElement("link");
  link.id = "leaflet-css";
  link.rel = "stylesheet";
  link.href = "https://unpkg.com/leaflet@1.9.4/dist/leaflet.css";
  document.head.appendChild(link);
}

/* ------------------------------------------------------------------ */
/* Inline Map component using raw Leaflet (no react-leaflet needed)   */
/* ------------------------------------------------------------------ */
function LeafletMap({ lat, lon, label, zoom = 10 }) {
  const containerRef = useRef(null);
  const mapRef = useRef(null);

  useEffect(() => {
    if (!lat || !lon) return;
    ensureLeafletCSS();

    let cancelled = false;

    async function init() {
      if (!L) {
        const mod = await import("leaflet");
        L = mod.default || mod;
        leafletLoaded = true;
      }
      if (cancelled || !containerRef.current) return;

      // Destroy previous map instance
      if (mapRef.current) {
        mapRef.current.remove();
        mapRef.current = null;
      }

      const map = L.map(containerRef.current, {
        center: [lat, lon],
        zoom,
        scrollWheelZoom: true,
        attributionControl: true,
      });

      // Dark-themed tile layer (CartoDB Dark Matter)
      L.tileLayer(
        "https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png",
        {
          attribution:
            '&copy; <a href="https://carto.com/">CARTO</a> &copy; <a href="https://osm.org/copyright">OSM</a>',
          subdomains: "abcd",
          maxZoom: 19,
        }
      ).addTo(map);

      // Custom green pulsing marker icon
      const icon = L.divIcon({
        className: "",
        html: `<div style="
          width:18px;height:18px;border-radius:50%;
          background:#10B981;border:3px solid #064E3B;
          box-shadow:0 0 12px 4px rgba(16,185,129,0.5);
        "></div>`,
        iconSize: [18, 18],
        iconAnchor: [9, 9],
      });

      L.marker([lat, lon], { icon })
        .addTo(map)
        .bindPopup(
          `<div style="font-family:monospace;font-size:12px;min-width:160px;">
            <strong>${label || "Target"}</strong><br/>
            Lat: ${lat}<br/>Lon: ${lon}
          </div>`
        );

      // Accuracy radius (~50km city-level)
      L.circle([lat, lon], {
        radius: 50000,
        color: "#10B981",
        fillColor: "#10B981",
        fillOpacity: 0.08,
        weight: 1,
        dashArray: "6 4",
      }).addTo(map);

      mapRef.current = map;

      // Fix tile loading on dynamic containers
      setTimeout(() => map.invalidateSize(), 200);
    }

    init();

    return () => {
      cancelled = true;
      if (mapRef.current) {
        mapRef.current.remove();
        mapRef.current = null;
      }
    };
  }, [lat, lon, zoom, label]);

  if (!lat || !lon) {
    return (
      <div className="p-8 text-center text-xs font-mono text-ink-muted bg-base-bg rounded border border-base-border">
        No coordinates available for map rendering.
      </div>
    );
  }

  return (
    <div
      ref={containerRef}
      style={{ height: "380px", width: "100%", borderRadius: "8px" }}
      className="border border-base-border bg-base-bg"
    />
  );
}

/* ------------------------------------------------------------------ */
/* Main component                                                      */
/* ------------------------------------------------------------------ */
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
  const reverseDomains = scanResult?.reverse_dns_domains || geo?.reverse_dns_domains || [];
  const mapLinks = scanResult?.map_links || {};

  const tabs = ["summary", "map", "geoip", "ports", "reputation"];
  if (reverseDomains.length > 0) tabs.splice(4, 0, "reverse-ip");

  return (
    <div className="bg-base-surface border border-base-border rounded-lg p-6 space-y-6">
      {/* Module Header & Input Form */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-base-border pb-6">
        <div>
          <div className="flex items-center gap-2">
            <span className="text-signal text-xl">🖥️</span>
            <h3 className="font-mono text-lg font-bold text-ink">IP Intelligence & Geolocation</h3>
          </div>
          <p className="text-xs font-mono text-ink-muted mt-1">
            Multi-source GeoIP fusion • Interactive map • Reverse IP • Consent-gated TCP port scanning
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
          <div className="grid grid-cols-2 sm:grid-cols-5 gap-3">
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
              <span className="text-[10px] font-mono text-ink-muted block uppercase">Open Ports</span>
              <span className="font-mono text-sm font-bold text-signal">
                {scanResult.consent_confirmed ? `${ports.length} Open` : "Consent Required"}
              </span>
            </div>
            <div className="bg-base-bg border border-base-border rounded-md p-3">
              <span className="text-[10px] font-mono text-ink-muted block uppercase">Co-Hosted</span>
              <span className="font-mono text-sm font-bold text-ink">
                {reverseDomains.length > 0 ? `${reverseDomains.length} Domains` : "N/A"}
              </span>
            </div>
          </div>

          {/* Subtabs */}
          <div className="flex items-center gap-2 border-b border-base-border overflow-x-auto">
            {tabs.map((tab) => (
              <button
                key={tab}
                onClick={() => setActiveTab(tab)}
                className={`px-3 py-1.5 text-xs font-mono uppercase tracking-wide border-b-2 -mb-px transition-colors whitespace-nowrap ${
                  activeTab === tab
                    ? "border-signal text-signal font-bold"
                    : "border-transparent text-ink-muted hover:text-ink"
                }`}
              >
                {tab === "reverse-ip" ? "Reverse IP" : tab}
              </button>
            ))}
          </div>

          {/* TAB: SUMMARY */}
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
                <span className="text-ink-muted">Geo Source:</span>
                <span className="text-signal font-bold">{geo.geo_source || "ip-api.com"}</span>
              </div>
              <div className="flex justify-between py-1 border-b border-base-border/50">
                <span className="text-ink-muted">Active Consent Logged:</span>
                <span className={scanResult.consent_logged ? "text-signal font-bold" : "text-ink-muted"}>
                  {scanResult.consent_logged ? "Yes (Logged to Audit Table)" : "No (Passive Scan Only)"}
                </span>
              </div>
              <div className="flex justify-between py-1 border-b border-base-border/50">
                <span className="text-ink-muted">Scan Timestamp:</span>
                <span className="text-ink">{scanResult.scanned_at ? new Date(scanResult.scanned_at).toLocaleString() : "Just now"}</span>
              </div>
              {/* Map Links */}
              {(mapLinks.google_maps || mapLinks.openstreetmap) && (
                <div className="flex justify-between py-1 items-center">
                  <span className="text-ink-muted">View on Map:</span>
                  <div className="flex gap-2">
                    {mapLinks.google_maps && (
                      <a href={mapLinks.google_maps} target="_blank" rel="noopener noreferrer"
                        className="px-2 py-1 bg-signal/10 border border-signal/30 text-signal rounded text-[10px] hover:bg-signal/20 transition-colors">
                        Google Maps ↗
                      </a>
                    )}
                    {mapLinks.openstreetmap && (
                      <a href={mapLinks.openstreetmap} target="_blank" rel="noopener noreferrer"
                        className="px-2 py-1 bg-signal/10 border border-signal/30 text-signal rounded text-[10px] hover:bg-signal/20 transition-colors">
                        OpenStreetMap ↗
                      </a>
                    )}
                  </div>
                </div>
              )}
            </div>
          )}

          {/* TAB: MAP */}
          {activeTab === "map" && (
            <div className="space-y-3">
              <div className="flex items-center gap-2 text-xs font-mono text-ink-muted">
                <span className="w-2 h-2 rounded-full bg-signal animate-pulse" />
                <span>Interactive Geolocation Map — approximate city-level accuracy (~50km radius)</span>
              </div>
              <LeafletMap
                lat={geo.lat}
                lon={geo.lon}
                label={`${scanResult.target} — ${geo.city || "Unknown"}, ${geo.country || "Unknown"}`}
              />
              {/* Map quick actions */}
              <div className="flex gap-2 flex-wrap">
                {mapLinks.google_maps && (
                  <a href={mapLinks.google_maps} target="_blank" rel="noopener noreferrer"
                    className="px-3 py-1.5 bg-signal/10 border border-signal/30 text-signal rounded text-xs font-mono hover:bg-signal/20 transition-colors">
                    🌍 Open in Google Maps ↗
                  </a>
                )}
                {mapLinks.openstreetmap && (
                  <a href={mapLinks.openstreetmap} target="_blank" rel="noopener noreferrer"
                    className="px-3 py-1.5 bg-signal/10 border border-signal/30 text-signal rounded text-xs font-mono hover:bg-signal/20 transition-colors">
                    🗺️ Open in OpenStreetMap ↗
                  </a>
                )}
              </div>
            </div>
          )}

          {/* TAB: GEOIP & NETWORK */}
          {activeTab === "geoip" && (
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 font-mono text-xs">
              <div className="bg-base-bg border border-base-border rounded-md p-4 space-y-2">
                <h4 className="font-bold text-signal mb-2">Geographic Location</h4>
                <p><span className="text-ink-muted">Country:</span> {geo.country} ({geo.country_code})</p>
                <p><span className="text-ink-muted">Region:</span> {geo.region || "N/A"}</p>
                <p><span className="text-ink-muted">City:</span> {geo.city || "N/A"}</p>
                <p><span className="text-ink-muted">Postal Code:</span> {geo.zip || "N/A"}</p>
                <p><span className="text-ink-muted">Coordinates:</span> {geo.lat}, {geo.lon}</p>
              </div>
              <div className="bg-base-bg border border-base-border rounded-md p-4 space-y-2">
                <h4 className="font-bold text-signal mb-2">Autonomous System & Network</h4>
                <p><span className="text-ink-muted">ISP:</span> {geo.isp || "N/A"}</p>
                <p><span className="text-ink-muted">Organization:</span> {geo.org || "N/A"}</p>
                <p><span className="text-ink-muted">ASN:</span> {geo.asn || "N/A"}</p>
                <p><span className="text-ink-muted">Timezone:</span> {geo.timezone || "N/A"}</p>
                <p><span className="text-ink-muted">Geo Source:</span> <span className="text-signal">{geo.geo_source || "N/A"}</span></p>
              </div>
            </div>
          )}

          {/* TAB: OPEN PORTS */}
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

          {/* TAB: REVERSE IP */}
          {activeTab === "reverse-ip" && reverseDomains.length > 0 && (
            <div className="space-y-3 font-mono text-xs">
              <div className="flex items-center gap-2 text-ink-muted">
                <span className="text-signal font-bold">{reverseDomains.length}</span>
                <span>domains co-hosted on {scanResult.target}</span>
              </div>
              <div className="overflow-x-auto border border-base-border rounded-md">
                <table className="w-full text-left">
                  <thead className="bg-base-bg border-b border-base-border text-ink-muted uppercase text-[11px]">
                    <tr>
                      <th className="p-3">#</th>
                      <th className="p-3">Domain</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-base-border/50 bg-base-bg">
                    {reverseDomains.map((d, idx) => (
                      <tr key={idx} className="hover:bg-base-surface">
                        <td className="p-3 text-ink-muted">{idx + 1}</td>
                        <td className="p-3 font-bold text-ink">{d.domain || d}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* TAB: REPUTATION */}
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
