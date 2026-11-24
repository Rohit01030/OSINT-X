import { useEffect, useRef } from "react";

/* ------------------------------------------------------------------ */
/* Lazy Leaflet loader                                                 */
/* ------------------------------------------------------------------ */
let L = null;

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
/* Multi-pin Leaflet Map for investigation-wide geo view               */
/* ------------------------------------------------------------------ */
function InvestigationMap({ locations }) {
  const containerRef = useRef(null);
  const mapRef = useRef(null);

  useEffect(() => {
    if (!locations || locations.length === 0) return;
    ensureLeafletCSS();

    let cancelled = false;

    async function init() {
      if (!L) {
        const mod = await import("leaflet");
        L = mod.default || mod;
      }
      if (cancelled || !containerRef.current) return;

      if (mapRef.current) {
        mapRef.current.remove();
        mapRef.current = null;
      }

      // Center on first location
      const first = locations[0];
      const map = L.map(containerRef.current, {
        center: [first.latitude, first.longitude],
        zoom: locations.length === 1 ? 10 : 3,
        scrollWheelZoom: true,
      });

      // Dark tiles
      L.tileLayer(
        "https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png",
        {
          attribution:
            '&copy; <a href="https://carto.com/">CARTO</a> &copy; <a href="https://osm.org/copyright">OSM</a>',
          subdomains: "abcd",
          maxZoom: 19,
        }
      ).addTo(map);

      // Module-to-color mapping
      const colorMap = {
        ip: "#10B981",
        domain: "#3B82F6",
        threat_intel: "#F59E0B",
      };

      const bounds = [];

      locations.forEach((loc) => {
        const color = colorMap[loc.source_module] || "#10B981";
        const icon = L.divIcon({
          className: "",
          html: `<div style="
            width:14px;height:14px;border-radius:50%;
            background:${color};border:2px solid #0f172a;
            box-shadow:0 0 8px 2px ${color}80;
          "></div>`,
          iconSize: [14, 14],
          iconAnchor: [7, 7],
        });

        const popupHtml = `
          <div style="font-family:monospace;font-size:11px;min-width:150px;">
            <strong>${loc.ip}</strong><br/>
            ${loc.city}, ${loc.country} (${loc.country_code})<br/>
            <span style="color:#888">ISP: ${loc.isp || "N/A"}</span><br/>
            <span style="color:#888">Source: ${loc.source_module}</span>
            ${loc.threat_level ? `<br/><span style="color:${loc.threat_level === "Clean" ? "#10B981" : "#EF4444"}">Threat: ${loc.threat_level}</span>` : ""}
            ${loc.open_ports_count ? `<br/><span style="color:#888">Open Ports: ${loc.open_ports_count}</span>` : ""}
            ${loc.reverse_dns_count ? `<br/><span style="color:#888">Co-hosted: ${loc.reverse_dns_count} domains</span>` : ""}
          </div>`;

        L.marker([loc.latitude, loc.longitude], { icon })
          .addTo(map)
          .bindPopup(popupHtml);

        bounds.push([loc.latitude, loc.longitude]);
      });

      // Fit to show all markers
      if (bounds.length > 1) {
        map.fitBounds(bounds, { padding: [40, 40], maxZoom: 12 });
      }

      mapRef.current = map;
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
  }, [locations]);

  return (
    <div
      ref={containerRef}
      style={{ height: "420px", width: "100%", borderRadius: "8px" }}
      className="border border-base-border bg-base-bg"
    />
  );
}

/* ------------------------------------------------------------------ */
/* GeoMap component                                                    */
/* ------------------------------------------------------------------ */
export default function GeoMap({ data }) {
  if (!data || !data.locations || data.locations.length === 0) {
    return (
      <div className="p-8 text-center text-xs font-mono text-ink-muted bg-base-bg rounded border border-base-border">
        No geographic location coordinates found. Run an IP Intelligence scan to generate geolocation data.
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header stats */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3 text-xs font-mono text-ink-muted">
          <div className="flex items-center gap-1.5">
            <span className="w-2 h-2 rounded-full bg-signal animate-pulse" />
            <span>Geographic Intelligence Map</span>
          </div>
          <span className="text-ink">•</span>
          <span><strong className="text-ink">{data.total_locations}</strong> locations mapped</span>
        </div>
        {/* Legend */}
        <div className="flex items-center gap-3 text-[10px] font-mono text-ink-muted">
          <span className="flex items-center gap-1">
            <span className="w-2 h-2 rounded-full bg-emerald-500 inline-block" /> IP Module
          </span>
          <span className="flex items-center gap-1">
            <span className="w-2 h-2 rounded-full bg-blue-500 inline-block" /> Domain
          </span>
          <span className="flex items-center gap-1">
            <span className="w-2 h-2 rounded-full bg-amber-500 inline-block" /> Threat Intel
          </span>
        </div>
      </div>

      {/* Interactive Leaflet Map */}
      <InvestigationMap locations={data.locations} />

      {/* Location Details Table */}
      <div className="overflow-x-auto bg-base-surface border border-base-border rounded-lg">
        <table className="w-full text-left font-mono text-xs text-ink-muted">
          <thead className="bg-base-bg border-b border-base-border text-ink text-[11px] uppercase">
            <tr>
              <th className="p-3">Target IP</th>
              <th className="p-3">Country / City</th>
              <th className="p-3">Coordinates</th>
              <th className="p-3">ISP Host</th>
              <th className="p-3">Threat</th>
              <th className="p-3">Source</th>
              <th className="p-3">Map</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-base-border">
            {data.locations.map((loc, idx) => (
              <tr key={idx} className="hover:bg-base-bg/50 transition-colors">
                <td className="p-3 font-bold text-ink">{loc.ip}</td>
                <td className="p-3">{loc.city}, {loc.country} ({loc.country_code})</td>
                <td className="p-3 text-[11px]">{loc.latitude}, {loc.longitude}</td>
                <td className="p-3 truncate max-w-[180px]">{loc.isp}</td>
                <td className="p-3">
                  <span className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${
                    loc.threat_level === "Clean" || !loc.threat_level
                      ? "bg-emerald-500/20 text-emerald-400 border border-emerald-500/30"
                      : "bg-red-500/20 text-red-400 border border-red-500/30"
                  }`}>
                    {loc.threat_level || "Clean"}
                  </span>
                </td>
                <td className="p-3 uppercase text-signal text-[10px]">{loc.source_module}</td>
                <td className="p-3">
                  <a
                    href={`https://www.google.com/maps?q=${loc.latitude},${loc.longitude}`}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-signal hover:underline text-[10px]"
                  >
                    View ↗
                  </a>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
