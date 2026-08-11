export default function GeoMap({ data }) {
  if (!data || !data.locations || data.locations.length === 0) {
    return (
      <div className="p-8 text-center text-xs font-mono text-ink-muted bg-base-bg rounded border border-base-border">
        No geographic location coordinates found.
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div className="text-xs font-mono text-ink-muted">
          Geographic Target Locations: <strong className="text-ink">{data.total_locations}</strong>
        </div>
      </div>

      {/* Visual World Map Representation Container */}
      <div className="relative bg-base-bg border border-base-border rounded-xl p-6 overflow-hidden min-h-[220px] flex items-center justify-center">
        {/* World Grid Lines Overlay */}
        <div className="absolute inset-0 opacity-10 bg-[radial-gradient(#10B981_1px,transparent_1px)] [background-size:16px_16px]" />
        
        <div className="relative z-10 text-center space-y-3">
          <div className="inline-flex items-center gap-2 px-3 py-1 bg-signal/10 border border-signal/30 rounded-full text-signal text-xs font-mono">
            <span className="w-2 h-2 rounded-full bg-signal animate-ping" />
            Active GeoIP Coordinates Rendered
          </div>
          
          <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-3">
            {data.locations.map((loc, idx) => (
              <div key={idx} className="bg-base-surface border border-base-border rounded-lg p-3 text-left font-mono text-xs shadow-sm">
                <div className="flex justify-between items-center mb-1">
                  <span className="font-bold text-ink">{loc.ip}</span>
                  <span className="px-2 py-0.5 bg-base-bg border border-base-border rounded text-[10px] text-signal">
                    {loc.country_code}
                  </span>
                </div>
                <div className="text-ink-muted text-[11px] mb-1">
                  {loc.city}, {loc.country}
                </div>
                <div className="text-[10px] text-ink-muted flex justify-between">
                  <span>Lat: {loc.latitude}</span>
                  <span>Lng: {loc.longitude}</span>
                </div>
                <div className="mt-1.5 pt-1.5 border-t border-base-border/50 text-[10px] text-signal truncate">
                  ISP: {loc.isp}
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Location Details Table */}
      <div className="overflow-x-auto bg-base-surface border border-base-border rounded-lg">
        <table className="w-full text-left font-mono text-xs text-ink-muted">
          <thead className="bg-base-bg border-b border-base-border text-ink text-[11px] uppercase">
            <tr>
              <th className="p-3">Target IP</th>
              <th className="p-3">Country / City</th>
              <th className="p-3">Coordinates</th>
              <th className="p-3">ISP Host</th>
              <th className="p-3">Source</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-base-border">
            {data.locations.map((loc, idx) => (
              <tr key={idx} className="hover:bg-base-bg/50 transition-colors">
                <td className="p-3 font-bold text-ink">{loc.ip}</td>
                <td className="p-3">{loc.city}, {loc.country} ({loc.country_code})</td>
                <td className="p-3 text-[11px]">{loc.latitude}, {loc.longitude}</td>
                <td className="p-3">{loc.isp}</td>
                <td className="p-3 uppercase text-signal text-[10px]">{loc.source_module}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
