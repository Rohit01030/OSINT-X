import { useState } from "react";

export default function TimelineView({ data }) {
  const [filterModule, setFilterModule] = useState("all");

  if (!data || !data.events || data.events.length === 0) {
    return (
      <div className="p-8 text-center text-xs font-mono text-ink-muted bg-base-bg rounded border border-base-border">
        No chronological timeline events recorded.
      </div>
    );
  }

  const filteredEvents = data.events.filter((e) =>
    filterModule === "all" ? true : e.module === filterModule
  );

  return (
    <div className="space-y-4">
      {/* Module Filter Toolbar */}
      <div className="flex flex-wrap items-center justify-between gap-2 border-b border-base-border pb-3">
        <span className="text-xs font-mono text-ink-muted">
          Total Events: <strong className="text-ink">{data.total_events}</strong>
        </span>

        <div className="flex flex-wrap gap-1.5 font-mono text-xs">
          {["all", "core", "domain", "ip", "email", "username", "file", "threat_intel"].map((m) => (
            <button
              key={m}
              onClick={() => setFilterModule(m)}
              className={`px-2.5 py-1 rounded capitalize transition-colors ${
                filterModule === m
                  ? "bg-signal text-base-bg font-medium"
                  : "text-ink-muted hover:text-ink border border-base-border bg-base-bg"
              }`}
            >
              {m}
            </button>
          ))}
        </div>
      </div>

      {/* Chronological Timeline Track */}
      <div className="relative border-l-2 border-base-border ml-4 pl-6 space-y-6">
        {filteredEvents.map((evt, idx) => (
          <div key={idx} className="relative group">
            {/* Timeline Marker Bullet */}
            <span
              className={`absolute -left-[31px] top-1.5 w-3.5 h-3.5 rounded-full border-2 border-base-bg ${
                evt.severity === "CRITICAL"
                  ? "bg-risk-critical"
                  : evt.severity === "HIGH"
                  ? "bg-amber-500"
                  : evt.severity === "NOTICE"
                  ? "bg-emerald-500"
                  : "bg-signal"
              }`}
            />

            <div className="bg-base-surface border border-base-border rounded-lg p-4 shadow-sm transition-all group-hover:border-signal/50">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-1 mb-2">
                <h4 className="font-mono text-xs font-bold text-ink">{evt.title}</h4>
                <span className="text-[11px] font-mono text-ink-muted bg-base-bg px-2 py-0.5 rounded border border-base-border/50">
                  {evt.timestamp ? new Date(evt.timestamp).toLocaleString() : "N/A"}
                </span>
              </div>

              <p className="font-mono text-xs text-ink-muted mb-2 leading-relaxed">{evt.details}</p>

              <div className="flex items-center gap-2 font-mono text-[10px]">
                <span className="px-2 py-0.5 bg-base-bg border border-base-border rounded uppercase text-signal">
                  {evt.module}
                </span>
                <span
                  className={`px-2 py-0.5 rounded uppercase font-bold ${
                    evt.severity === "CRITICAL"
                      ? "bg-risk-critical text-white"
                      : evt.severity === "HIGH"
                      ? "bg-amber-500 text-black"
                      : "bg-signal/20 text-signal"
                  }`}
                >
                  {evt.severity}
                </span>
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
