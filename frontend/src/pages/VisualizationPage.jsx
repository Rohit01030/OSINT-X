import { useState, useEffect } from "react";
import MainLayout from "../layouts/MainLayout";
import { getInvestigations } from "../services/api";
import {
  getRelationshipGraph,
  getTimeline,
  getGeoMap,
  getChartMetrics
} from "../services/visualizationService";

import RelationshipGraph from "../components/visualization/RelationshipGraph";
import TimelineView from "../components/visualization/TimelineView";
import GeoMap from "../components/visualization/GeoMap";
import MetricsCharts from "../components/visualization/MetricsCharts";

export default function VisualizationPage() {
  const [investigations, setInvestigations] = useState([]);
  const [selectedId, setSelectedId] = useState("");
  const [activeTab, setActiveTab] = useState("graph");

  const [graphData, setGraphData] = useState(null);
  const [timelineData, setTimelineData] = useState(null);
  const [geoData, setGeoData] = useState(null);
  const [metricsData, setMetricsData] = useState(null);

  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  useEffect(() => {
    fetchCaseList();
  }, []);

  useEffect(() => {
    if (selectedId) {
      loadTabData(activeTab, selectedId);
    }
  }, [selectedId, activeTab]);

  const fetchCaseList = async () => {
    try {
      const res = await getInvestigations();
      setInvestigations(res);
      if (res.length > 0) {
        setSelectedId(res[0].id);
      }
    } catch {
      setError("Failed to load investigation cases.");
    }
  };

  const loadTabData = async (tab, invId) => {
    setLoading(true);
    setError(null);
    try {
      if (tab === "graph") {
        const res = await getRelationshipGraph(invId);
        setGraphData(res);
      } else if (tab === "timeline") {
        const res = await getTimeline(invId);
        setTimelineData(res);
      } else if (tab === "geomap") {
        const res = await getGeoMap(invId);
        setGeoData(res);
      } else if (tab === "metrics") {
        const res = await getChartMetrics(invId);
        setMetricsData(res);
      }
    } catch (err) {
      setError(err.response?.data?.detail || "Failed to load visualization data.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <MainLayout>
      <div className="max-w-7xl mx-auto px-6 py-8 space-y-8">
        {/* Header & Case Selector Toolbar */}
        <div className="bg-base-surface border border-base-border rounded-xl p-6 shadow-sm flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-2 mb-1">
              <span className="w-3 h-3 rounded-full bg-signal inline-block animate-pulse" />
              <h1 className="text-xl font-bold font-mono tracking-tight text-ink">
                Intelligence Visualization Dashboard
              </h1>
            </div>
            <p className="text-xs font-mono text-ink-muted">
              Interactive Relationship Topology • Chronological Timeline • GeoIP Intelligence • Chart Metrics
            </p>
          </div>

          {/* Case Selector Dropdown */}
          <div className="flex items-center gap-3">
            <span className="text-xs font-mono text-ink-muted hidden sm:inline">Select Case:</span>
            <select
              value={selectedId}
              onChange={(e) => setSelectedId(e.target.value)}
              className="px-3 py-2 bg-base-bg border border-base-border rounded text-xs font-mono text-ink focus:outline-none focus:border-signal min-w-[220px]"
            >
              {investigations.length > 0 ? (
                investigations.map((inv) => (
                  <option key={inv.id} value={inv.id}>
                    {inv.title} ({inv.status})
                  </option>
                ))
              ) : (
                <option value="">No cases found</option>
              )}
            </select>
          </div>
        </div>

        {/* Tab Navigation Toolbar */}
        <div className="flex border-b border-base-border gap-2 font-mono text-xs">
          <button
            onClick={() => setActiveTab("graph")}
            className={`px-4 py-2.5 rounded-t-lg font-medium transition-colors ${
              activeTab === "graph"
                ? "bg-base-surface text-signal border-t border-x border-base-border border-b-base-surface -mb-px"
                : "text-ink-muted hover:text-ink"
            }`}
          >
            Network Graph
          </button>
          <button
            onClick={() => setActiveTab("timeline")}
            className={`px-4 py-2.5 rounded-t-lg font-medium transition-colors ${
              activeTab === "timeline"
                ? "bg-base-surface text-signal border-t border-x border-base-border border-b-base-surface -mb-px"
                : "text-ink-muted hover:text-ink"
            }`}
          >
            Timeline View
          </button>
          <button
            onClick={() => setActiveTab("geomap")}
            className={`px-4 py-2.5 rounded-t-lg font-medium transition-colors ${
              activeTab === "geomap"
                ? "bg-base-surface text-signal border-t border-x border-base-border border-b-base-surface -mb-px"
                : "text-ink-muted hover:text-ink"
            }`}
          >
            GeoIP Map
          </button>
          <button
            onClick={() => setActiveTab("metrics")}
            className={`px-4 py-2.5 rounded-t-lg font-medium transition-colors ${
              activeTab === "metrics"
                ? "bg-base-surface text-signal border-t border-x border-base-border border-b-base-surface -mb-px"
                : "text-ink-muted hover:text-ink"
            }`}
          >
            Chart Metrics
          </button>
        </div>

        {/* Loading & Error Indicators */}
        {loading && (
          <div className="py-16 text-center text-xs font-mono text-ink-muted bg-base-surface border border-base-border rounded-xl">
            <div className="inline-block animate-spin h-6 w-6 border-2 border-signal border-t-transparent rounded-full mb-3" />
            <p>Rendering visualization data graphics...</p>
          </div>
        )}

        {error && (
          <div className="p-4 bg-risk-critical/10 border border-risk-critical/30 text-risk-critical rounded-xl text-xs font-mono">
            {error}
          </div>
        )}

        {/* Tab Content Panes */}
        {!loading && !error && (
          <div className="bg-base-surface border border-base-border rounded-xl p-6 shadow-sm">
            {activeTab === "graph" && <RelationshipGraph data={graphData} />}
            {activeTab === "timeline" && <TimelineView data={timelineData} />}
            {activeTab === "geomap" && <GeoMap data={geoData} />}
            {activeTab === "metrics" && <MetricsCharts data={metricsData} />}
          </div>
        )}
      </div>
    </MainLayout>
  );
}
