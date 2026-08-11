import { useState, useEffect, useCallback } from "react";
import { useAuth } from "../contexts/AuthContext";
import {
  getDashboardSummary,
  getInvestigations,
  createInvestigation,
  updateInvestigation,
  deleteInvestigation,
} from "../services/api";
import DomainIntelModule from "../components/DomainIntelModule";

export default function Dashboard() {
  const { user } = useAuth();

  const [summary, setSummary] = useState(null);
  const [investigations, setInvestigations] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  // Filters & Search
  const [statusFilter, setStatusFilter] = useState("");
  const [searchQuery, setSearchQuery] = useState("");
  const [selectedTag, setSelectedTag] = useState("");

  // Modals state
  const [isCreateOpen, setIsCreateOpen] = useState(false);
  const [selectedCase, setSelectedCase] = useState(null);
  const [caseModalTab, setCaseModalTab] = useState("domain_scan"); // "domain_scan" or "settings"

  // New Case form state
  const [newTitle, setNewTitle] = useState("");
  const [newDesc, setNewDesc] = useState("");
  const [newTagsInput, setNewTagsInput] = useState("");
  const [createSubmitting, setCreateSubmitting] = useState(false);
  const [createError, setCreateError] = useState("");

  // Edit Case state
  const [editStatus, setEditStatus] = useState("");
  const [editDesc, setEditDesc] = useState("");
  const [editTagsInput, setEditTagsInput] = useState("");
  const [editSubmitting, setEditSubmitting] = useState(false);

  // Fetch Dashboard & Cases Data
  const fetchData = useCallback(async () => {
    setLoading(true);
    setError("");
    try {
      const [sumData, invList] = await Promise.all([
        getDashboardSummary(),
        getInvestigations({
          status: statusFilter || undefined,
          search: searchQuery || undefined,
          tag: selectedTag || undefined,
        }),
      ]);
      setSummary(sumData);
      setInvestigations(invList);
    } catch (err) {
      console.error("Dashboard fetch error:", err);
      setError("Failed to fetch dashboard data. Please try refreshing.");
    } finally {
      setLoading(false);
    }
  }, [statusFilter, searchQuery, selectedTag]);

  useEffect(() => {
    fetchData();
  }, [fetchData]);

  // Handle Create Investigation Case
  const handleCreateCase = async (e) => {
    e.preventDefault();
    if (!newTitle.trim()) {
      setCreateError("Title is required.");
      return;
    }

    setCreateError("");
    setCreateSubmitting(true);
    try {
      const tags = newTagsInput
        .split(",")
        .map((t) => t.trim())
        .filter(Boolean);

      await createInvestigation({
        title: newTitle.trim(),
        description: newDesc.trim(),
        tags,
      });

      setNewTitle("");
      setNewDesc("");
      setNewTagsInput("");
      setIsCreateOpen(false);
      await fetchData();
    } catch (err) {
      setCreateError(err.response?.data?.detail || "Failed to create investigation case.");
    } finally {
      setCreateSubmitting(false);
    }
  };

  // Open Edit / Manage Modal
  const openCaseDetails = (inv) => {
    setSelectedCase(inv);
    setCaseModalTab("domain_scan");
    setEditStatus(inv.status);
    setEditDesc(inv.description || "");
    setEditTagsInput((inv.tags || []).join(", "));
  };

  // Handle Save Case Updates
  const handleUpdateCase = async () => {
    if (!selectedCase) return;
    setEditSubmitting(true);
    try {
      const tags = editTagsInput
        .split(",")
        .map((t) => t.trim())
        .filter(Boolean);

      await updateInvestigation(selectedCase.id, {
        status: editStatus,
        description: editDesc,
        tags,
      });

      setSelectedCase(null);
      await fetchData();
    } catch (err) {
      alert(err.response?.data?.detail || "Failed to update investigation case.");
    } finally {
      setEditSubmitting(false);
    }
  };

  // Handle Delete Case
  const handleDeleteCase = async (invId) => {
    if (!window.confirm("Are you sure you want to delete this investigation case?")) return;
    try {
      await deleteInvestigation(invId);
      if (selectedCase?.id === invId) setSelectedCase(null);
      await fetchData();
    } catch (err) {
      alert("Failed to delete case.");
    }
  };

  // Get status color badge style
  const getStatusBadge = (status) => {
    switch (status) {
      case "active":
        return "bg-signal/15 text-signal border-signal/30";
      case "archived":
        return "bg-risk-medium/15 text-risk-medium border-risk-medium/30";
      case "closed":
        return "bg-ink-muted/15 text-ink-muted border-ink-muted/30";
      default:
        return "bg-base-border text-ink border-base-border";
    }
  };

  return (
    <div className="max-w-7xl mx-auto px-6 py-10 space-y-8">
      {/* Header Banner */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-base-border pb-6">
        <div>
          <div className="flex items-center gap-3">
            <h1 className="text-3xl font-mono font-bold text-ink">Investigation Cases</h1>
            <span className="px-2.5 py-0.5 rounded text-xs font-mono bg-signal/10 text-signal border border-signal/30">
              Phase 4 Domain Intel Ready
            </span>
          </div>
          <p className="mt-1 text-sm text-ink-muted">
            Welcome back, <span className="text-signal font-mono">{user?.username}</span> ({user?.role})
          </p>
        </div>

        <button
          onClick={() => setIsCreateOpen(true)}
          className="px-4 py-2.5 bg-signal text-base-bg font-mono font-semibold rounded-md hover:bg-signal-dim transition-colors flex items-center gap-2 self-start md:self-auto shadow-lg shadow-signal/10"
        >
          <span className="text-lg leading-none">+</span> New Case
        </button>
      </div>

      {/* Metrics Summary Widgets */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
        <div className="bg-base-surface border border-base-border rounded-lg p-5">
          <p className="text-xs font-mono text-ink-muted uppercase">Total Cases</p>
          <p className="text-3xl font-mono font-bold text-ink mt-2">
            {summary ? summary.total_investigations : "—"}
          </p>
        </div>

        <div className="bg-base-surface border border-base-border rounded-lg p-5">
          <p className="text-xs font-mono text-ink-muted uppercase">Active Cases</p>
          <p className="text-3xl font-mono font-bold text-signal mt-2">
            {summary ? summary.active_count : "—"}
          </p>
        </div>

        <div className="bg-base-surface border border-base-border rounded-lg p-5">
          <p className="text-xs font-mono text-ink-muted uppercase">Archived Cases</p>
          <p className="text-3xl font-mono font-bold text-risk-medium mt-2">
            {summary ? summary.archived_count : "—"}
          </p>
        </div>

        <div className="bg-base-surface border border-base-border rounded-lg p-5">
          <p className="text-xs font-mono text-ink-muted uppercase">Closed Cases</p>
          <p className="text-3xl font-mono font-bold text-ink-muted mt-2">
            {summary ? summary.closed_count : "—"}
          </p>
        </div>

        <div className="bg-base-surface border border-base-border rounded-lg p-5 col-span-2 md:col-span-1">
          <p className="text-xs font-mono text-ink-muted uppercase">Total Findings</p>
          <p className="text-3xl font-mono font-bold text-ink mt-2">
            {summary ? summary.total_findings : "—"}
          </p>
        </div>
      </div>

      {/* Controls & Search Filter Bar */}
      <div className="flex flex-col md:flex-row items-stretch md:items-center justify-between gap-4 bg-base-surface p-4 rounded-lg border border-base-border">
        {/* Status Filter Tabs */}
        <div className="flex items-center gap-1 bg-base-bg p-1 rounded-md border border-base-border overflow-x-auto">
          {[
            { label: "All Cases", val: "" },
            { label: "Active", val: "active" },
            { label: "Archived", val: "archived" },
            { label: "Closed", val: "closed" },
          ].map((tab) => (
            <button
              key={tab.val}
              onClick={() => setStatusFilter(tab.val)}
              className={`px-3 py-1.5 text-xs font-mono rounded transition-colors whitespace-nowrap ${
                statusFilter === tab.val
                  ? "bg-signal text-base-bg font-semibold"
                  : "text-ink-muted hover:text-ink"
              }`}
            >
              {tab.label}
            </button>
          ))}
        </div>

        {/* Search Bar */}
        <div className="flex items-center gap-3 flex-1 max-w-md">
          <div className="relative w-full">
            <input
              type="text"
              placeholder="Search title, description, domain..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full pl-9 pr-4 py-2 bg-base-bg border border-base-border rounded-md text-sm text-ink placeholder:text-ink-muted/50 focus:border-signal"
            />
            <span className="absolute left-3 top-2.5 text-ink-muted text-sm">🔍</span>
          </div>

          {selectedTag && (
            <button
              onClick={() => setSelectedTag("")}
              className="px-2.5 py-1.5 bg-risk-medium/20 text-risk-medium text-xs font-mono rounded border border-risk-medium/40 flex items-center gap-1"
            >
              tag: {selectedTag} ✕
            </button>
          )}
        </div>
      </div>

      {/* Error alert */}
      {error && (
        <div className="p-4 bg-risk-critical/10 border border-risk-critical/30 text-risk-critical text-sm font-mono rounded-md">
          {error}
        </div>
      )}

      {/* Cases List / Grid */}
      {loading ? (
        <div className="py-20 text-center font-mono text-ink-muted">
          <div className="inline-block animate-spin h-6 w-6 border-2 border-signal border-t-transparent rounded-full mb-3" />
          <p>Loading investigation repository...</p>
        </div>
      ) : investigations.length === 0 ? (
        <div className="bg-base-surface border border-base-border rounded-lg py-16 px-6 text-center">
          <p className="font-mono text-ink-muted text-base mb-4">No investigation cases found matching filter criteria.</p>
          <button
            onClick={() => setIsCreateOpen(true)}
            className="px-4 py-2 bg-signal/20 text-signal border border-signal/40 font-mono text-sm rounded hover:bg-signal/30 transition-colors"
          >
            Create first case
          </button>
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          {investigations.map((inv) => (
            <div
              key={inv.id}
              className="bg-base-surface border border-base-border hover:border-signal/50 transition-colors rounded-lg p-6 flex flex-col justify-between space-y-4 group"
            >
              <div>
                <div className="flex items-start justify-between gap-2 mb-3">
                  <h3 className="text-lg font-mono font-semibold text-ink group-hover:text-signal transition-colors line-clamp-1">
                    {inv.title}
                  </h3>
                  <span className={`px-2.5 py-0.5 text-xs font-mono rounded border uppercase ${getStatusBadge(inv.status)}`}>
                    {inv.status}
                  </span>
                </div>

                <p className="text-sm text-ink-muted line-clamp-2 min-h-[40px] mb-4">
                  {inv.description || "No description provided."}
                </p>

                {/* Tags */}
                {inv.tags && inv.tags.length > 0 && (
                  <div className="flex flex-wrap gap-1.5 mb-4">
                    {inv.tags.map((tag) => (
                      <span
                        key={tag}
                        onClick={(e) => {
                          e.stopPropagation();
                          setSelectedTag(tag);
                        }}
                        className="px-2 py-0.5 bg-base-bg text-ink-muted hover:text-signal text-xs font-mono rounded border border-base-border cursor-pointer transition-colors"
                      >
                        #{tag}
                      </span>
                    ))}
                  </div>
                )}
              </div>

              <div className="pt-4 border-t border-base-border flex items-center justify-between text-xs font-mono text-ink-muted">
                <span>Findings: <strong className="text-ink">{inv.findings_count || 0}</strong></span>
                <span>{new Date(inv.created_at).toLocaleDateString()}</span>
                <button
                  onClick={() => openCaseDetails(inv)}
                  className="text-signal hover:underline font-semibold"
                >
                  Manage / Scan →
                </button>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* CREATE CASE MODAL */}
      {isCreateOpen && (
        <div className="fixed inset-0 z-50 bg-black/70 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-base-surface border border-base-border rounded-lg max-w-lg w-full p-6 shadow-2xl space-y-5">
            <div className="flex items-center justify-between border-b border-base-border pb-4">
              <h2 className="text-xl font-mono font-semibold text-ink">New Investigation Case</h2>
              <button onClick={() => setIsCreateOpen(false)} className="text-ink-muted hover:text-ink text-lg">
                ✕
              </button>
            </div>

            {createError && (
              <div className="p-3 bg-risk-critical/10 border border-risk-critical/30 text-risk-critical text-xs font-mono rounded">
                ⚠️ {createError}
              </div>
            )}

            <form onSubmit={handleCreateCase} className="space-y-4">
              <div>
                <label className="block text-xs font-mono text-ink-muted mb-1">Case Title *</label>
                <input
                  type="text"
                  required
                  placeholder="e.g., Target Domain Recon — example.com"
                  value={newTitle}
                  onChange={(e) => setNewTitle(e.target.value)}
                  className="w-full px-3 py-2 bg-base-bg border border-base-border rounded text-sm text-ink focus:border-signal"
                />
              </div>

              <div>
                <label className="block text-xs font-mono text-ink-muted mb-1">Description</label>
                <textarea
                  rows={3}
                  placeholder="Scope, targets, goals, or preliminary notes..."
                  value={newDesc}
                  onChange={(e) => setNewDesc(e.target.value)}
                  className="w-full px-3 py-2 bg-base-bg border border-base-border rounded text-sm text-ink focus:border-signal"
                />
              </div>

              <div>
                <label className="block text-xs font-mono text-ink-muted mb-1">Tags (comma separated)</label>
                <input
                  type="text"
                  placeholder="phishing, domain_check, priority_1"
                  value={newTagsInput}
                  onChange={(e) => setNewTagsInput(e.target.value)}
                  className="w-full px-3 py-2 bg-base-bg border border-base-border rounded text-sm text-ink focus:border-signal"
                />
              </div>

              <div className="flex justify-end gap-3 pt-4 border-t border-base-border">
                <button
                  type="button"
                  onClick={() => setIsCreateOpen(false)}
                  className="px-4 py-2 border border-base-border text-ink-muted font-mono text-xs rounded hover:text-ink"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={createSubmitting}
                  className="px-4 py-2 bg-signal text-base-bg font-mono text-xs font-bold rounded hover:bg-signal-dim transition-colors"
                >
                  {createSubmitting ? "Creating..." : "Create Case"}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* MANAGE CASE & SCANNER DRAWER MODAL */}
      {selectedCase && (
        <div className="fixed inset-0 z-50 bg-black/75 backdrop-blur-sm flex items-center justify-center p-4 overflow-y-auto">
          <div className="bg-base-surface border border-base-border rounded-lg max-w-4xl w-full p-6 shadow-2xl space-y-6 my-8">
            <div className="flex flex-col md:flex-row md:items-center justify-between border-b border-base-border pb-4 gap-2">
              <div>
                <div className="flex items-center gap-2">
                  <span className="text-xs font-mono text-ink-muted">Case ID: {selectedCase.id.slice(0, 8)}...</span>
                  <span className={`px-2 py-0.5 text-[10px] font-mono rounded border uppercase ${getStatusBadge(selectedCase.status)}`}>
                    {selectedCase.status}
                  </span>
                </div>
                <h2 className="text-2xl font-mono font-bold text-ink mt-0.5">{selectedCase.title}</h2>
              </div>
              <button onClick={() => setSelectedCase(null)} className="text-ink-muted hover:text-ink text-xl self-end md:self-auto">
                ✕
              </button>
            </div>

            {/* Modal Tabs */}
            <div className="flex items-center gap-2 border-b border-base-border">
              <button
                onClick={() => setCaseModalTab("domain_scan")}
                className={`px-4 py-2 text-xs font-mono font-bold rounded-t-md transition-colors ${
                  caseModalTab === "domain_scan"
                    ? "bg-signal text-base-bg"
                    : "text-ink-muted hover:text-ink bg-base-bg"
                }`}
              >
                🌐 Domain Intelligence Scanner
              </button>
              <button
                onClick={() => setCaseModalTab("settings")}
                className={`px-4 py-2 text-xs font-mono font-bold rounded-t-md transition-colors ${
                  caseModalTab === "settings"
                    ? "bg-signal text-base-bg"
                    : "text-ink-muted hover:text-ink bg-base-bg"
                }`}
              >
                ⚙️ Case Settings & Metadata
              </button>
            </div>

            {/* TAB CONTENT 1: DOMAIN INTELLIGENCE MODULE */}
            {caseModalTab === "domain_scan" && (
              <DomainIntelModule
                investigationId={selectedCase.id}
                onScanComplete={() => fetchData()}
              />
            )}

            {/* TAB CONTENT 2: CASE SETTINGS */}
            {caseModalTab === "settings" && (
              <div className="space-y-4">
                <div>
                  <label className="block text-xs font-mono text-ink-muted mb-1">Status</label>
                  <select
                    value={editStatus}
                    onChange={(e) => setEditStatus(e.target.value)}
                    className="w-full px-3 py-2 bg-base-bg border border-base-border rounded text-sm text-ink focus:border-signal"
                  >
                    <option value="active">active</option>
                    <option value="archived">archived</option>
                    <option value="closed">closed</option>
                  </select>
                </div>

                <div>
                  <label className="block text-xs font-mono text-ink-muted mb-1">Description</label>
                  <textarea
                    rows={3}
                    value={editDesc}
                    onChange={(e) => setEditDesc(e.target.value)}
                    className="w-full px-3 py-2 bg-base-bg border border-base-border rounded text-sm text-ink focus:border-signal"
                  />
                </div>

                <div>
                  <label className="block text-xs font-mono text-ink-muted mb-1">Tags (comma separated)</label>
                  <input
                    type="text"
                    value={editTagsInput}
                    onChange={(e) => setEditTagsInput(e.target.value)}
                    className="w-full px-3 py-2 bg-base-bg border border-base-border rounded text-sm text-ink focus:border-signal"
                  />
                </div>

                <div className="bg-base-bg p-3 rounded border border-base-border text-xs font-mono space-y-1">
                  <p className="text-ink-muted">Created: <span className="text-ink">{new Date(selectedCase.created_at).toLocaleString()}</span></p>
                  <p className="text-ink-muted">Created By: <span className="text-ink">{selectedCase.created_by}</span></p>
                  <p className="text-ink-muted">Findings recorded: <span className="text-signal">{selectedCase.findings_count || 0}</span></p>
                </div>

                <div className="flex items-center justify-between pt-4 border-t border-base-border">
                  <button
                    type="button"
                    onClick={() => handleDeleteCase(selectedCase.id)}
                    className="px-3 py-2 bg-risk-critical/15 text-risk-critical border border-risk-critical/30 rounded font-mono text-xs hover:bg-risk-critical/25"
                  >
                    Delete Case
                  </button>

                  <div className="flex gap-3">
                    <button
                      type="button"
                      onClick={() => setSelectedCase(null)}
                      className="px-4 py-2 border border-base-border text-ink-muted font-mono text-xs rounded hover:text-ink"
                    >
                      Close
                    </button>
                    <button
                      type="button"
                      onClick={handleUpdateCase}
                      disabled={editSubmitting}
                      className="px-4 py-2 bg-signal text-base-bg font-mono text-xs font-bold rounded hover:bg-signal-dim"
                    >
                      {editSubmitting ? "Saving..." : "Save Changes"}
                    </button>
                  </div>
                </div>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
