import { useState, useRef } from "react";
import { analyzeFile } from "../services/api";

export default function FileIntelModule({ investigationId, onScanComplete }) {
  const [file, setFile] = useState(null);
  const [scanning, setScanning] = useState(false);
  const [error, setError] = useState("");
  const [scanResult, setScanResult] = useState(null);
  const [copiedHash, setCopiedHash] = useState("");
  const [activeTab, setActiveTab] = useState("summary");
  const fileInputRef = useRef(null);

  const handleFileChange = (e) => {
    if (e.target.files && e.target.files[0]) {
      setFile(e.target.files[0]);
      setError("");
    }
  };

  const handleDrop = (e) => {
    e.preventDefault();
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      setFile(e.dataTransfer.files[0]);
      setError("");
    }
  };

  const handleUploadAndScan = async (e) => {
    e.preventDefault();
    if (!file) {
      setError("Please select or drop a file to analyze.");
      return;
    }

    setError("");
    setScanning(true);
    setScanResult(null);

    try {
      const data = await analyzeFile(investigationId, file);
      setScanResult(data);
      if (onScanComplete) onScanComplete(data);
    } catch (err) {
      console.error("File analysis error:", err);
      setError(err.response?.data?.detail || "File analysis failed. Please try a different file.");
    } finally {
      setScanning(false);
    }
  };

  const copyToClipboard = (text, type) => {
    navigator.clipboard.writeText(text);
    setCopiedHash(type);
    setTimeout(() => setCopiedHash(""), 2000);
  };

  const hashes = scanResult?.hashes || {};
  const exif = scanResult?.exif_metadata || {};
  const docForensics = scanResult?.document_forensics || {};
  const threatIntel = scanResult?.threat_intel || {};

  const getVerdictBadge = (verdict) => {
    switch (verdict) {
      case "malicious":
        return "bg-rose-500/20 text-rose-400 border-rose-500/30";
      case "suspicious":
        return "bg-amber-500/20 text-amber-400 border-amber-500/30";
      case "clean":
        return "bg-emerald-500/20 text-emerald-400 border-emerald-500/30";
      default:
        return "bg-base-border text-ink-muted border-base-border";
    }
  };

  return (
    <div className="bg-base-surface border border-base-border rounded-lg p-6 space-y-6">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-base-border pb-6">
        <div>
          <div className="flex items-center gap-2">
            <span className="text-signal text-xl">📁</span>
            <h3 className="font-mono text-lg font-bold text-ink">File Analysis & EXIF Forensics</h3>
          </div>
          <p className="text-xs font-mono text-ink-muted mt-1">
            Cryptographic hashing (MD5, SHA-1, SHA-256), MIME inspection, embedded EXIF & GPS geolocation, and threat reputation
          </p>
        </div>
      </div>

      {/* File Dropzone */}
      <form onSubmit={handleUploadAndScan} className="space-y-4">
        <div
          onDragOver={(e) => e.preventDefault()}
          onDrop={handleDrop}
          onClick={() => fileInputRef.current?.click()}
          className="border-2 border-dashed border-base-border hover:border-signal/50 bg-base-bg rounded-lg p-8 text-center cursor-pointer transition-colors"
        >
          <input
            ref={fileInputRef}
            type="file"
            onChange={handleFileChange}
            disabled={scanning}
            className="hidden"
          />
          <span className="text-3xl mb-2 block">📄</span>
          {file ? (
            <div className="font-mono text-sm">
              <span className="text-signal font-bold">{file.name}</span>
              <span className="text-ink-muted text-xs block mt-1">
                {(file.size / 1024).toFixed(1)} KB — Click or drop to replace
              </span>
            </div>
          ) : (
            <div className="font-mono text-xs text-ink-muted">
              <p className="text-ink font-semibold mb-1">Click to browse or drop an artifact here</p>
              <p className="text-[11px]">Supports images, executables, documents, archives</p>
            </div>
          )}
        </div>

        <div className="flex justify-end">
          <button
            type="submit"
            disabled={!file || scanning}
            className="px-6 py-2.5 bg-signal text-base-bg font-mono text-xs font-bold rounded-md hover:bg-signal-dim transition-colors disabled:opacity-50 flex items-center gap-2"
          >
            {scanning ? (
              <>
                <div className="animate-spin h-4 w-4 border-2 border-base-bg border-t-transparent rounded-full" />
                <span>Extracting Artifact Forensics...</span>
              </>
            ) : (
              <span>Analyze File</span>
            )}
          </button>
        </div>
      </form>

      {error && (
        <div className="p-4 bg-risk-critical/10 border border-risk-critical/30 text-risk-critical text-xs font-mono rounded-md">
          {error}
        </div>
      )}

      {/* Results Display */}
      {scanResult && (
        <div className="space-y-6 pt-2">
          {/* Metric Cards */}
          <div className="grid grid-cols-2 sm:grid-cols-5 gap-3">
            <div className="bg-base-bg border border-base-border rounded-md p-3">
              <span className="text-[10px] font-mono text-ink-muted block uppercase">Filename</span>
              <span className="font-mono text-sm font-bold text-ink truncate block" title={scanResult.filename || scanResult.target}>
                {scanResult.filename || scanResult.target}
              </span>
            </div>
            <div className="bg-base-bg border border-base-border rounded-md p-3">
              <span className="text-[10px] font-mono text-ink-muted block uppercase">File Size</span>
              <span className="font-mono text-sm font-bold text-ink">
                {scanResult.file_size_human || `${scanResult.file_size_bytes} B`}
              </span>
            </div>
            <div className="bg-base-bg border border-base-border rounded-md p-3">
              <span className="text-[10px] font-mono text-ink-muted block uppercase">MIME Type</span>
              <span className="font-mono text-xs font-bold text-signal truncate block" title={scanResult.mime_type}>
                {scanResult.mime_type || "application/octet-stream"}
              </span>
            </div>
            <div className="bg-base-bg border border-base-border rounded-md p-3">
              <span className="text-[10px] font-mono text-ink-muted block uppercase">EXIF Forensics</span>
              <span className={`inline-block px-2 py-0.5 text-xs font-mono font-bold rounded border mt-0.5 ${
                exif.has_exif
                  ? "bg-emerald-500/20 text-emerald-400 border-emerald-500/30"
                  : "bg-base-border text-ink-muted border-base-border"
              }`}>
                {exif.has_exif ? "EXIF Present" : "No EXIF"}
              </span>
            </div>
            <div className="bg-base-bg border border-base-border rounded-md p-3">
              <span className="text-[10px] font-mono text-ink-muted block uppercase">Threat Verdict</span>
              <span className={`inline-block px-2 py-0.5 text-xs font-mono font-bold rounded border uppercase mt-0.5 ${
                getVerdictBadge(threatIntel.verdict)
              }`}>
                {threatIntel.verdict || "Clean"}
              </span>
            </div>
          </div>

          {/* Subtabs */}
          <div className="flex items-center gap-2 border-b border-base-border overflow-x-auto pb-1">
            {[
              { id: "summary", label: "Summary" },
              { id: "hashes", label: "Cryptographic Hashes" },
              { id: "exif", label: "EXIF & Geolocation" },
              { id: "threat", label: "Threat Intelligence" },
            ].map((tab) => (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={`px-3 py-1.5 text-xs font-mono uppercase tracking-wide border-b-2 -mb-px whitespace-nowrap transition-colors ${
                  activeTab === tab.id
                    ? "border-signal text-signal font-bold"
                    : "border-transparent text-ink-muted hover:text-ink"
                }`}
              >
                {tab.label}
              </button>
            ))}
          </div>

          {/* TAB 1: SUMMARY */}
          {activeTab === "summary" && (
            <div className="space-y-4">
              <div className="bg-base-bg border border-base-border rounded-md p-4 space-y-3 font-mono text-xs">
                <div className="flex justify-between py-1 border-b border-base-border/50">
                  <span className="text-ink-muted">Original File Name:</span>
                  <span className="text-ink font-bold">{scanResult.filename || scanResult.target}</span>
                </div>
                <div className="flex justify-between py-1 border-b border-base-border/50">
                  <span className="text-ink-muted">File Size:</span>
                  <span className="text-ink">{scanResult.file_size_human} ({scanResult.file_size_bytes} bytes)</span>
                </div>
                <div className="flex justify-between py-1 border-b border-base-border/50">
                  <span className="text-ink-muted">Detected MIME Type:</span>
                  <span className="text-signal font-bold">{scanResult.mime_type}</span>
                </div>
                {exif.dimensions && (
                  <div className="flex justify-between py-1 border-b border-base-border/50">
                    <span className="text-ink-muted">Image Dimensions:</span>
                    <span className="text-ink">{exif.dimensions} ({exif.format})</span>
                  </div>
                )}
                <div className="flex justify-between py-1">
                  <span className="text-ink-muted">Analysis Timestamp:</span>
                  <span className="text-ink">{scanResult.analyzed_at || scanResult.scanned_at ? new Date(scanResult.analyzed_at || scanResult.scanned_at).toLocaleString() : "Just now"}</span>
                </div>
              </div>

              {/* Document / Binary Forensics block if detected */}
              {docForensics && Object.keys(docForensics).length > 0 && (
                <div className="bg-base-bg border border-base-border rounded-md p-4 space-y-3 font-mono text-xs">
                  <span className="text-xs font-bold text-signal block uppercase">Artifact Header Forensics</span>
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 pt-1">
                    {Object.entries(docForensics).map(([key, val]) => (
                      <div key={key} className="py-1 border-b border-base-border/30">
                        <span className="text-ink-muted block text-[10px] uppercase">{key.replace(/_/g, " ")}:</span>
                        <span className="text-ink font-semibold">
                          {Array.isArray(val) ? val.join(", ") : String(val)}
                        </span>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}

          {/* TAB 2: CRYPTOGRAPHIC HASHES */}
          {activeTab === "hashes" && (
            <div className="space-y-3 font-mono text-xs">
              {["sha256", "sha1", "md5"].map((hType) => (
                <div key={hType} className="bg-base-bg border border-base-border rounded-md p-3.5 flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                  <div className="flex-1 min-w-0">
                    <span className="text-[10px] text-signal font-bold uppercase block">{hType.toUpperCase()}</span>
                    <span className="text-ink font-bold break-all text-xs">{hashes[hType] || "N/A"}</span>
                  </div>
                  <button
                    onClick={() => copyToClipboard(hashes[hType], hType)}
                    className="px-3 py-1.5 bg-base-surface border border-base-border hover:border-signal/50 text-ink-muted hover:text-ink rounded text-[11px] self-start sm:self-center shrink-0"
                  >
                    {copiedHash === hType ? "✓ Copied" : "Copy Hash"}
                  </button>
                </div>
              ))}
            </div>
          )}

          {/* TAB 3: EXIF FORENSICS & GEOLOCATION */}
          {activeTab === "exif" && (
            <div className="space-y-4 font-mono text-xs">
              {!exif.has_exif ? (
                <div className="p-8 text-center bg-base-bg border border-base-border rounded-md text-ink-muted">
                  No EXIF or camera metadata headers embedded in this file artifact.
                </div>
              ) : (
                <div className="space-y-4">
                  <div className="bg-base-bg border border-base-border rounded-md p-4 space-y-4">
                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 pb-3 border-b border-base-border/50">
                      <div>
                        <span className="text-ink-muted block text-[10px]">Camera Make:</span>
                        <span className="text-ink font-bold">{exif.camera_make || "Unknown / Not recorded"}</span>
                      </div>
                      <div>
                        <span className="text-ink-muted block text-[10px]">Camera Model:</span>
                        <span className="text-ink font-bold">{exif.camera_model || "Unknown / Not recorded"}</span>
                      </div>
                      <div>
                        <span className="text-ink-muted block text-[10px]">Capture Timestamp:</span>
                        <span className="text-ink">{exif.datetime_original || "N/A"}</span>
                      </div>
                      <div>
                        <span className="text-ink-muted block text-[10px]">Software / Editor:</span>
                        <span className="text-ink">{exif.software || "Not specified"}</span>
                      </div>
                    </div>

                    {/* Geolocation Section */}
                    {exif.gps_info ? (
                      <div className="p-3 bg-base-surface border border-signal/30 rounded space-y-2">
                        <div className="flex items-center gap-2">
                          <span className="text-signal">📍</span>
                          <span className="font-bold text-signal">Embedded GPS Geolocation Coordinates</span>
                        </div>
                        <div className="flex flex-wrap items-center justify-between gap-3 pt-1">
                          <div>
                            <span className="text-ink font-mono font-bold block text-sm">
                              {exif.gps_info.coordinates_text || `${exif.gps_info.latitude}, ${exif.gps_info.longitude}`}
                            </span>
                            {exif.gps_info.altitude_m !== null && (
                              <span className="text-ink-muted text-[11px] block">
                                Altitude: {exif.gps_info.altitude_m} meters
                              </span>
                            )}
                          </div>
                          <div className="flex items-center gap-2">
                            {exif.gps_info.google_maps_url && (
                              <a
                                href={exif.gps_info.google_maps_url}
                                target="_blank"
                                rel="noreferrer"
                                className="px-3 py-1.5 bg-signal text-base-bg font-bold rounded text-xs hover:bg-signal-dim transition-colors inline-flex items-center gap-1"
                              >
                                Google Maps ↗
                              </a>
                            )}
                            {exif.gps_info.osm_url && (
                              <a
                                href={exif.gps_info.osm_url}
                                target="_blank"
                                rel="noreferrer"
                                className="px-3 py-1.5 bg-base-bg border border-base-border text-ink rounded text-xs hover:border-signal transition-colors inline-flex items-center gap-1"
                              >
                                OpenStreetMap ↗
                              </a>
                            )}
                          </div>
                        </div>
                      </div>
                    ) : (
                      <div className="p-3 bg-base-bg border border-base-border/50 rounded text-ink-muted text-[11px]">
                        ℹ️ No GPS coordinates were embedded in this image's EXIF data.
                      </div>
                    )}

                    {/* All Tags Collapsible / List */}
                    {exif.all_tags && Object.keys(exif.all_tags).length > 0 && (
                      <div className="space-y-2 pt-2">
                        <span className="font-bold text-ink block">All EXIF Header Tags ({Object.keys(exif.all_tags).length})</span>
                        <div className="max-h-60 overflow-y-auto space-y-1 pr-1">
                          {Object.entries(exif.all_tags).map(([key, val]) => (
                            <div key={key} className="flex justify-between py-1 text-[11px] border-b border-base-border/30">
                              <span className="text-ink-muted shrink-0 mr-2">{key}</span>
                              <span className="text-ink truncate text-right">{String(val)}</span>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                </div>
              )}
            </div>
          )}

          {/* TAB 4: THREAT INTELLIGENCE */}
          {activeTab === "threat" && (
            <div className="bg-base-bg border border-base-border rounded-md p-4 space-y-4 font-mono text-xs">
              <div className="flex items-center justify-between border-b border-base-border pb-3">
                <div>
                  <span className="text-ink-muted block text-[10px] uppercase">VirusTotal Detection Ratio</span>
                  <span className="text-ink font-bold text-base">
                    {threatIntel.detection_ratio || "0/0"} engines
                  </span>
                </div>
                <span className={`px-3 py-1 text-xs font-bold rounded border uppercase ${
                  getVerdictBadge(threatIntel.verdict)
                }`}>
                  {threatIntel.verdict || "Clean"}
                </span>
              </div>

              <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-center">
                <div className="bg-base-surface p-2.5 rounded border border-base-border">
                  <span className="text-[10px] text-rose-400 block uppercase font-bold">Malicious</span>
                  <span className="text-lg font-bold text-rose-400">{threatIntel.malicious_count || 0}</span>
                </div>
                <div className="bg-base-surface p-2.5 rounded border border-base-border">
                  <span className="text-[10px] text-amber-400 block uppercase font-bold">Suspicious</span>
                  <span className="text-lg font-bold text-amber-400">{threatIntel.suspicious_count || 0}</span>
                </div>
                <div className="bg-base-surface p-2.5 rounded border border-base-border">
                  <span className="text-[10px] text-emerald-400 block uppercase font-bold">Harmless</span>
                  <span className="text-lg font-bold text-emerald-400">{threatIntel.harmless_count || 0}</span>
                </div>
                <div className="bg-base-surface p-2.5 rounded border border-base-border">
                  <span className="text-[10px] text-ink-muted block uppercase font-bold">Undetected</span>
                  <span className="text-lg font-bold text-ink">{threatIntel.undetected_count || 0}</span>
                </div>
              </div>

              <div className="text-[11px] text-ink-muted pt-2 border-t border-base-border/50">
                <span>Queried Target Hash (SHA-256): </span>
                <span className="text-ink font-bold break-all">{hashes.sha256}</span>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
