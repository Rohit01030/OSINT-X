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
            Cryptographic hashing (MD5, SHA-1, SHA-256), MIME inspection, and embedded EXIF metadata extraction
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
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
            <div className="bg-base-bg border border-base-border rounded-md p-3">
              <span className="text-[10px] font-mono text-ink-muted block uppercase">Filename</span>
              <span className="font-mono text-sm font-bold text-ink truncate block" title={scanResult.filename}>
                {scanResult.filename}
              </span>
            </div>
            <div className="bg-base-bg border border-base-border rounded-md p-3">
              <span className="text-[10px] font-mono text-ink-muted block uppercase">File Size</span>
              <span className="font-mono text-sm font-bold text-ink">
                {scanResult.file_size_human || `${scanResult.file_size_bytes} B`}
              </span>
            </div>
            <div className="bg-base-bg border border-base-border rounded-md p-3">
              <span className="text-[10px] font-mono text-ink-muted block uppercase">MIME Classification</span>
              <span className="font-mono text-xs font-bold text-signal truncate block" title={scanResult.mime_type}>
                {scanResult.mime_type || "application/octet-stream"}
              </span>
            </div>
            <div className="bg-base-bg border border-base-border rounded-md p-3">
              <span className="text-[10px] font-mono text-ink-muted block uppercase">EXIF Metadata</span>
              <span className={`inline-block px-2 py-0.5 text-xs font-mono font-bold rounded border mt-0.5 ${
                exif.has_exif
                  ? "bg-emerald-500/20 text-emerald-400 border-emerald-500/30"
                  : "bg-base-border text-ink-muted border-base-border"
              }`}>
                {exif.has_exif ? "EXIF Present" : "No EXIF"}
              </span>
            </div>
          </div>

          {/* Subtabs */}
          <div className="flex items-center gap-2 border-b border-base-border">
            {["summary", "hashes", "exif"].map((tab) => (
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
                <span className="text-ink-muted">Original File Name:</span>
                <span className="text-ink font-bold">{scanResult.filename}</span>
              </div>
              <div className="flex justify-between py-1 border-b border-base-border/50">
                <span className="text-ink-muted">File Size:</span>
                <span className="text-ink">{scanResult.file_size_human} ({scanResult.file_size_bytes} bytes)</span>
              </div>
              <div className="flex justify-between py-1 border-b border-base-border/50">
                <span className="text-ink-muted">Detected Type:</span>
                <span className="text-signal">{scanResult.mime_type}</span>
              </div>
              <div className="flex justify-between py-1">
                <span className="text-ink-muted">Analysis Timestamp:</span>
                <span className="text-ink">{scanResult.analyzed_at ? new Date(scanResult.analyzed_at).toLocaleString() : "Just now"}</span>
              </div>
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

          {/* TAB 3: EXIF FORENSICS */}
          {activeTab === "exif" && (
            <div className="space-y-3 font-mono text-xs">
              {!exif.has_exif ? (
                <div className="p-6 text-center bg-base-bg border border-base-border rounded-md text-ink-muted">
                  No EXIF or camera metadata headers embedded in this file artifact.
                </div>
              ) : (
                <div className="bg-base-bg border border-base-border rounded-md p-4 space-y-3">
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 pb-3 border-b border-base-border/50">
                    <div>
                      <span className="text-ink-muted block text-[10px]">Camera Make:</span>
                      <span className="text-ink font-bold">{exif.camera_make || "Unknown"}</span>
                    </div>
                    <div>
                      <span className="text-ink-muted block text-[10px]">Camera Model:</span>
                      <span className="text-ink font-bold">{exif.camera_model || "Unknown"}</span>
                    </div>
                    <div>
                      <span className="text-ink-muted block text-[10px]">Original Timestamp:</span>
                      <span className="text-ink">{exif.datetime_original || "N/A"}</span>
                    </div>
                    <div>
                      <span className="text-ink-muted block text-[10px]">GPS Coordinates:</span>
                      <span className="text-signal">{exif.gps_info ? JSON.stringify(exif.gps_info) : "None"}</span>
                    </div>
                  </div>

                  {exif.all_tags && Object.keys(exif.all_tags).length > 0 && (
                    <div className="space-y-2 pt-2">
                      <span className="font-bold text-ink block">All EXIF Header Tags</span>
                      <div className="max-h-60 overflow-y-auto space-y-1">
                        {Object.entries(exif.all_tags).map(([key, val]) => (
                          <div key={key} className="flex justify-between py-1 text-[11px] border-b border-base-border/30">
                            <span className="text-ink-muted">{key}</span>
                            <span className="text-ink truncate max-w-xs">{String(val)}</span>
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
      )}
    </div>
  );
}
