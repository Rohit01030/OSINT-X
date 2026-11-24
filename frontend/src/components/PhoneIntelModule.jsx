import { useState } from "react";
import { lookupPhone } from "../services/api";

export default function PhoneIntelModule({ investigationId, onScanComplete }) {
  const [phoneNumber, setPhoneNumber] = useState("");
  const [scanning, setScanning] = useState(false);
  const [error, setError] = useState("");
  const [scanResult, setScanResult] = useState(null);

  const handleRunScan = async (e) => {
    e.preventDefault();
    const cleaned = phoneNumber.trim();
    if (!cleaned) {
      setError("Please enter a valid phone number (e.g. +14158586273).");
      return;
    }

    setError("");
    setScanning(true);
    setScanResult(null);

    try {
      const data = await lookupPhone(cleaned);
      setScanResult(data);
      if (onScanComplete) onScanComplete(data);
    } catch (err) {
      console.error("Phone lookup error:", err);
      setError(
        err.response?.data?.detail ||
          "Phone lookup failed. Please verify the number and try again."
      );
    } finally {
      setScanning(false);
    }
  };

  return (
    <div className="bg-base-surface border border-base-border rounded-lg p-6 space-y-6">
      {/* Module Header & Input Form */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-base-border pb-6">
        <div>
          <div className="flex items-center gap-2">
            <span className="text-signal text-xl">📞</span>
            <h2 className="text-xl font-mono font-bold text-ink">
              Phone Intelligence Module
            </h2>
          </div>
          <p className="text-xs text-ink-muted mt-1 font-mono">
            Number validation, carrier lookup, line type, and geographic location.
          </p>
        </div>

        <form onSubmit={handleRunScan} className="flex items-center gap-2 max-w-md w-full">
          <input
            type="text"
            required
            placeholder="+14158586273"
            value={phoneNumber}
            onChange={(e) => setPhoneNumber(e.target.value)}
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
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <div className="bg-base-bg p-4 rounded border border-base-border">
              <span className="text-xs font-mono text-ink-muted uppercase">Validation</span>
              <p className="mt-2">
                {scanResult.valid ? (
                  <span className="px-2.5 py-1 text-xs font-mono font-bold rounded bg-risk-low/20 text-risk-low border border-risk-low/40">
                    Valid
                  </span>
                ) : (
                  <span className="px-2.5 py-1 text-xs font-mono font-bold rounded bg-risk-critical/20 text-risk-critical border border-risk-critical/40">
                    Invalid
                  </span>
                )}
              </p>
            </div>

            <div className="bg-base-bg p-4 rounded border border-base-border">
              <span className="text-xs font-mono text-ink-muted uppercase">Carrier</span>
              <p className="text-sm font-mono font-bold text-ink mt-2">
                {scanResult.carrier || "Unknown"}
              </p>
            </div>

            <div className="bg-base-bg p-4 rounded border border-base-border">
              <span className="text-xs font-mono text-ink-muted uppercase">Line Type</span>
              <p className="text-sm font-mono font-bold text-signal mt-2 uppercase">
                {scanResult.line_type || "N/A"}
              </p>
            </div>

            <div className="bg-base-bg p-4 rounded border border-base-border">
              <span className="text-xs font-mono text-ink-muted uppercase">Country</span>
              <p className="text-sm font-mono font-bold text-ink mt-2">
                {scanResult.country_name
                  ? `${scanResult.country_name} (${scanResult.country_code || ""})`
                  : "N/A"}
              </p>
            </div>
          </div>

          <div className="bg-base-bg p-5 rounded border border-base-border space-y-3 font-mono text-xs">
            <h3 className="text-sm font-bold text-signal uppercase border-b border-base-border pb-2">
              Phone Number Details
            </h3>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              <div className="flex justify-between bg-base-surface px-3 py-2 rounded border border-base-border">
                <span className="text-ink-muted">Input Number:</span>
                <span className="text-ink font-semibold">{scanResult.number || phoneNumber}</span>
              </div>
              <div className="flex justify-between bg-base-surface px-3 py-2 rounded border border-base-border">
                <span className="text-ink-muted">International Format:</span>
                <span className="text-signal">{scanResult.international_format || "N/A"}</span>
              </div>
              <div className="flex justify-between bg-base-surface px-3 py-2 rounded border border-base-border">
                <span className="text-ink-muted">Local Format:</span>
                <span className="text-ink">{scanResult.local_format || "N/A"}</span>
              </div>
              <div className="flex justify-between bg-base-surface px-3 py-2 rounded border border-base-border">
                <span className="text-ink-muted">Country Prefix:</span>
                <span className="text-ink">{scanResult.country_prefix || "N/A"}</span>
              </div>
              <div className="flex justify-between bg-base-surface px-3 py-2 rounded border border-base-border">
                <span className="text-ink-muted">Location / Region:</span>
                <span className="text-ink">{scanResult.location || "N/A"}</span>
              </div>
              <div className="flex justify-between bg-base-surface px-3 py-2 rounded border border-base-border">
                <span className="text-ink-muted">Investigation ID:</span>
                <span className="text-ink-muted">{investigationId ? investigationId.slice(0, 8) + "..." : "N/A"}</span>
              </div>
            </div>
            {scanResult.error && (
              <div className="p-2.5 bg-risk-critical/10 border border-risk-critical/30 text-risk-critical rounded">
                Error: {typeof scanResult.error === "string" ? scanResult.error : JSON.stringify(scanResult.error)}
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
