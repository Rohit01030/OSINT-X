import { Link } from "react-router-dom";

export default function NotFound() {
  return (
    <div className="max-w-md mx-auto px-6 py-32 text-center">
      <h1 className="text-6xl font-mono font-bold text-signal mb-4">404</h1>
      <h2 className="text-xl font-mono text-ink mb-2">Target route not found</h2>
      <p className="text-sm text-ink-muted mb-8">
        The requested resource or page does not exist in this OSINT workspace.
      </p>

      <Link
        to="/dashboard"
        className="inline-block px-5 py-2.5 bg-signal text-base-bg font-mono text-sm font-medium rounded-md hover:bg-signal-dim transition-colors"
      >
        Return to Dashboard →
      </Link>
    </div>
  );
}
