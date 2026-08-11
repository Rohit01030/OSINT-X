import { Link, useLocation, useNavigate } from "react-router-dom";
import { useAuth } from "../contexts/AuthContext";

export default function MainLayout({ children }) {
  const location = useLocation();
  const navigate = useNavigate();
  const { user, logout } = useAuth();

  const handleLogout = () => {
    logout();
    navigate("/login");
  };

  return (
    <div className="min-h-screen flex flex-col bg-base-bg text-ink">
      <header className="border-b border-base-border bg-base-surface sticky top-0 z-40">
        <div className="max-w-7xl mx-auto px-6 h-16 flex items-center justify-between">
          <Link to="/" className="font-mono text-xl font-bold text-ink tracking-tight flex items-center gap-2">
            <span className="w-2.5 h-2.5 rounded-full bg-signal inline-block" />
            OSINT<span className="text-signal">-X</span>
          </Link>

          <nav className="flex items-center gap-6">
            <Link
              to="/dashboard"
              className={
                location.pathname === "/dashboard"
                  ? "text-signal font-mono font-medium text-sm"
                  : "text-ink-muted hover:text-ink font-mono text-sm transition-colors"
              }
            >
              Dashboard
            </Link>

            {user ? (
              <div className="flex items-center gap-4 border-l border-base-border pl-6">
                <span className="text-xs font-mono text-ink-muted hidden sm:inline">
                  <strong className="text-ink">{user.username}</strong> ({user.role})
                </span>
                <button
                  onClick={handleLogout}
                  className="px-3 py-1.5 border border-base-border text-ink-muted hover:text-risk-critical hover:border-risk-critical/40 text-xs font-mono rounded transition-colors"
                >
                  Logout
                </button>
              </div>
            ) : (
              <div className="flex items-center gap-3 border-l border-base-border pl-6">
                <Link
                  to="/login"
                  className={
                    location.pathname === "/login"
                      ? "text-signal font-mono font-medium text-sm"
                      : "text-ink-muted hover:text-ink font-mono text-sm transition-colors"
                  }
                >
                  Sign in
                </Link>
                <Link
                  to="/register"
                  className="px-3 py-1.5 bg-signal text-base-bg font-mono font-medium text-xs rounded hover:bg-signal-dim transition-colors"
                >
                  Register
                </Link>
              </div>
            )}
          </nav>
        </div>
      </header>

      <main className="flex-1">{children}</main>

      <footer className="border-t border-base-border py-6 bg-base-surface/50">
        <div className="max-w-7xl mx-auto px-6 flex flex-col md:flex-row items-center justify-between text-xs text-ink-muted font-mono gap-2">
          <div>OSINT-X — Security-First Open Source Intelligence Platform.</div>
          <div>Authorized use only.</div>
        </div>
      </footer>
    </div>
  );
}