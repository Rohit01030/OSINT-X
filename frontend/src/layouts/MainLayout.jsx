import { Link, useLocation } from "react-router-dom";

const NAV_LINKS = [
  { label: "Dashboard", to: "/dashboard" },
  { label: "Login", to: "/login" },
  { label: "Register", to: "/register" },
];

export default function MainLayout({ children }) {
  const location = useLocation();

  return (
    <div className="min-h-screen flex flex-col">
      <header className="border-b border-base-border bg-base-surface">
        <div className="max-w-6xl mx-auto px-6 h-16 flex items-center justify-between">
          <Link to="/" className="font-mono text-lg font-semibold text-ink tracking-tight">
            OSINT<span className="text-signal">-X</span>
          </Link>

          <nav className="flex items-center gap-6">
            {NAV_LINKS.map((link) => {
              const isActive = location.pathname === link.to;
              return (
                <Link
                  key={link.to}
                  to={link.to}
                  className={
                    isActive
                      ? "text-signal font-medium"
                      : "text-ink-muted hover:text-ink transition-colors"
                  }
                >
                  {link.label}
                </Link>
              );
            })}
          </nav>
        </div>
      </header>

      <main className="flex-1">{children}</main>

      <footer className="border-t border-base-border py-6">
        <div className="max-w-6xl mx-auto px-6 text-sm text-ink-muted font-mono">
          OSINT-X — for authorized, educational, and professional use only.
        </div>
      </footer>
    </div>
  );
}