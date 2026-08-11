import { useState } from "react";
import { Link, useNavigate, useLocation } from "react-router-dom";
import { useAuth } from "../contexts/AuthContext";

export default function Login() {
  const navigate = useNavigate();
  const location = useLocation();
  const { login } = useAuth();

  const [usernameOrEmail, setUsernameOrEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [isSubmitting, setIsSubmitting] = useState(false);

  const from = location.state?.from?.pathname || "/dashboard";

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!usernameOrEmail || !password) {
      setError("Please fill in all fields.");
      return;
    }

    setError("");
    setIsSubmitting(true);

    try {
      await login(usernameOrEmail, password);
      navigate(from, { replace: true });
    } catch (err) {
      const msg = err.response?.data?.detail || "Authentication failed. Please check your credentials.";
      setError(msg);
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <div className="max-w-md mx-auto px-6 py-24">
      <div className="bg-base-surface border border-base-border rounded-lg p-8 shadow-xl">
        <div className="flex items-center gap-3 mb-6">
          <div className="w-3 h-3 rounded-full bg-signal animate-pulse" />
          <h1 className="text-2xl font-mono font-semibold text-ink">Sign in</h1>
        </div>

        {error && (
          <div className="mb-6 p-3 bg-risk-critical/10 border border-risk-critical/30 rounded text-risk-critical text-sm font-mono">
            ⚠️ {error}
          </div>
        )}

        <form onSubmit={handleSubmit} className="space-y-5">
          <div>
            <label htmlFor="usernameOrEmail" className="block text-sm text-ink-muted mb-1.5 font-mono">
              Username or Email
            </label>
            <input
              id="usernameOrEmail"
              type="text"
              required
              value={usernameOrEmail}
              onChange={(e) => setUsernameOrEmail(e.target.value)}
              placeholder="analyst@osintx.local"
              className="w-full px-3.5 py-2.5 bg-base-bg border border-base-border rounded-md text-ink placeholder:text-ink-muted/50 focus:border-signal transition-colors font-sans"
            />
          </div>

          <div>
            <label htmlFor="password" className="block text-sm text-ink-muted mb-1.5 font-mono">
              Password
            </label>
            <input
              id="password"
              type="password"
              required
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="••••••••"
              className="w-full px-3.5 py-2.5 bg-base-bg border border-base-border rounded-md text-ink placeholder:text-ink-muted/50 focus:border-signal transition-colors font-sans"
            />
          </div>

          <button
            type="submit"
            disabled={isSubmitting}
            className="w-full py-3 bg-signal text-base-bg font-mono font-medium rounded-md hover:bg-signal-dim transition-colors disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center gap-2"
          >
            {isSubmitting ? (
              <>
                <svg className="animate-spin h-4 w-4 text-base-bg" viewBox="0 0 24 24">
                  <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" fill="none" />
                  <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
                </svg>
                Authenticating...
              </>
            ) : (
              "Sign in"
            )}
          </button>
        </form>

        <div className="mt-6 pt-6 border-t border-base-border flex items-center justify-between text-sm">
          <span className="text-ink-muted">Need an account?</span>
          <Link to="/register" className="text-signal hover:text-signal-dim font-medium transition-colors">
            Create analyst account →
          </Link>
        </div>
      </div>
    </div>
  );
}