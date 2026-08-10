import { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { useAuth } from "../contexts/AuthContext";

export default function Register() {
  const navigate = useNavigate();
  const { register } = useAuth();

  const [username, setUsername] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [error, setError] = useState("");
  const [isSubmitting, setIsSubmitting] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!username || !email || !password || !confirmPassword) {
      setError("Please fill in all fields.");
      return;
    }

    if (username.length < 3) {
      setError("Username must be at least 3 characters long.");
      return;
    }

    if (password.length < 8) {
      setError("Password must be at least 8 characters long.");
      return;
    }

    if (password !== confirmPassword) {
      setError("Passwords do not match.");
      return;
    }

    setError("");
    setIsSubmitting(true);

    try {
      await register(username, email, password);
      navigate("/dashboard", { replace: true });
    } catch (err) {
      const msg = err.response?.data?.detail || "Registration failed. Please check your inputs.";
      setError(msg);
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <div className="max-w-md mx-auto px-6 py-20">
      <div className="bg-base-surface border border-base-border rounded-lg p-8 shadow-xl">
        <div className="flex items-center gap-3 mb-6">
          <div className="w-3 h-3 rounded-full bg-signal animate-pulse" />
          <h1 className="text-2xl font-mono font-semibold text-ink">Create Analyst Account</h1>
        </div>

        {error && (
          <div className="mb-6 p-3 bg-risk-critical/10 border border-risk-critical/30 rounded text-risk-critical text-sm font-mono">
            ⚠️ {error}
          </div>
        )}

        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label htmlFor="username" className="block text-sm text-ink-muted mb-1 font-mono">
              Username
            </label>
            <input
              id="username"
              type="text"
              required
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              placeholder="analyst_01"
              className="w-full px-3.5 py-2.5 bg-base-bg border border-base-border rounded-md text-ink placeholder:text-ink-muted/50 focus:border-signal transition-colors font-sans"
            />
          </div>

          <div>
            <label htmlFor="email" className="block text-sm text-ink-muted mb-1 font-mono">
              Email Address
            </label>
            <input
              id="email"
              type="email"
              required
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              placeholder="analyst@osintx.local"
              className="w-full px-3.5 py-2.5 bg-base-bg border border-base-border rounded-md text-ink placeholder:text-ink-muted/50 focus:border-signal transition-colors font-sans"
            />
          </div>

          <div>
            <label htmlFor="password" className="block text-sm text-ink-muted mb-1 font-mono">
              Password (min 8 characters)
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

          <div>
            <label htmlFor="confirmPassword" className="block text-sm text-ink-muted mb-1 font-mono">
              Confirm Password
            </label>
            <input
              id="confirmPassword"
              type="password"
              required
              value={confirmPassword}
              onChange={(e) => setConfirmPassword(e.target.value)}
              placeholder="••••••••"
              className="w-full px-3.5 py-2.5 bg-base-bg border border-base-border rounded-md text-ink placeholder:text-ink-muted/50 focus:border-signal transition-colors font-sans"
            />
          </div>

          <button
            type="submit"
            disabled={isSubmitting}
            className="w-full mt-2 py-3 bg-signal text-base-bg font-mono font-medium rounded-md hover:bg-signal-dim transition-colors disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center gap-2"
          >
            {isSubmitting ? (
              <>
                <svg className="animate-spin h-4 w-4 text-base-bg" viewBox="0 0 24 24">
                  <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" fill="none" />
                  <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
                </svg>
                Creating Account...
              </>
            ) : (
              "Create Account"
            )}
          </button>
        </form>

        <div className="mt-6 pt-6 border-t border-base-border flex items-center justify-between text-sm">
          <span className="text-ink-muted">Already registered?</span>
          <Link to="/login" className="text-signal hover:text-signal-dim font-medium transition-colors">
            Sign in →
          </Link>
        </div>
      </div>
    </div>
  );
}