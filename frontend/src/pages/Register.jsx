export default function Register() {
  return (
    <div className="max-w-md mx-auto px-6 py-24">
      <h1 className="text-2xl font-mono font-semibold text-ink mb-2">Create an account</h1>
      <p className="text-sm text-ink-muted mb-8">
        Registration isn't wired up yet — this is a placeholder screen.
      </p>

      <form className="space-y-4">
        <div>
          <label htmlFor="username" className="block text-sm text-ink-muted mb-1">
            Username
          </label>
          <input
            id="username"
            type="text"
            disabled
            placeholder="analyst_01"
            className="w-full px-3 py-2 bg-base-surface border border-base-border rounded-md text-ink placeholder:text-ink-muted/60 disabled:opacity-50"
          />
        </div>

        <div>
          <label htmlFor="email" className="block text-sm text-ink-muted mb-1">
            Email
          </label>
          <input
            id="email"
            type="email"
            disabled
            placeholder="you@example.com"
            className="w-full px-3 py-2 bg-base-surface border border-base-border rounded-md text-ink placeholder:text-ink-muted/60 disabled:opacity-50"
          />
        </div>

        <div>
          <label htmlFor="password" className="block text-sm text-ink-muted mb-1">
            Password
          </label>
          <input
            id="password"
            type="password"
            disabled
            placeholder="••••••••"
            className="w-full px-3 py-2 bg-base-surface border border-base-border rounded-md text-ink placeholder:text-ink-muted/60 disabled:opacity-50"
          />
        </div>

        <button
          type="button"
          disabled
          className="w-full py-2.5 bg-signal text-base-bg font-medium rounded-md opacity-50 cursor-not-allowed"
        >
          Create account (coming in Step 7)
        </button>
      </form>

      <p className="mt-6 text-sm text-ink-muted">
        Already have an account?{" "}
        <a href="/login" className="text-signal hover:text-signal-dim">
          Sign in
        </a>
      </p>
    </div>
  );
}