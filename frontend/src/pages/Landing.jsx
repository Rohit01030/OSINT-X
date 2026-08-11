import { Link } from "react-router-dom";

const CAPABILITIES = [
  { label: "Domain", detail: "WHOIS, DNS, SSL, subdomains" },
  { label: "IP", detail: "GeoIP, ASN, reputation, blacklists" },
  { label: "Identity", detail: "Email, username, file metadata" },
  { label: "Threat Intel", detail: "VirusTotal, AbuseIPDB, Shodan" },
];

export default function Landing() {
  return (
    <div className="max-w-6xl mx-auto px-6">
      <section className="py-24 md:py-32 border-b border-base-border">
        <p className="font-mono text-sm text-signal mb-4">
          $ osint-x --init investigation
        </p>
        <h1 className="text-4xl md:text-6xl font-mono font-semibold text-ink leading-tight max-w-3xl">
          Open-source intelligence,
          <br />
          one investigation at a time.
        </h1>
        <p className="mt-6 text-lg text-ink-muted max-w-xl">
          Domain, IP, and identity intelligence with threat-feed correlation
          and a local AI assistant — no data leaves your machine unless you
          send it there.
        </p>

        <div className="mt-10 flex items-center gap-4">
          <Link
            to="/register"
            className="px-5 py-3 bg-signal text-base-bg font-medium rounded-md hover:bg-signal-dim transition-colors"
          >
            Start an investigation
          </Link>
          <Link
            to="/login"
            className="px-5 py-3 border border-base-border text-ink font-medium rounded-md hover:border-signal transition-colors"
          >
            Sign in
          </Link>
        </div>
      </section>

      <section className="py-16 grid grid-cols-2 md:grid-cols-4 gap-px bg-base-border">
        {CAPABILITIES.map((cap) => (
          <div key={cap.label} className="bg-base-bg p-6">
            <p className="font-mono text-sm text-signal mb-2">{cap.label}</p>
            <p className="text-sm text-ink-muted">{cap.detail}</p>
          </div>
        ))}
      </section>
    </div>
  );
}