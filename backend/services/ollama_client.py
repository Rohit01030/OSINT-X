"""
Ollama Local REST API Client.

Communicates with Ollama running at OLLAMA_BASE_URL (http://localhost:11434 by default).
Operates with ZERO external API keys. If the local Ollama server is offline or unreachable,
it provides structured fallback simulation mode so the system remains 100% operational.
"""
import logging
import httpx
from typing import Dict, Any, Optional
from core.config import settings

logger = logging.getLogger(__name__)


class OllamaClient:
    def __init__(self, base_url: str = None, model: str = None):
        self.base_url = (base_url or settings.OLLAMA_BASE_URL).rstrip("/")
        self.model = model or settings.OLLAMA_MODEL

    def is_available(self) -> bool:
        """Pings local Ollama service to check availability."""
        try:
            with httpx.Client(timeout=2.0) as client:
                res = client.get(f"{self.base_url}/api/tags")
                return res.status_code == 200
        except Exception:
            return False

    def generate(self, prompt: str, system_prompt: Optional[str] = None) -> Dict[str, Any]:
        """
        Sends generation request to local Ollama instance.
        Falls back to local structured template if service is unreachable.
        Uses a generous timeout: 5s to connect, 120s to read (model cold-start can be slow).
        """
        payload = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
        }
        if system_prompt:
            payload["system"] = system_prompt

        # connect=5s (server must respond quickly), read=120s (generation can take time)
        timeout = httpx.Timeout(connect=5.0, read=120.0, write=10.0, pool=5.0)

        try:
            with httpx.Client(timeout=timeout) as client:
                response = client.post(f"{self.base_url}/api/generate", json=payload)
                if response.status_code == 200:
                    data = response.json()
                    return {
                        "status": "success",
                        "model": self.model,
                        "response": data.get("response", ""),
                        "offline_fallback": False,
                    }
                else:
                    logger.warning("Ollama returned unexpected status %s", response.status_code)
        except httpx.ConnectError as e:
            logger.info("Ollama server not reachable (%s). Using fallback.", e)
        except httpx.ReadTimeout:
            logger.warning("Ollama generation timed out after 120s. Using fallback.")
        except Exception as e:
            logger.info("Ollama error (%s). Using local rule-based fallback response.", e)

        # Fallback generator if Ollama is offline
        return {
            "status": "success",
            "model": f"{self.model} (fallback-mode)",
            "response": self._generate_fallback_response(prompt),
            "offline_fallback": True,
        }

    def _generate_fallback_response(self, prompt: str) -> str:
        """Structured fallback response generator for offline execution.

        Covers all common OSINT-X AI chat patterns with professional, context-aware
        responses so the assistant remains useful even when Ollama is offline.
        """
        p = prompt.lower()

        # --- Analytical steps / next steps / recommendations ---
        if any(w in p for w in ["suggest", "next step", "analytical step", "what should", "recommendation", "what to do", "advise", "advice"]):
            return (
                "**Recommended Next Analytical Steps (Rule-Based Engine):**\n\n"
                "1. **Domain Reconnaissance** — Run passive DNS enumeration (A, MX, NS, TXT records) "
                "and check SSL certificate transparency logs (crt.sh) for subdomains.\n"
                "2. **IP Reputation Analysis** — Query AbuseIPDB and VirusTotal for the resolved IPs. "
                "Cross-reference against Shodan for exposed services and banners.\n"
                "3. **Email Threat Surface** — Verify SPF/DMARC/DKIM configurations. Check the "
                "domain's mail servers against known spam blacklists (MXToolbox, Spamhaus).\n"
                "4. **IOC Correlation** — Use the Cross-Case IOC Correlation tool to identify whether "
                "any findings appear in other active investigations.\n"
                "5. **MITRE ATT&CK Mapping** — Review the automatically generated technique mapping "
                "to understand adversary TTPs associated with the collected indicators.\n"
                "6. **Generate Intelligence Report** — Compile all findings into a TLP:AMBER "
                "classified intelligence report for SOC or stakeholder review.\n\n"
                "> *Start Ollama locally (`ollama serve`) to get AI-powered, case-specific recommendations.*"
            )

        # --- Summarize / overview / brief ---
        elif any(w in p for w in ["summarize", "summary", "overview", "brief", "tldr", "tl;dr"]):
            return (
                "**Executive Summary (Local AI Engine):**\n\n"
                "Investigation intelligence modules have processed available network indicators, "
                "threat scores, and associated IOCs. Review the **Findings** panel for all recorded "
                "observations. Prioritize findings marked **HIGH** or **CRITICAL** severity for "
                "immediate remediation action.\n\n"
                "Key areas to review:\n"
                "- Risk Score breakdown in the Intelligence Report\n"
                "- Open ports and exposed service banners\n"
                "- Threat Intelligence reputation flags\n"
                "- MITRE ATT&CK technique mappings\n\n"
                "> *Start Ollama locally for a case-specific AI-generated summary.*"
            )

        # --- Risk / score / threat level ---
        elif any(w in p for w in ["risk", "score", "threat level", "dangerous", "severity", "critical"]):
            return (
                "**Risk Assessment (Local AI Engine):**\n\n"
                "The computed risk score reflects deterministic evaluation of:\n"
                "- **Open Services** — Exposed ports and service versions\n"
                "- **Threat Intelligence Flags** — AbuseIPDB confidence score, VirusTotal detections\n"
                "- **Confirmed Malicious Indicators** — Blacklist occurrences, known bad hashes\n\n"
                "**Scoring thresholds:**\n"
                "- `0.0 – 3.9` → Low risk\n"
                "- `4.0 – 6.9` → Medium risk\n"
                "- `7.0 – 8.9` → High risk\n"
                "- `9.0 – 10.0` → Critical — immediate action required\n\n"
                "Review the Risk Score breakdown in the Intelligence Report for per-factor contribution."
            )

        # --- IOC / indicator / hash / malware analysis ---
        elif any(w in p for w in ["ioc", "indicator", "hash", "malware", "artifact", "file hash", "sha256", "md5"]):
            return (
                "**IOC Analysis Guidance (Local AI Engine):**\n\n"
                "To investigate an Indicator of Compromise:\n"
                "1. **Hash** — Run it through the **File Analysis** module; SHA-256 is cross-referenced "
                "against VirusTotal for known malware families.\n"
                "2. **IP Address** — Use the **IP Intelligence** module; checks AbuseIPDB confidence, "
                "ASN ownership, geolocation, and open ports via Shodan.\n"
                "3. **Domain** — Use the **Domain Intelligence** module; checks WHOIS, DNS records, "
                "SSL certificate, and passive DNS history.\n"
                "4. **Cross-Case Correlation** — Use the IOC Correlation tool to identify if the same "
                "indicator appears in multiple active investigations.\n\n"
                "High-confidence malicious IOCs should be escalated to your SOC ticketing system immediately."
            )

        # --- MITRE ATT&CK / TTP / technique / tactic ---
        elif any(w in p for w in ["mitre", "att&ck", "attack", "technique", "tactic", "ttp", "kill chain"]):
            return (
                "**MITRE ATT&CK Guidance (Local AI Engine):**\n\n"
                "OSINT-X maps findings to the **MITRE ATT&CK Enterprise** framework automatically.\n\n"
                "**Entry types:**\n"
                "- `TOOL_COLLECTION_ACTIVITY` — Reflects OSINT-X's own reconnaissance actions "
                "(e.g., DNS lookup = T1590.002, WHOIS = T1590.001)\n"
                "- `OBSERVED_ADVERSARY_BEHAVIOR` — Confirmed threat actor activity inferred from "
                "findings (e.g., exposed RDP = T1021.001, phishing domain = T1566)\n\n"
                "**Recommended focus:** Prioritize remediation for **Observed Adversary Behavior** "
                "entries first. Review each technique ID on [attack.mitre.org](https://attack.mitre.org) "
                "for detailed detection and mitigation guidance."
            )

        # --- IP address analysis ---
        elif any(w in p for w in ["ip address", "ip intel", "geolocation", "asn", "autonomous system", "shodan"]):
            return (
                "**IP Intelligence Guidance (Local AI Engine):**\n\n"
                "IP analysis includes:\n"
                "- **Geolocation** — Country, city, latitude/longitude\n"
                "- **ASN Ownership** — Internet service provider and network block\n"
                "- **Open Ports** — Exposed services detected via active scanning\n"
                "- **Reputation** — AbuseIPDB confidence score (>50% = suspicious, >80% = malicious)\n"
                "- **VirusTotal** — Detections across 90+ AV engines\n\n"
                "High AbuseIPDB scores combined with open administrative ports (22, 3389, 445) "
                "indicate a high-priority threat requiring immediate investigation."
            )

        # --- Domain / DNS analysis ---
        elif any(w in p for w in ["domain", "dns", "whois", "subdomain", "ssl", "certificate"]):
            return (
                "**Domain Intelligence Guidance (Local AI Engine):**\n\n"
                "Domain analysis covers:\n"
                "- **WHOIS** — Registrar, registrant, registration/expiry dates\n"
                "- **DNS Records** — A, AAAA, MX, NS, TXT, CNAME resolution\n"
                "- **SSL Certificate** — Issuer, validity, SANs for subdomain enumeration\n"
                "- **Passive DNS** — Historical resolutions to identify IP churn\n"
                "- **Reputation** — VirusTotal URL/domain scan results\n\n"
                "Newly registered domains (<30 days) with privacy-protected WHOIS and "
                "free SSL certificates are strong phishing indicators."
            )

        # --- Email analysis ---
        elif any(w in p for w in ["email", "phishing", "spf", "dmarc", "dkim", "mail"]):
            return (
                "**Email Intelligence Guidance (Local AI Engine):**\n\n"
                "Email investigation covers:\n"
                "- **Header Analysis** — Originating IP, relay chain, spoofing indicators\n"
                "- **SPF/DMARC/DKIM** — Email authentication policy validation\n"
                "- **Domain Reputation** — Sender domain cross-referenced against threat intel\n"
                "- **Blacklist Check** — MX record IPs checked against spam blacklists\n\n"
                "Missing or failing SPF/DMARC records on a sender domain is a strong indicator "
                "of a spoofed or malicious email."
            )

        # --- Explain / help / what is ---
        elif any(w in p for w in ["explain", "what is", "how does", "what does", "help me understand", "tell me about", "describe"]):
            return (
                "**OSINT-X Knowledge Base (Local AI Engine):**\n\n"
                "OSINT-X is a **Cyber Threat Intelligence** platform combining passive and active "
                "reconnaissance modules:\n\n"
                "| Module | Purpose |\n"
                "|---|---|\n"
                "| **Domain Intel** | WHOIS, DNS, SSL, subdomain enumeration |\n"
                "| **IP Intel** | Geolocation, ASN, open ports, reputation |\n"
                "| **Email Intel** | Header analysis, SPF/DMARC, blacklist |\n"
                "| **Username Intel** | Social media presence, breach exposure |\n"
                "| **File Analysis** | EXIF, hashes, MIME detection, VirusTotal |\n"
                "| **Threat Intel** | VirusTotal + AbuseIPDB reputation scoring |\n"
                "| **IOC Analysis** | Cross-case indicator correlation |\n"
                "| **MITRE ATT&CK** | Automatic TTP mapping to findings |\n\n"
                "All findings are stored per investigation case and compiled into TLP-classified "
                "intelligence reports."
            )

        # --- Report / export ---
        elif any(w in p for w in ["report", "export", "generate report", "intelligence report", "pdf"]):
            return (
                "**Intelligence Report Guidance (Local AI Engine):**\n\n"
                "To generate an intelligence report:\n"
                "1. Navigate to the **Reports** tab\n"
                "2. Select the investigation case\n"
                "3. Choose format: **JSON** (machine-readable) or **HTML** (analyst-friendly)\n"
                "4. The report includes: executive summary, risk score breakdown, all findings, "
                "MITRE ATT&CK matrix, and IOC list\n\n"
                "Reports are automatically classified at **TLP:AMBER** — handle accordingly."
            )

        # --- Search / filter ---
        elif any(w in p for w in ["search", "filter", "find case", "look for", "query"]):
            return (
                "**Natural Language Search (Local AI Engine):**\n\n"
                "Use the **Natural Language Search** panel to filter investigation cases. "
                "You can query by: target, risk score threshold, date range, finding type, or module.\n\n"
                "Example queries:\n"
                "- *\"Show high-risk investigations from last week\"*\n"
                "- *\"Find cases with malicious IP findings\"*\n"
                "- *\"List investigations targeting .ru domains\"*"
            )

        # --- Generic fallback ---
        else:
            return (
                "**OSINT-X AI Assistant (Offline Mode):**\n\n"
                "I'm currently running in **offline rule-based fallback mode** as Ollama is not "
                "available locally. I can still help with:\n\n"
                "- 🔍 **Analytical step suggestions** — Ask \"Suggest next steps\"\n"
                "- ⚠️ **Risk interpretation** — Ask \"Explain the risk score\"\n"
                "- 🦠 **IOC & malware guidance** — Ask about hashes, IPs, or domains\n"
                "- 🛡️ **MITRE ATT&CK explanations** — Ask about techniques or TTPs\n"
                "- 📋 **Investigation methodology** — Ask \"How do I investigate a phishing domain?\"\n"
                "- 📊 **Report generation** — Ask \"How do I generate a report?\"\n\n"
                "Start Ollama locally (`ollama serve`) to enable full AI-powered contextual analysis."
            )


ollama_client = OllamaClient()
