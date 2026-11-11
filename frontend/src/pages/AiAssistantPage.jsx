import { useState, useEffect, useRef } from "react";
import MainLayout from "../layouts/MainLayout";
import { getAiHealth, naturalLanguageSearch, correlateIocs, aiChat } from "../services/aiService";
import { getInvestigations } from "../services/api";

export default function AiAssistantPage() {
  const [health, setHealth] = useState(null);
  const [loadingHealth, setLoadingHealth] = useState(true);
  const [nlQuery, setNlQuery] = useState("");
  const [searchResults, setSearchResults] = useState(null);
  const [searching, setSearching] = useState(false);
  const [searchError, setSearchError] = useState(null);

  const [investigations, setInvestigations] = useState([]);
  const [selectedCaseId, setSelectedCaseId] = useState("");
  const [correlationData, setCorrelationData] = useState(null);
  const [correlating, setCorrelating] = useState(false);

  // AI Chat state
  const [chatMessages, setChatMessages] = useState([
    {
      role: "assistant",
      content:
        "👋 Hi! I'm OSINT-X AI, your local intelligence analyst assistant. I can help you:\n\n" +
        "• Interpret investigation findings and IOCs\n" +
        "• Suggest next analytical steps\n" +
        "• Explain threat intelligence concepts\n" +
        "• Assist with OSINT methodology\n\n" +
        "Optionally select an active investigation case to anchor my responses to live data. How can I help?",
    },
  ]);
  const [chatInput, setChatInput] = useState("");
  const [chatLoading, setChatLoading] = useState(false);
  const [chatCaseId, setChatCaseId] = useState("");
  const [chatError, setChatError] = useState(null);
  const chatEndRef = useRef(null);
  const chatInputRef = useRef(null);

  useEffect(() => {
    fetchHealth();
    fetchCaseList();
  }, []);

  // Auto-scroll chat to latest message
  useEffect(() => {
    chatEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [chatMessages, chatLoading]);

  const fetchHealth = async () => {
    try {
      const res = await getAiHealth();
      setHealth(res);
    } catch {
      setHealth({ status: "fallback_mode", available: false, ollama_model: "llama3:8b (offline fallback)" });
    } finally {
      setLoadingHealth(false);
    }
  };

  const fetchCaseList = async () => {
    try {
      const res = await getInvestigations();
      setInvestigations(res);
      if (res.length > 0) setSelectedCaseId(res[0].id);
    } catch {
      // ignore
    }
  };

  const handleNlSearch = async (e) => {
    e.preventDefault();
    if (!nlQuery.trim()) return;
    setSearching(true);
    setSearchError(null);
    try {
      const res = await naturalLanguageSearch(nlQuery);
      setSearchResults(res);
    } catch (err) {
      setSearchError(err.response?.data?.detail || "Search failed.");
    } finally {
      setSearching(false);
    }
  };

  const handleCorrelate = async () => {
    if (!selectedCaseId) return;
    setCorrelating(true);
    try {
      const res = await correlateIocs(selectedCaseId);
      setCorrelationData(res);
    } catch {
      setCorrelationData({ correlations: [] });
    } finally {
      setCorrelating(false);
    }
  };

  const handleChatSubmit = async (e) => {
    e.preventDefault();
    const msg = chatInput.trim();
    if (!msg || chatLoading) return;

    // Append user message immediately
    const userMsg = { role: "user", content: msg };
    const updatedHistory = [...chatMessages, userMsg];
    setChatMessages(updatedHistory);
    setChatInput("");
    setChatLoading(true);
    setChatError(null);

    try {
      // Send only the last 10 messages as history (skip the initial greeting)
      const historyToSend = updatedHistory.slice(1, -1).slice(-10);
      const res = await aiChat(msg, chatCaseId || null, historyToSend);
      setChatMessages((prev) => [
        ...prev,
        {
          role: "assistant",
          content: res.reply || "No response received.",
          offline_fallback: res.offline_fallback,
          model_used: res.model_used,
        },
      ]);
    } catch (err) {
      setChatError(err.response?.data?.detail || "AI response failed. Please try again.");
      setChatMessages((prev) => [
        ...prev,
        {
          role: "assistant",
          content: "⚠️ I encountered an error processing your request. Please try again.",
          error: true,
        },
      ]);
    } finally {
      setChatLoading(false);
      chatInputRef.current?.focus();
    }
  };

  const handleChatKeyDown = (e) => {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      handleChatSubmit(e);
    }
  };

  const clearChat = () => {
    setChatMessages([
      {
        role: "assistant",
        content:
          "Chat cleared. What would you like to investigate next?",
      },
    ]);
    setChatError(null);
  };

  return (
    <MainLayout>
      <div className="max-w-7xl mx-auto px-6 py-8 space-y-8">
        {/* Header Banner */}
        <div className="bg-base-surface border border-base-border rounded-xl p-6 shadow-sm">
          <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
            <div>
              <div className="flex items-center gap-2 mb-1">
                <span className="w-3 h-3 rounded-full bg-signal inline-block animate-pulse" />
                <h1 className="text-xl font-bold font-mono tracking-tight text-ink">
                  Local AI Investigation Assistant
                </h1>
              </div>
              <p className="text-xs font-mono text-ink-muted">
                Ollama REST API integration • 100% Local Inference • Zero API Keys Required • Rule-Based Core Safety
              </p>
            </div>

            <div className="flex items-center gap-3">
              {loadingHealth ? (
                <span className="text-xs font-mono text-ink-muted">Checking Ollama engine status...</span>
              ) : (
                <div className="px-3 py-1.5 bg-base-bg border border-base-border rounded text-xs font-mono flex items-center gap-2">
                  <span
                    className={`w-2 h-2 rounded-full ${
                      health?.available ? "bg-emerald-500" : "bg-amber-500"
                    }`}
                  />
                  <span>
                    Status: <strong className="text-ink">{health?.available ? "Ollama Connected" : "Simulation Fallback"}</strong>
                  </span>
                </div>
              )}
            </div>
          </div>
        </div>

        {/* Grid Container */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
          {/* Section 1: Natural Language Search */}
          <div className="bg-base-surface border border-base-border rounded-xl p-6 shadow-sm flex flex-col justify-between">
            <div>
              <h2 className="text-sm font-bold font-mono text-ink mb-1 flex items-center gap-2">
                <span className="text-signal">#</span> Natural Language Case Query
              </h2>
              <p className="text-xs font-mono text-ink-muted mb-4">
                Ask in natural language to search and filter active or archived investigation cases.
              </p>

              <form onSubmit={handleNlSearch} className="flex gap-2 mb-4">
                <input
                  type="text"
                  value={nlQuery}
                  onChange={(e) => setNlQuery(e.target.value)}
                  placeholder="e.g. active phishing cases with domain findings..."
                  className="flex-1 px-3 py-2 bg-base-bg border border-base-border rounded text-xs font-mono text-ink focus:outline-none focus:border-signal"
                />
                <button
                  type="submit"
                  disabled={searching}
                  className="px-4 py-2 bg-signal text-base-bg font-mono font-medium text-xs rounded hover:bg-signal-dim transition-colors disabled:opacity-50"
                >
                  {searching ? "Searching..." : "Execute Query"}
                </button>
              </form>

              {searchError && (
                <div className="p-3 bg-risk-critical/10 border border-risk-critical/30 text-risk-critical rounded text-xs font-mono mb-3">
                  {searchError}
                </div>
              )}

              {searchResults && (
                <div className="space-y-3 font-mono text-xs">
                  <div className="p-2.5 bg-base-bg border border-base-border rounded flex justify-between text-ink-muted">
                    <span>Query: <strong className="text-ink">"{searchResults.raw_query}"</strong></span>
                    <span>Matches: <strong className="text-signal">{searchResults.total_matches}</strong></span>
                  </div>

                  {searchResults.matches.length > 0 ? (
                    <div className="space-y-2 max-h-60 overflow-y-auto pr-1">
                      {searchResults.matches.map((item) => (
                        <div key={item.id} className="p-3 bg-base-bg border border-base-border rounded flex justify-between items-center">
                          <div>
                            <div className="font-bold text-ink">{item.title}</div>
                            <div className="text-[11px] text-ink-muted">Status: {item.status}</div>
                          </div>
                          <span className="px-2 py-0.5 bg-base-surface border border-base-border rounded text-[10px] text-signal font-mono">
                            ID: {item.id.slice(0, 8)}...
                          </span>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <div className="p-4 text-center text-ink-muted text-xs bg-base-bg rounded border border-base-border">
                      No matching cases found for this query.
                    </div>
                  )}
                </div>
              )}
            </div>
          </div>

          {/* Section 2: Cross-Investigation IOC Correlation Explorer */}
          <div className="bg-base-surface border border-base-border rounded-xl p-6 shadow-sm flex flex-col justify-between">
            <div>
              <h2 className="text-sm font-bold font-mono text-ink mb-1 flex items-center gap-2">
                <span className="text-signal">#</span> Cross-Case IOC Correlation
              </h2>
              <p className="text-xs font-mono text-ink-muted mb-4">
                Analyze cross-case overlapping IPs, domains, hashes, and tags across all investigations.
              </p>

              <div className="flex gap-2 mb-4">
                <select
                  value={selectedCaseId}
                  onChange={(e) => setSelectedCaseId(e.target.value)}
                  className="flex-1 px-3 py-2 bg-base-bg border border-base-border rounded text-xs font-mono text-ink focus:outline-none focus:border-signal"
                >
                  {investigations.length > 0 ? (
                    investigations.map((inv) => (
                      <option key={inv.id} value={inv.id}>
                        {inv.title} ({inv.status})
                      </option>
                    ))
                  ) : (
                    <option value="">No cases available</option>
                  )}
                </select>

                <button
                  onClick={handleCorrelate}
                  disabled={correlating || !selectedCaseId}
                  className="px-4 py-2 bg-signal text-base-bg font-mono font-medium text-xs rounded hover:bg-signal-dim transition-colors disabled:opacity-50"
                >
                  {correlating ? "Analyzing..." : "Correlate Case"}
                </button>
              </div>

              {correlationData && (
                <div className="space-y-3 font-mono text-xs">
                  <div className="p-2.5 bg-base-bg border border-base-border rounded flex justify-between text-ink-muted">
                    <span>Correlations Detected</span>
                    <span className="text-signal font-bold">{correlationData.total_correlations_found}</span>
                  </div>

                  {correlationData.correlations.length > 0 ? (
                    <div className="space-y-2 max-h-60 overflow-y-auto pr-1">
                      {correlationData.correlations.map((corr, idx) => (
                        <div key={idx} className="p-3 bg-base-bg border border-base-border rounded">
                          <div className="flex justify-between items-center mb-1">
                            <span className="font-bold text-ink">{corr.target_investigation_title}</span>
                            <span className="px-2 py-0.5 bg-signal/20 text-signal rounded text-[10px] font-bold">
                              {corr.confidence} CONFIDENCE
                            </span>
                          </div>
                          <div className="text-[11px] text-ink-muted">
                            Type: {corr.correlation_type} | Shared: {corr.matched_values.join(", ")}
                          </div>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <div className="p-4 text-center text-ink-muted text-xs bg-base-bg rounded border border-base-border">
                      No cross-investigation IOC or tag correlations detected for this case.
                    </div>
                  )}
                </div>
              )}
            </div>
          </div>
        </div>

        {/* AI Chat Section */}
        <div className="bg-base-surface border border-base-border rounded-xl shadow-sm flex flex-col" style={{ minHeight: "520px" }}>
          {/* Chat Header */}
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 p-5 border-b border-base-border">
            <div>
              <h2 className="text-sm font-bold font-mono text-ink flex items-center gap-2">
                <span className="text-signal text-base">🤖</span>
                AI Investigation Chat
                <span className="px-1.5 py-0.5 bg-signal/20 text-signal rounded text-[10px] font-mono font-bold border border-signal/30">
                  OSINT-X AI
                </span>
              </h2>
              <p className="text-xs font-mono text-ink-muted mt-0.5">
                Ask anything about OSINT, threat analysis, or your investigation findings. Press <kbd className="px-1 py-0.5 bg-base-bg border border-base-border rounded text-[10px]">Enter</kbd> to send.
              </p>
            </div>
            <div className="flex items-center gap-2 flex-shrink-0">
              {/* Case context selector */}
              <select
                value={chatCaseId}
                onChange={(e) => setChatCaseId(e.target.value)}
                className="px-2 py-1.5 bg-base-bg border border-base-border rounded text-xs font-mono text-ink focus:outline-none focus:border-signal max-w-[200px] truncate"
                title="Anchor AI to a specific investigation case"
              >
                <option value="">No case context</option>
                {investigations.map((inv) => (
                  <option key={inv.id} value={inv.id}>
                    📁 {inv.title}
                  </option>
                ))}
              </select>
              <button
                onClick={clearChat}
                className="px-2.5 py-1.5 bg-base-bg border border-base-border rounded text-xs font-mono text-ink-muted hover:text-ink hover:border-signal transition-colors"
                title="Clear chat history"
              >
                Clear
              </button>
            </div>
          </div>

          {/* Messages Area */}
          <div className="flex-1 overflow-y-auto p-4 space-y-4 font-mono text-xs" style={{ maxHeight: "400px" }}>
            {chatMessages.map((msg, idx) => (
              <div
                key={idx}
                className={`flex gap-3 ${msg.role === "user" ? "flex-row-reverse" : "flex-row"}`}
              >
                {/* Avatar */}
                <div
                  className={`flex-shrink-0 w-7 h-7 rounded-full flex items-center justify-center text-sm font-bold border ${
                    msg.role === "user"
                      ? "bg-signal/20 border-signal/40 text-signal"
                      : "bg-base-bg border-base-border text-ink-muted"
                  }`}
                >
                  {msg.role === "user" ? "U" : "AI"}
                </div>

                {/* Bubble */}
                <div
                  className={`max-w-[80%] rounded-xl px-4 py-3 leading-relaxed whitespace-pre-wrap ${
                    msg.role === "user"
                      ? "bg-signal/15 border border-signal/25 text-ink"
                      : msg.error
                      ? "bg-risk-critical/10 border border-risk-critical/30 text-risk-critical"
                      : "bg-base-bg border border-base-border text-ink"
                  }`}
                >
                  {msg.content}
                  {msg.offline_fallback && (
                    <div className="mt-2 pt-2 border-t border-base-border/50 text-[10px] text-amber-400 flex items-center gap-1">
                      <span>⚡</span> Offline fallback mode — Ollama not running locally
                    </div>
                  )}
                  {msg.model_used && !msg.offline_fallback && (
                    <div className="mt-2 pt-2 border-t border-base-border/50 text-[10px] text-ink-muted">
                      via {msg.model_used}
                    </div>
                  )}
                </div>
              </div>
            ))}

            {/* Typing Indicator */}
            {chatLoading && (
              <div className="flex gap-3 flex-row">
                <div className="flex-shrink-0 w-7 h-7 rounded-full bg-base-bg border border-base-border flex items-center justify-center text-sm font-bold text-ink-muted">
                  AI
                </div>
                <div className="bg-base-bg border border-base-border rounded-xl px-4 py-3 flex items-center gap-1.5">
                  <span className="w-1.5 h-1.5 bg-signal rounded-full animate-bounce" style={{ animationDelay: "0ms" }} />
                  <span className="w-1.5 h-1.5 bg-signal rounded-full animate-bounce" style={{ animationDelay: "150ms" }} />
                  <span className="w-1.5 h-1.5 bg-signal rounded-full animate-bounce" style={{ animationDelay: "300ms" }} />
                </div>
              </div>
            )}

            <div ref={chatEndRef} />
          </div>

          {/* Error banner */}
          {chatError && (
            <div className="mx-4 mb-2 p-2.5 bg-risk-critical/10 border border-risk-critical/30 text-risk-critical text-xs font-mono rounded-md">
              {chatError}
            </div>
          )}

          {/* Input Bar */}
          <div className="border-t border-base-border p-4">
            {chatCaseId && (
              <div className="mb-2 text-[11px] font-mono text-ink-muted flex items-center gap-1">
                <span className="text-signal">📁</span>
                <span>Case context: <strong className="text-ink">{investigations.find((i) => i.id === chatCaseId)?.title || chatCaseId}</strong></span>
              </div>
            )}
            <form onSubmit={handleChatSubmit} className="flex gap-2">
              <textarea
                ref={chatInputRef}
                value={chatInput}
                onChange={(e) => setChatInput(e.target.value)}
                onKeyDown={handleChatKeyDown}
                disabled={chatLoading}
                rows={1}
                placeholder={
                  chatLoading
                    ? "AI is thinking..."
                    : chatCaseId
                    ? "Ask about this investigation, IOCs, or any OSINT topic..."
                    : "Ask an OSINT question, e.g. 'How do I analyze a suspicious IP address?'"
                }
                className="flex-1 px-4 py-2.5 bg-base-bg border border-base-border rounded-lg text-xs font-mono text-ink placeholder:text-ink-muted/50 focus:outline-none focus:border-signal resize-none disabled:opacity-50 leading-relaxed"
                style={{ maxHeight: "120px", overflowY: "auto" }}
              />
              <button
                type="submit"
                disabled={chatLoading || !chatInput.trim()}
                className="px-5 py-2.5 bg-signal text-base-bg font-mono font-bold text-xs rounded-lg hover:bg-signal-dim transition-colors disabled:opacity-40 flex-shrink-0 flex items-center gap-2"
              >
                {chatLoading ? (
                  <div className="animate-spin h-4 w-4 border-2 border-base-bg border-t-transparent rounded-full" />
                ) : (
                  <span>Send ↑</span>
                )}
              </button>
            </form>
            <p className="mt-1.5 text-[10px] text-ink-muted font-mono">
              {health?.available
                ? `🟢 Ollama connected — ${health.ollama_model}`
                : "🟡 Offline mode — using local rule-based fallback responses"}
            </p>
          </div>
        </div>
      </div>
    </MainLayout>
  );
}
