import api from "./api";

export async function getAiHealth() {
  const response = await api.get("/api/ai/health");
  return response.data;
}

export async function summarizeInvestigation(investigationId) {
  const response = await api.post("/api/ai/summarize", {
    investigation_id: investigationId,
  });
  return response.data;
}

export async function explainRiskScore(investigationId) {
  const response = await api.post("/api/ai/risk-explain", {
    investigation_id: investigationId,
  });
  return response.data;
}

export async function correlateIocs(investigationId) {
  const response = await api.post("/api/ai/correlate-iocs", {
    investigation_id: investigationId,
  });
  return response.data;
}

export async function getMitreAttackMapping(investigationId) {
  const response = await api.get(`/api/ai/attack-mapping/${investigationId}`);
  return response.data;
}

export async function naturalLanguageSearch(query) {
  const response = await api.post("/api/ai/nl-search", { query });
  return response.data;
}

export async function aiChat(message, investigationId = null, history = []) {
  const response = await api.post("/api/ai/chat", {
    message,
    investigation_id: investigationId || null,
    history,
  });
  return response.data;
}
