import api from "./api";

export async function getAuditLogs(skip = 0, limit = 50, action = null) {
  const params = { skip, limit };
  if (action) params.action = action;
  const response = await api.get("/api/audit/logs", { params });
  return response.data;
}

export async function getAuditStats() {
  const response = await api.get("/api/audit/stats");
  return response.data;
}
