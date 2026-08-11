import api from "./api";

export async function generateReport(investigationId, format = "json") {
  const response = await api.post("/api/reports/generate", {
    investigation_id: investigationId,
    format,
  }, {
    responseType: format === "csv" ? "blob" : "json"
  });
  return response.data;
}

export async function listInvestigationReports(investigationId) {
  const response = await api.get(`/api/reports/investigation/${investigationId}`);
  return response.data;
}

export async function downloadReportDetails(reportId) {
  const response = await api.get(`/api/reports/download/${reportId}`);
  return response.data;
}
