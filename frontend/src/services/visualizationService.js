import api from "./api";

export async function getRelationshipGraph(investigationId) {
  const response = await api.get(`/api/visualization/relationship-graph/${investigationId}`);
  return response.data;
}

export async function getTimeline(investigationId) {
  const response = await api.get(`/api/visualization/timeline/${investigationId}`);
  return response.data;
}

export async function getGeoMap(investigationId) {
  const response = await api.get(`/api/visualization/geo-map/${investigationId}`);
  return response.data;
}

export async function getChartMetrics(investigationId) {
  const response = await api.get(`/api/visualization/metrics/${investigationId}`);
  return response.data;
}
