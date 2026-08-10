import axios from "axios";

const API_BASE_URL = import.meta.env.VITE_API_URL || "http://localhost:8000";

const api = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    "Content-Type": "application/json",
  },
});

// Interceptor to attach Bearer token if available
api.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem("osintx_token");
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  },
  (error) => Promise.reject(error)
);

// Authentication Endpoints
export async function registerUser(userData) {
  const response = await api.post("/api/auth/register", userData);
  return response.data;
}

export async function loginUser(credentials) {
  const response = await api.post("/api/auth/login", credentials);
  return response.data;
}

export async function getCurrentUser() {
  const response = await api.get("/api/auth/me");
  return response.data;
}

// Investigation Endpoints
export async function getDashboardSummary() {
  const response = await api.get("/api/investigations/dashboard");
  return response.data;
}

export async function getInvestigations(params = {}) {
  const response = await api.get("/api/investigations", { params });
  return response.data;
}

export async function getInvestigationById(id) {
  const response = await api.get(`/api/investigations/${id}`);
  return response.data;
}

export async function createInvestigation(data) {
  const response = await api.post("/api/investigations", data);
  return response.data;
}

export async function updateInvestigation(id, data) {
  const response = await api.put(`/api/investigations/${id}`, data);
  return response.data;
}

export async function deleteInvestigation(id) {
  const response = await api.delete(`/api/investigations/${id}`);
  return response.data;
}

// Domain Intelligence Endpoints
export async function analyzeDomain(investigationId, target) {
  const response = await api.post("/api/domain/analyze", {
    investigation_id: investigationId,
    target,
  });
  return response.data;
}

export async function getDomainWhois(domain) {
  const response = await api.get("/api/domain/whois", { params: { domain } });
  return response.data;
}

export async function getDomainDns(domain) {
  const response = await api.get("/api/domain/dns", { params: { domain } });
  return response.data;
}

export async function getDomainSsl(domain) {
  const response = await api.get("/api/domain/ssl", { params: { domain } });
  return response.data;
}

export async function getDomainHeaders(domain) {
  const response = await api.get("/api/domain/headers", { params: { domain } });
  return response.data;
}

export async function getDomainSubdomains(domain) {
  const response = await api.get("/api/domain/subdomains", { params: { domain } });
  return response.data;
}

export default api;
