import axios from 'axios';

const API_BASE_URL = 'http://localhost:8000';

const api = axios.create({
  baseURL: API_BASE_URL,
  timeout: 30000,
  headers: {
    'Content-Type': 'application/json',
  },
});

export const scanService = {
  getScans: () => api.get('/api/scans'),
  getScanById: (id) => api.get(`/api/scans/${id}`),
  createScan: (data) => api.post('/api/scans', data),
  getScanFindings: (id, category = '', severity = '') => {
    let url = `/api/scans/${id}/findings`;
    const params = [];
    if (category) params.push(`category=${category}`);
    if (severity) params.push(`severity=${severity}`);
    if (params.length > 0) url += `?${params.join('&')}`;
    return api.get(url);
  },
  getAiAdvisor: (id) => api.get(`/api/scans/${id}/ai-advisor`),
  deleteScan: (id) => api.delete(`/api/scans/${id}`),
};

export const reconService = {
  getEndpoints: (scanId) => api.get(`/api/recon/${scanId}/endpoints`),
  getSitemap: (scanId) => api.get(`/api/recon/${scanId}/sitemap`),
  getParameters: (scanId) => api.get(`/api/recon/${scanId}/parameters`),
};

export const scannerService = {
  getSqli: (scanId) => api.get(`/api/scanners/sqli${scanId ? `?scan_id=${scanId}` : ''}`),
  getXss: (scanId) => api.get(`/api/scanners/xss${scanId ? `?scan_id=${scanId}` : ''}`),
  getIdor: (scanId) => api.get(`/api/scanners/idor${scanId ? `?scan_id=${scanId}` : ''}`),
  getAuth: (scanId) => api.get(`/api/scanners/auth${scanId ? `?scan_id=${scanId}` : ''}`),
  getUpload: (scanId) => api.get(`/api/scanners/upload${scanId ? `?scan_id=${scanId}` : ''}`),
  getHeaders: (scanId) => api.get(`/api/scanners/headers${scanId ? `?scan_id=${scanId}` : ''}`),
  getExposure: (scanId) => api.get(`/api/scanners/exposure${scanId ? `?scan_id=${scanId}` : ''}`),
};

export const httpAnalyzerService = {
  getHistory: (scanId, limit = 50) => api.get(`/api/http-analyzer/history?limit=${limit}${scanId ? `&scan_id=${scanId}` : ''}`),
  replay: (data) => api.post('/api/http-analyzer/replay', data),
  decodeJwt: (token) => api.post('/api/http-analyzer/decode-jwt', { token }),
  compare: (body1, body2) => api.post('/api/http-analyzer/compare', { body1, body2 }),
};

export const sastService = {
  uploadProject: (formData) => api.post('/api/static-analysis/upload', formData, {
    headers: { 'Content-Type': 'multipart/form-data' },
  }),
};

export const intelService = {
  getVtDomain: (domain) => api.get(`/api/intelligence/virustotal/domain?domain=${domain}`),
  getVtUrl: (url) => api.get(`/api/intelligence/virustotal/url?target_url=${encodeURIComponent(url)}`),
  getVtHash: (hash) => api.get(`/api/intelligence/virustotal/hash?file_hash=${hash}`),
  getAbuseIp: (ip) => api.get(`/api/intelligence/abuseipdb?ip=${ip}`),
  getShodan: (ip) => api.get(`/api/intelligence/shodan?ip=${ip}`),
  getCves: (keyword) => api.get(`/api/intelligence/cve?keyword=${encodeURIComponent(keyword)}`),
  getWhoisDns: (target) => api.get(`/api/intelligence/whois-dns?target=${encodeURIComponent(target)}`),
};

export const reportService = {
  getPdfUrl: (scanId) => `${API_BASE_URL}/api/reports/pdf/${scanId}`,
  getJsonUrl: (scanId) => `${API_BASE_URL}/api/reports/json/${scanId}`,
};

export const settingsService = {
  getSettings: () => api.get('/api/settings'),
  updateSetting: (key, value, description = '') => api.post('/api/settings/update', { key, value, description }),
  deleteSetting: (key) => api.post(`/api/settings/delete/${key}`),
};

export default api;
