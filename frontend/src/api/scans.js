import client from './client';

export const listScans = (domainId) =>
  client.get('/scans', { params: domainId ? { domain_id: domainId } : {} }).then((r) => r.data);
export const createScan = (domainId, scanners = null) =>
  client.post('/scans', { domain_id: domainId, scanners }).then((r) => r.data);
export const getScan = (id) => client.get(`/scans/${id}`).then((r) => r.data);
export const cancelScan = (id) => client.post(`/scans/${id}/cancel`).then((r) => r.data);