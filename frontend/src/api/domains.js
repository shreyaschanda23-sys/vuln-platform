import client from './client';

export const listDomains = () => client.get('/domains').then((r) => r.data);
export const createDomain = (name, description) =>
  client.post('/domains', { name, description }).then((r) => r.data);
export const deleteDomain = (id) => client.delete(`/domains/${id}`);