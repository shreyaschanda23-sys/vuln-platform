import client from './client';

export const listFindings = (params) => client.get('/findings', { params }).then((r) => r.data);
export const updateFinding = (id, payload) => client.patch(`/findings/${id}`, payload).then((r) => r.data);