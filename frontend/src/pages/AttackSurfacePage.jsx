import { useState, useEffect } from 'react';
import { listDomains } from '../api/domains';
import client from '../api/client';

export default function AttackSurfacePage() {
  const [domains, setDomains] = useState([]);
  const [domainId, setDomainId] = useState('');
  const [assets, setAssets] = useState(null);

  useEffect(() => { listDomains().then(setDomains); }, []);

  useEffect(() => {
    if (!domainId) return setAssets(null);
    client.get(`/domains/${domainId}/assets`).then((r) => setAssets(r.data));
  }, [domainId]);

  return (
    <div>
      <h1 className="text-xl font-semibold text-zinc-100 mb-6">Attack Surface</h1>

      <select
        value={domainId}
        onChange={(e) => setDomainId(e.target.value)}
        className="bg-bg-elevated border border-bg-border rounded-md px-3 py-2 text-sm outline-none focus:border-accent mb-6"
      >
        <option value="">Select a domain</option>
        {domains.map((d) => <option key={d.id} value={d.id}>{d.name}</option>)}
      </select>

      {!assets ? (
        <div className="text-zinc-500 text-sm">Select a domain to view its attack surface.</div>
      ) : (
        <div className="grid grid-cols-3 gap-4">
          <div className="bg-bg-surface border border-bg-border rounded-lg p-4">
            <div className="text-sm font-medium text-zinc-300 mb-3">Subdomains ({assets.subdomains.length})</div>
            <div className="space-y-1 max-h-96 overflow-y-auto text-sm">
              {assets.subdomains.map((s, i) => (
                <div key={i} className="text-zinc-400 font-mono text-xs truncate">{s.name}</div>
              ))}
            </div>
          </div>
          <div className="bg-bg-surface border border-bg-border rounded-lg p-4">
            <div className="text-sm font-medium text-zinc-300 mb-3">Open Ports ({assets.ports.length})</div>
            <div className="space-y-1 max-h-96 overflow-y-auto text-sm">
              {assets.ports.map((p, i) => (
                <div key={i} className="text-zinc-400 font-mono text-xs">{p.host}:{p.port} {p.service || ''}</div>
              ))}
            </div>
          </div>
          <div className="bg-bg-surface border border-bg-border rounded-lg p-4">
            <div className="text-sm font-medium text-zinc-300 mb-3">Endpoints ({assets.endpoints.length})</div>
            <div className="space-y-1 max-h-96 overflow-y-auto text-sm">
              {assets.endpoints.map((e, i) => (
                <div key={i} className="text-zinc-400 text-xs truncate">
                  <span className="text-accent">{e.status_code}</span> {e.url}
                </div>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}