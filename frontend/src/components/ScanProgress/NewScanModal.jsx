import { useState, useEffect } from 'react';
import toast from 'react-hot-toast';
import { listDomains, createDomain } from '../../api/domains';
import { createScan } from '../../api/scans';
import ScannerSelector from './ScannerSelector';

export default function NewScanModal({ onClose, onScanCreated }) {
  const [domains, setDomains] = useState([]);
  const [domainId, setDomainId] = useState('');
  const [newDomain, setNewDomain] = useState('');
  const [scanners, setScanners] = useState(null); // null = all
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    listDomains().then(setDomains).catch(() => toast.error('Failed to load domains'));
  }, []);

  const handleAddDomain = async () => {
    if (!newDomain.trim()) return;
    try {
      const domain = await createDomain(newDomain.trim());
      setDomains((prev) => [domain, ...prev]);
      setDomainId(domain.id);
      setNewDomain('');
    } catch {
      toast.error('Failed to add domain');
    }
  };

  const handleSubmit = async () => {
    if (!domainId) return toast.error('Select a domain');
    setLoading(true);
    try {
      const scan = await createScan(Number(domainId), scanners);
      toast.success('Scan started');
      onScanCreated(scan);
      onClose();
    } catch {
      toast.error('Failed to start scan');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50 px-4">
      <div className="w-full max-w-md bg-bg-surface border border-bg-border rounded-lg p-6">
        <h2 className="text-lg font-semibold text-zinc-100 mb-4">New Scan</h2>

        <div className="space-y-4">
          <div>
            <label className="text-xs text-zinc-500 mb-1 block">Domain</label>
            <select
              value={domainId}
              onChange={(e) => setDomainId(e.target.value)}
              className="w-full bg-bg-elevated border border-bg-border rounded-md px-3 py-2 text-sm outline-none focus:border-accent"
            >
              <option value="">Select a domain</option>
              {domains.map((d) => (
                <option key={d.id} value={d.id}>{d.name}</option>
              ))}
            </select>
          </div>

          <div className="flex gap-2">
            <input
              value={newDomain}
              onChange={(e) => setNewDomain(e.target.value)}
              placeholder="Or add a new domain..."
              className="flex-1 bg-bg-elevated border border-bg-border rounded-md px-3 py-2 text-sm outline-none focus:border-accent"
            />
            <button
              type="button"
              onClick={handleAddDomain}
              className="px-3 py-2 text-sm rounded-md border border-bg-border hover:border-accent/50 transition-colors"
            >
              Add
            </button>
          </div>

          <ScannerSelector selected={scanners} onChange={setScanners} />
        </div>

        <div className="flex justify-end gap-2 mt-6">
          <button onClick={onClose} className="px-4 py-2 text-sm text-zinc-400 hover:text-zinc-200">
            Cancel
          </button>
          <button
            onClick={handleSubmit}
            disabled={loading}
            className="px-4 py-2 text-sm bg-accent text-bg font-medium rounded-md hover:bg-accent/90 disabled:opacity-50"
          >
            {loading ? 'Starting...' : 'Start Scan'}
          </button>
        </div>
      </div>
    </div>
  );
}