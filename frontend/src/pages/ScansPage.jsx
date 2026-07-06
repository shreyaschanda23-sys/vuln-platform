import { useState, useEffect, useCallback } from 'react';
import toast from 'react-hot-toast';
import { LuPlus, LuX } from 'react-icons/lu';
import { listScans, cancelScan } from '../api/scans';
import NewScanModal from '../components/ScanProgress/NewScanModal';
import { useScanSocket } from '../hooks/useScanSocket';

const STAGE_LABELS = {
  asset_discovery: 'Asset Discovery', port_scan: 'Port Scan', live_hosts: 'Live Hosts',
  crawl: 'Crawling', vuln_scan: 'Vuln Scan', validation: 'Validation',
  enrichment: 'Enrichment', scoring: 'Scoring', complete: 'Complete',
};

const STATUS_STYLES = {
  pending: 'text-zinc-500 bg-zinc-500/10', running: 'text-accent bg-accent/10',
  complete: 'text-emerald-400 bg-emerald-400/10', failed: 'text-red-400 bg-red-400/10',
};

function ScanRow({ scan, onCancel }) {
  const live = useScanSocket(scan.status === 'running' || scan.status === 'pending' ? scan.id : null);
  const status = live?.status ?? scan.status;
  const stage = live?.current_stage ?? scan.current_stage;

  return (
    <tr className="border-b border-bg-border last:border-0 hover:bg-bg-elevated/50">
      <td className="px-4 py-3 font-mono text-zinc-300">#{scan.id}</td>
      <td className="px-4 py-3 text-zinc-300">{scan.domain_name}</td>
      <td className="px-4 py-3">
        <span className={`px-2 py-0.5 rounded-full text-xs font-medium ${STATUS_STYLES[status]}`}>{status}</span>
      </td>
      <td className="px-4 py-3 text-zinc-400">{stage ? STAGE_LABELS[stage] : '—'}</td>
      <td className="px-4 py-3 text-zinc-500">{new Date(scan.started_at + 'Z').toLocaleString()}</td>
      <td className="px-4 py-3 text-right">
        {(status === 'running' || status === 'pending') && (
          <button onClick={() => onCancel(scan.id)} className="text-zinc-500 hover:text-red-400 transition-colors">
            <LuX size={16} />
          </button>
        )}
      </td>
    </tr>
  );
}

export default function ScansPage() {
  const [scans, setScans] = useState([]);
  const [showModal, setShowModal] = useState(false);
  const [loading, setLoading] = useState(true);

  const load = useCallback(() => {
    listScans().then(setScans).catch(() => toast.error('Failed to load scans')).finally(() => setLoading(false));
  }, []);

  useEffect(() => { load(); }, [load]);

  const handleCancel = async (id) => {
    try {
      await cancelScan(id);
      toast.success('Scan cancelled');
      load();
    } catch {
      toast.error('Failed to cancel scan');
    }
  };

  return (
    <div>
      <div className="flex items-center justify-between mb-6">
        <h1 className="text-xl font-semibold text-zinc-100">Scans</h1>
        <button
          onClick={() => setShowModal(true)}
          className="flex items-center gap-2 bg-accent text-bg font-medium text-sm rounded-md px-4 py-2 hover:bg-accent/90 transition-colors"
        >
          <LuPlus size={16} />
          New Scan
        </button>
      </div>

      {loading ? (
        <div className="text-zinc-500 text-sm">Loading...</div>
      ) : scans.length === 0 ? (
        <div className="text-center py-20 text-zinc-500">
          <p>No scans yet. Start your first security assessment.</p>
        </div>
      ) : (
        <div className="bg-bg-surface border border-bg-border rounded-lg overflow-hidden">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-bg-border text-zinc-500 text-xs uppercase tracking-wide">
                <th className="text-left px-4 py-3 font-medium">Scan ID</th>
                <th className="text-left px-4 py-3 font-medium">Target</th>
                <th className="text-left px-4 py-3 font-medium">Status</th>
                <th className="text-left px-4 py-3 font-medium">Stage</th>
                <th className="text-left px-4 py-3 font-medium">Started</th>
                <th className="text-right px-4 py-3 font-medium">Actions</th>
              </tr>
            </thead>
            <tbody>
              {scans.map((scan) => (
                <ScanRow key={scan.id} scan={scan} onCancel={handleCancel} />
              ))}
            </tbody>
          </table>
        </div>
      )}

      {showModal && <NewScanModal onClose={() => setShowModal(false)} onScanCreated={load} />}
    </div>
  );
}