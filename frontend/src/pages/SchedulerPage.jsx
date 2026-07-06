import { useState, useEffect } from 'react';
import toast from 'react-hot-toast';
import { LuTrash2 } from 'react-icons/lu';
import client from '../api/client';
import { listDomains } from '../api/domains';

export default function SchedulerPage() {
  const [jobs, setJobs] = useState([]);
  const [domains, setDomains] = useState([]);
  const [domainId, setDomainId] = useState('');
  const [frequency, setFrequency] = useState('daily');
  const [loading, setLoading] = useState(false);

  const load = () => {
    client.get('/scheduler').then((r) => setJobs(r.data));
    listDomains().then(setDomains);
  };

  useEffect(() => { load(); }, []);

  const handleCreate = async () => {
    if (!domainId) return toast.error('Select a domain');
    setLoading(true);
    try {
      await client.post('/scheduler', { domain_id: Number(domainId), frequency });
      toast.success('Schedule created');
      load();
    } catch {
      toast.error('Failed to create schedule');
    } finally {
      setLoading(false);
    }
  };

  const handleDelete = async (jobId) => {
    try {
      await client.delete(`/scheduler/${jobId}`);
      toast.success('Schedule removed');
      load();
    } catch {
      toast.error('Failed to remove schedule');
    }
  };

  return (
    <div>
      <h1 className="text-xl font-semibold text-zinc-100 mb-6">Scheduler</h1>

      <div className="bg-bg-surface border border-bg-border rounded-lg p-4 mb-6 flex items-end gap-3">
        <div className="flex-1">
          <label className="text-xs text-zinc-500 mb-1 block">Domain</label>
          <select
            value={domainId}
            onChange={(e) => setDomainId(e.target.value)}
            className="w-full bg-bg-elevated border border-bg-border rounded-md px-3 py-2 text-sm outline-none focus:border-accent"
          >
            <option value="">Select a domain</option>
            {domains.map((d) => <option key={d.id} value={d.id}>{d.name}</option>)}
          </select>
        </div>
        <div>
          <label className="text-xs text-zinc-500 mb-1 block">Frequency</label>
          <select
            value={frequency}
            onChange={(e) => setFrequency(e.target.value)}
            className="bg-bg-elevated border border-bg-border rounded-md px-3 py-2 text-sm outline-none focus:border-accent"
          >
            <option value="daily">Daily</option>
            <option value="weekly">Weekly</option>
            <option value="monthly">Monthly</option>
          </select>
        </div>
        <button
          onClick={handleCreate}
          disabled={loading}
          className="bg-accent text-bg font-medium text-sm rounded-md px-4 py-2 hover:bg-accent/90 disabled:opacity-50"
        >
          Schedule
        </button>
      </div>

      <div className="bg-bg-surface border border-bg-border rounded-lg overflow-hidden">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-bg-border text-zinc-500 text-xs uppercase tracking-wide">
              <th className="text-left px-4 py-3 font-medium">Job ID</th>
              <th className="text-left px-4 py-3 font-medium">Next Run</th>
              <th className="text-right px-4 py-3 font-medium">Actions</th>
            </tr>
          </thead>
          <tbody>
            {jobs.map((job) => (
              <tr key={job.id} className="border-b border-bg-border last:border-0">
                <td className="px-4 py-3 font-mono text-zinc-300">{job.id}</td>
                <td className="px-4 py-3 text-zinc-500">{job.next_run}</td>
                <td className="px-4 py-3 text-right">
                  <button onClick={() => handleDelete(job.id)} className="text-zinc-500 hover:text-red-400">
                    <LuTrash2 size={16} />
                  </button>
                </td>
              </tr>
            ))}
            {jobs.length === 0 && (
              <tr><td colSpan={3} className="text-center py-8 text-zinc-500">No recurring scans scheduled.</td></tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}