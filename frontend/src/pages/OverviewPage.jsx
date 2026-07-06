import { useState, useEffect } from 'react';
import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip } from 'recharts';
import { listDomains } from '../api/domains';
import { listScans } from '../api/scans';
import { listFindings } from '../api/findings';

const SEVERITY_COLORS = {
  critical: '#dc2626', high: '#ea580c', medium: '#ca8a04', low: '#2563eb', info: '#71717a',
};

function KpiCard({ label, value, sub }) {
  return (
    <div className="bg-bg-surface border border-bg-border rounded-lg p-4">
      <div className="text-xs text-zinc-500 uppercase tracking-wide mb-1">{label}</div>
      <div className="text-2xl font-semibold text-zinc-100">{value}</div>
      {sub && <div className="text-xs text-zinc-500 mt-1">{sub}</div>}
    </div>
  );
}

export default function OverviewPage() {
  const [domains, setDomains] = useState([]);
  const [scans, setScans] = useState([]);
  const [findings, setFindings] = useState([]);

  useEffect(() => {
    listDomains().then(setDomains);
    listScans().then(setScans);
    listFindings({ limit: 200 }).then((r) => setFindings(r.items));
  }, []);

  const activeScans = scans.filter((s) => s.status === 'running' || s.status === 'pending').length;
  const critical = findings.filter((f) => f.severity === 'critical').length;
  const lastScan = scans[0];

  const severityData = Object.entries(
    findings.reduce((acc, f) => {
      acc[f.severity] = (acc[f.severity] || 0) + 1;
      return acc;
    }, {})
  ).map(([name, value]) => ({ name, value }));

  return (
    <div>
      <h1 className="text-xl font-semibold text-zinc-100 mb-6">Overview</h1>

      <div className="grid grid-cols-4 gap-4 mb-6">
        <KpiCard label="Domains" value={domains.length} />
        <KpiCard label="Active Scans" value={activeScans} />
        <KpiCard label="Critical Findings" value={critical} />
        <KpiCard
          label="Last Scan"
          value={lastScan ? `#${lastScan.id}` : '—'}
          sub={lastScan ? lastScan.status : undefined}
        />
      </div>

      <div className="grid grid-cols-3 gap-4">
        <div className="col-span-2 bg-bg-surface border border-bg-border rounded-lg p-4">
          <div className="text-sm font-medium text-zinc-300 mb-4">Recent Scans</div>
          {scans.slice(0, 5).map((s) => (
            <div key={s.id} className="flex items-center justify-between py-2 border-b border-bg-border last:border-0 text-sm">
              <span className="font-mono text-zinc-400">#{s.id}</span>
              <span className="text-zinc-500">{s.current_stage || '—'}</span>
              <span className={s.status === 'complete' ? 'text-emerald-400' : s.status === 'failed' ? 'text-red-400' : 'text-accent'}>
                {s.status}
              </span>
            </div>
          ))}
          {scans.length === 0 && <div className="text-zinc-500 text-sm py-4 text-center">No scans yet</div>}
        </div>

        <div className="bg-bg-surface border border-bg-border rounded-lg p-4">
          <div className="text-sm font-medium text-zinc-300 mb-4">Severity Breakdown</div>
          {severityData.length > 0 ? (
            <ResponsiveContainer width="100%" height={180}>
              <PieChart>
                <Pie data={severityData} dataKey="value" nameKey="name" innerRadius={45} outerRadius={70}>
                  {severityData.map((entry) => (
                    <Cell key={entry.name} fill={SEVERITY_COLORS[entry.name] || '#71717a'} />
                  ))}
                </Pie>
                <Tooltip contentStyle={{ background: '#18181b', border: '1px solid #27272a', fontSize: 12 }} />
              </PieChart>
            </ResponsiveContainer>
          ) : (
            <div className="text-zinc-500 text-sm py-12 text-center">No findings yet</div>
          )}
        </div>
      </div>
    </div>
  );
}