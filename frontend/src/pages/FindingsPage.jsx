import { useState, useEffect } from 'react';
import toast from 'react-hot-toast';
import { listFindings, updateFinding } from '../api/findings';

const SEVERITY_STYLES = {
  critical: 'text-severity-critical bg-severity-critical/10 border-severity-critical/30',
  high: 'text-severity-high bg-severity-high/10 border-severity-high/30',
  medium: 'text-severity-medium bg-severity-medium/10 border-severity-medium/30',
  low: 'text-severity-low bg-severity-low/10 border-severity-low/30',
  info: 'text-severity-info bg-severity-info/10 border-severity-info/30',
};

export default function FindingsPage() {
  const [findings, setFindings] = useState([]);
  const [total, setTotal] = useState(0);
  const [severity, setSeverity] = useState('');
  const [showResolved, setShowResolved] = useState(false);
  const [offset, setOffset] = useState(0);
  const [loading, setLoading] = useState(true);
  const limit = 25;

  const load = () => {
    setLoading(true);
    listFindings({
      severity: severity || undefined,
      is_resolved: showResolved ? undefined : false,
      limit,
      offset,
    })
      .then((res) => {
        setFindings(res.items);
        setTotal(res.total);
      })
      .catch(() => toast.error('Failed to load findings'))
      .finally(() => setLoading(false));
  };

  useEffect(() => { load(); }, [severity, showResolved, offset]);

  const toggleResolved = async (finding) => {
    try {
      await updateFinding(finding.id, { is_resolved: !finding.is_resolved });
      load();
    } catch {
      toast.error('Failed to update finding');
    }
  };

  const markFP = async (finding) => {
    try {
      await updateFinding(finding.id, { is_false_positive: !finding.is_false_positive });
      load();
    } catch {
      toast.error('Failed to update finding');
    }
  };

  return (
    <div>
      <div className="flex items-center justify-between mb-6">
        <h1 className="text-xl font-semibold text-zinc-100">Findings</h1>
        <div className="flex items-center gap-3">
          <select
            value={severity}
            onChange={(e) => { setSeverity(e.target.value); setOffset(0); }}
            className="bg-bg-elevated border border-bg-border rounded-md px-3 py-1.5 text-sm outline-none focus:border-accent"
          >
            <option value="">All severities</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
            <option value="info">Info</option>
          </select>
          <label className="flex items-center gap-2 text-sm text-zinc-400">
            <input
              type="checkbox"
              checked={showResolved}
              onChange={(e) => { setShowResolved(e.target.checked); setOffset(0); }}
              className="accent-accent"
            />
            Show resolved
          </label>
        </div>
      </div>

      {loading ? (
        <div className="text-zinc-500 text-sm">Loading...</div>
      ) : findings.length === 0 ? (
        <div className="text-center py-20 text-zinc-500">No findings match these filters.</div>
      ) : (
        <>
          <div className="space-y-2">
            {findings.map((f) => (
              <div
                key={f.id}
                className={`border rounded-lg p-4 bg-bg-surface ${f.is_resolved ? 'opacity-50' : ''}`}
              >
                <div className="flex items-start justify-between gap-4">
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 mb-1.5">
                      <span className={`text-xs font-medium px-2 py-0.5 rounded border uppercase ${SEVERITY_STYLES[f.severity] || SEVERITY_STYLES.info}`}>
                        {f.severity}
                      </span>
                      {f.cve_id && <span className="text-xs font-mono text-zinc-500">{f.cve_id}</span>}
                      {f.kev_status && (
                        <span className="text-xs font-medium px-2 py-0.5 rounded bg-red-500/10 text-red-400 border border-red-500/30">
                          KEV
                        </span>
                      )}
                      {f.risk_score != null && (
                        <span className="text-xs font-mono text-zinc-500">risk {f.risk_score.toFixed(0)}</span>
                      )}
                    </div>
                    <div className="text-sm text-zinc-200">{f.description || f.template_id || 'Unnamed finding'}</div>
                    <div className="text-xs text-zinc-500 mt-1 font-mono truncate">
                      {f.host}{f.port ? `:${f.port}` : ''}{f.endpoint ? ` — ${f.endpoint}` : ''}
                    </div>
                  </div>
                  <div className="flex items-center gap-2 shrink-0">
                    <button
                      onClick={() => markFP(f)}
                      className={`text-xs px-2 py-1 rounded border transition-colors ${
                        f.is_false_positive
                          ? 'border-amber-500/40 text-amber-400 bg-amber-500/10'
                          : 'border-bg-border text-zinc-500 hover:text-zinc-300'
                      }`}
                    >
                      {f.is_false_positive ? 'FP' : 'Mark FP'}
                    </button>
                    <button
                      onClick={() => toggleResolved(f)}
                      className={`text-xs px-2 py-1 rounded border transition-colors ${
                        f.is_resolved
                          ? 'border-emerald-500/40 text-emerald-400 bg-emerald-500/10'
                          : 'border-bg-border text-zinc-500 hover:text-zinc-300'
                      }`}
                    >
                      {f.is_resolved ? 'Resolved' : 'Resolve'}
                    </button>
                  </div>
                </div>
              </div>
            ))}
          </div>

          <div className="flex items-center justify-between mt-4 text-sm text-zinc-500">
            <span>{total} total findings</span>
            <div className="flex gap-2">
              <button
                disabled={offset === 0}
                onClick={() => setOffset((o) => Math.max(0, o - limit))}
                className="px-3 py-1 rounded border border-bg-border disabled:opacity-30"
              >
                Previous
              </button>
              <button
                disabled={offset + limit >= total}
                onClick={() => setOffset((o) => o + limit)}
                className="px-3 py-1 rounded border border-bg-border disabled:opacity-30"
              >
                Next
              </button>
            </div>
          </div>
        </>
      )}
    </div>
  );
}