export default function ReportsPage() {
  return (
    <div>
      <h1 className="text-xl font-semibold text-zinc-100 mb-6">Reports</h1>
      <div className="bg-bg-surface border border-bg-border rounded-lg p-8 text-center text-zinc-500 text-sm">
        Report generation is Phase 8 — backend endpoint returns 501 until <code className="text-accent">services/reporter.py</code> is built.
      </div>
    </div>
  );
}