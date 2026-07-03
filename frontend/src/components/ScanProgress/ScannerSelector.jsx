const SCANNERS = [
  { id: 'subfinder', label: 'Subfinder', desc: 'Subdomain enumeration' },
  { id: 'amass', label: 'Amass', desc: 'Subdomain enumeration' },
  { id: 'masscan', label: 'Masscan', desc: 'Fast port scanning' },
  { id: 'nmap', label: 'Nmap', desc: 'Service/version detection' },
  { id: 'httpx', label: 'httpx', desc: 'Live host probing' },
  { id: 'katana', label: 'Katana', desc: 'Web crawler' },
  { id: 'nuclei', label: 'Nuclei', desc: 'CVE/vuln templates' },
];

export default function ScannerSelector({ selected, onChange }) {
  const allSelected = selected === null;

  const toggleAll = () => onChange(allSelected ? SCANNERS.map((s) => s.id) : null);

  const toggleOne = (id) => {
    const current = selected ?? SCANNERS.map((s) => s.id);
    const next = current.includes(id) ? current.filter((s) => s !== id) : [...current, id];
    onChange(next.length === SCANNERS.length ? null : next);
  };

  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between">
        <span className="text-xs text-zinc-500 uppercase tracking-wide">Scanners</span>
        <button
          type="button"
          onClick={toggleAll}
          className="text-xs text-accent hover:underline"
        >
          {allSelected ? 'Deselect all' : 'Select all'}
        </button>
      </div>
      <div className="grid grid-cols-2 gap-2">
        {SCANNERS.map((s) => {
          const isChecked = allSelected || (selected ?? []).includes(s.id);
          return (
            <label
              key={s.id}
              className={`flex items-start gap-2 px-3 py-2 rounded-md border cursor-pointer transition-colors ${
                isChecked ? 'border-accent/40 bg-accent/5' : 'border-bg-border bg-bg-elevated'
              }`}
            >
              <input
                type="checkbox"
                checked={isChecked}
                onChange={() => toggleOne(s.id)}
                className="mt-0.5 accent-accent"
              />
              <div>
                <div className="text-sm text-zinc-200">{s.label}</div>
                <div className="text-xs text-zinc-500">{s.desc}</div>
              </div>
            </label>
          );
        })}
      </div>
    </div>
  );
}