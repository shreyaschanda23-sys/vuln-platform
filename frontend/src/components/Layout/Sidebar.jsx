import { NavLink } from 'react-router-dom';
import { LuLayoutDashboard, LuRadar, LuShieldAlert, LuNetwork, LuCalendarClock, LuFileText, LuSettings } from 'react-icons/lu';

const links = [
  { to: '/', label: 'Overview', icon: LuLayoutDashboard, end: true },
  { to: '/scans', label: 'Scans', icon: LuRadar },
  { to: '/findings', label: 'Findings', icon: LuShieldAlert },
  { to: '/attack-surface', label: 'Attack Surface', icon: LuNetwork },
  { to: '/scheduler', label: 'Scheduler', icon: LuCalendarClock },
  { to: '/reports', label: 'Reports', icon: LuFileText },
  { to: '/settings', label: 'Settings', icon: LuSettings },
];

export default function Sidebar() {
  return (
    <aside className="w-60 shrink-0 bg-bg-surface border-r border-bg-border flex flex-col">
      <div className="h-16 flex items-center px-5 border-b border-bg-border">
        <span className="text-accent font-mono font-bold text-lg tracking-tight">VULN//PLATFORM</span>
      </div>
      <nav className="flex-1 py-4 px-3 space-y-1">
        {links.map(({ to, label, icon: Icon, end }) => (
          <NavLink
            key={to}
            to={to}
            end={end}
            className={({ isActive }) =>
              `flex items-center gap-3 px-3 py-2 rounded-md text-sm font-medium transition-colors ${
                isActive
                  ? 'bg-accent/10 text-accent'
                  : 'text-zinc-400 hover:text-zinc-200 hover:bg-bg-elevated'
              }`
            }
          >
            <Icon size={17} />
            {label}
          </NavLink>
        ))}
      </nav>
    </aside>
  );
}