import { useAuthStore } from '../../store/authStore';
import { LuLogOut } from 'react-icons/lu';

export default function Topbar() {
  const { user, logout } = useAuthStore();

  return (
    <header className="h-16 shrink-0 flex items-center justify-between px-6 border-b border-bg-border bg-bg-surface">
      <div className="text-sm text-zinc-500 font-mono">Automated Vulnerability Management</div>
      <div className="flex items-center gap-4">
        <span className="text-sm text-zinc-400">{user?.email}</span>
        <button
          onClick={logout}
          className="flex items-center gap-1.5 text-sm text-zinc-500 hover:text-red-400 transition-colors"
        >
          <LuLogOut size={16} />
          Logout
        </button>
      </div>
    </header>
  );
}