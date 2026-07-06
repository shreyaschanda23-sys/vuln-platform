import { useState } from 'react';
import toast from 'react-hot-toast';
import { useAuthStore } from '../store/authStore';
import client from '../api/client';

export default function SettingsPage() {
  const user = useAuthStore((s) => s.user);
  const [currentPassword, setCurrentPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [loading, setLoading] = useState(false);

  const handleChangePassword = async (e) => {
    e.preventDefault();
    setLoading(true);
    try {
      await client.post('/auth/change-password', { current_password: currentPassword, new_password: newPassword });
      toast.success('Password updated');
      setCurrentPassword('');
      setNewPassword('');
    } catch {
      toast.error('Failed to update password');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="max-w-md space-y-6">
      <h1 className="text-xl font-semibold text-zinc-100">Settings</h1>

      <div className="bg-bg-surface border border-bg-border rounded-lg p-6">
        <div className="text-sm text-zinc-500 mb-1">Email</div>
        <div className="text-zinc-200 mb-4">{user?.email}</div>
        <div className="text-sm text-zinc-500 mb-1">Role</div>
        <div className="text-zinc-200 capitalize">{user?.role}</div>
      </div>

      <form onSubmit={handleChangePassword} className="bg-bg-surface border border-bg-border rounded-lg p-6 space-y-3">
        <div className="text-sm font-medium text-zinc-300 mb-2">Change Password</div>
        <input
          type="password" placeholder="Current password" value={currentPassword}
          onChange={(e) => setCurrentPassword(e.target.value)} required
          className="w-full bg-bg-elevated border border-bg-border rounded-md px-3 py-2 text-sm outline-none focus:border-accent"
        />
        <input
          type="password" placeholder="New password" value={newPassword}
          onChange={(e) => setNewPassword(e.target.value)} required minLength={8}
          className="w-full bg-bg-elevated border border-bg-border rounded-md px-3 py-2 text-sm outline-none focus:border-accent"
        />
        <button
          type="submit" disabled={loading}
          className="w-full bg-accent text-bg font-medium rounded-md py-2 text-sm hover:bg-accent/90 disabled:opacity-50"
        >
          {loading ? 'Updating...' : 'Update Password'}
        </button>
      </form>
    </div>
  );
}