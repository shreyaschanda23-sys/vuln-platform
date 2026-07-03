import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import toast from 'react-hot-toast';
import { useAuthStore } from '../store/authStore';

export default function LoginPage() {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [loading, setLoading] = useState(false);
  const login = useAuthStore((s) => s.login);
  const navigate = useNavigate();

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    try {
      await login(email, password);
      navigate('/');
    } catch {
      toast.error('Invalid credentials');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-bg">
      <form onSubmit={handleSubmit} className="w-full max-w-sm bg-bg-surface border border-bg-border rounded-lg p-8">
        <div className="mb-8 text-center">
          <span className="text-accent font-mono font-bold text-xl tracking-tight">VULN//PLATFORM</span>
          <p className="text-zinc-500 text-sm mt-1">Sign in to continue</p>
        </div>
        <div className="space-y-4">
          <div>
            <label className="text-xs text-zinc-500 mb-1 block">Email</label>
            <input
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              required
              className="w-full bg-bg-elevated border border-bg-border rounded-md px-3 py-2 text-sm outline-none focus:border-accent transition-colors"
            />
          </div>
          <div>
            <label className="text-xs text-zinc-500 mb-1 block">Password</label>
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
              className="w-full bg-bg-elevated border border-bg-border rounded-md px-3 py-2 text-sm outline-none focus:border-accent transition-colors"
            />
          </div>
          <button
            type="submit"
            disabled={loading}
            className="w-full bg-accent text-bg font-medium rounded-md py-2 text-sm hover:bg-accent/90 transition-colors disabled:opacity-50"
          >
            {loading ? 'Signing in...' : 'Sign In'}
          </button>
        </div>
      </form>
    </div>
  );
}