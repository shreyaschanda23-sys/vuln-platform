import { useEffect, useState } from 'react';

export function useScanSocket(scanId) {
  const [progress, setProgress] = useState(null);

  useEffect(() => {
    if (!scanId) return;
    const ws = new WebSocket(`ws://localhost:8000/ws/scans/${scanId}`);
    ws.onmessage = (e) => setProgress(JSON.parse(e.data));
    return () => ws.close();
  }, [scanId]);

  return progress;
}