'use client';

import { useEffect, useState } from 'react';

export default function Header() {
  const [clock, setClock] = useState('--:--:-- UTC');

  useEffect(() => {
    const update = () => setClock(new Date().toUTCString().slice(17, 25) + ' UTC');
    update();
    const id = setInterval(update, 1000);
    return () => clearInterval(id);
  }, []);

  return (
    <div className="hud-header">
      <div className="hud-logo">
        Use-<span>Protection-</span>Tech
      </div>
      <div className="hud-status-row">
        <div className="status-pill online">● SANDBOX ONLINE</div>
        <div className="status-pill armed">◆ AI ARMED</div>
        <div className="hud-clock">{clock}</div>
      </div>
    </div>
  );
}
