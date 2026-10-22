'use client';

import Link from 'next/link';
import { useRouter } from 'next/navigation';
import { navigateWithFade } from '@/lib/pageTransition';

interface HeaderProps {
  locked?: boolean;
  /** Shows a fading-in "start over" control once a run has actually
   *  finished (nothing left running) — lets you jump straight back to file
   *  intake without a manual reload. */
  showStartOver?: boolean;
}

export default function Header({ locked = false, showStartOver = false }: HeaderProps) {
  const router = useRouter();
  const logoStyle: React.CSSProperties = {
    display: 'flex',
    alignItems: 'center',
    gap: '10px',
    textDecoration: 'none',
  };

  const content = (
    <>
      <img src="/icon.svg" alt="UseProtection" width={24} height={24} />
      Use<span>Protechtion</span>
    </>
  );

  function goHome(e: React.MouseEvent) {
    e.preventDefault();
    navigateWithFade(router.push, '/');
  }

  // A hard reload, not a client-side route push — pushing to the route
  // we're already on wouldn't remount the page or reset any state. Fades
  // #page-content out first (same mechanism as navigateWithFade) so it
  // doesn't look like an abrupt flash/reload.
  function startOver() {
    const el = document.getElementById('page-content');
    el?.classList.add('page-leaving');
    setTimeout(() => { window.location.href = '/dashboard'; }, 260);
  }

  return (
    <div className="hud-header">
      {locked ? (
        <div
          className="hud-logo"
          style={{ ...logoStyle, cursor: 'not-allowed', opacity: 0.6 }}
          title="Analysis in progress — can't leave this session right now"
        >
          {content}
        </div>
      ) : (
        <Link href="/" className="hud-logo clickable" style={logoStyle} onClick={goHome}>
          {content}
        </Link>
      )}

      <button
        onClick={startOver}
        className="start-over-btn clickable"
        style={{ opacity: showStartOver ? 1 : 0, pointerEvents: showStartOver ? 'auto' : 'none' }}
      >
        ↺ START OVER
      </button>
    </div>
  );
}
