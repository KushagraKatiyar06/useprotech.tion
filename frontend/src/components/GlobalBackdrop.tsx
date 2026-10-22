'use client';

import dynamic from 'next/dynamic';

// Same WebGL backdrop the landing page always had — now rendered once here,
// in layout.tsx, so it's the same persistent canvas across every page
// instead of a fresh one per route. Next's App Router keeps layout.tsx's
// tree mounted across client-side navigation, so this never restarts.
// Circuit-wires moved out of here — they now live inside the individual
// Agents/Raw Logs/Reports widgets (see Widget in BehavioralAnalysisPanel.tsx
// + WidgetWires), fading in per-widget once a run starts, instead of being
// one full-page overlay.
const FloatingLines = dynamic(() => import('./FloatingLines'), { ssr: false });

export default function GlobalBackdrop() {
  return (
    <div style={{ position: 'fixed', inset: 0, zIndex: 0, pointerEvents: 'none', opacity: 0.35 }}>
      <FloatingLines
        enabledWaves={['top', 'middle', 'bottom']}
        lineCount={5}
        lineDistance={5}
        bendRadius={5}
        bendStrength={-0.5}
        interactive={true}
        parallax={true}
        linesGradient={['#3b82f6', '#8b5cf6', '#06b6d4']}
        mixBlendMode="screen"
      />
    </div>
  );
}
