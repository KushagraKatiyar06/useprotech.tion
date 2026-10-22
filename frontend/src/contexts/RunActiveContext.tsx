'use client';

import { createContext, useContext, useState } from 'react';

// Lets dashboard/page.tsx (deep in the tree) signal "a run has actually
// started" up to GlobalBackdrop (a sibling of {children} in layout.tsx,
// outside the page's own render tree) so the circuit-wires overlay can fade
// in at that moment instead of being part of the backdrop from page load.
interface RunActiveState {
  active: boolean;
  setActive: (active: boolean) => void;
}

const RunActiveContext = createContext<RunActiveState>({ active: false, setActive: () => {} });

export function RunActiveProvider({ children }: { children: React.ReactNode }) {
  const [active, setActive] = useState(false);
  return (
    <RunActiveContext.Provider value={{ active, setActive }}>
      {children}
    </RunActiveContext.Provider>
  );
}

export function useRunActive() {
  return useContext(RunActiveContext);
}
