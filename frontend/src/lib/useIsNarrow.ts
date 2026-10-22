'use client';

import { useEffect, useState } from 'react';

/**
 * Tracks whether the viewport is at or below `breakpoint` (default 860px,
 * matching .main-grid's single-column CSS breakpoint). A handful of layouts
 * in this app are computed as inline flex/grid styles (not static CSS
 * classes), so a plain CSS media query can't reach them — this is the JS
 * equivalent, used only where that's the case.
 */
export function useIsNarrow(breakpoint = 860): boolean {
  const [isNarrow, setIsNarrow] = useState(false);

  useEffect(() => {
    const mql = window.matchMedia(`(max-width: ${breakpoint}px)`);
    setIsNarrow(mql.matches);
    const onChange = (e: MediaQueryListEvent) => setIsNarrow(e.matches);
    mql.addEventListener('change', onChange);
    return () => mql.removeEventListener('change', onChange);
  }, [breakpoint]);

  return isNarrow;
}
