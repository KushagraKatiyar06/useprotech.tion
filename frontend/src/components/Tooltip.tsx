'use client';

import { useState } from 'react';

interface Props {
  text: string;
  children: React.ReactNode;
  /** Only show tooltip when disabled — default true */
  onlyWhenDisabled?: boolean;
  disabled?: boolean;
}

/**
 * Wraps a button (or any element) and shows a floating hint tooltip on hover.
 * Designed for grayed-out / disabled controls to explain what the user must do.
 */
export default function Tooltip({ text, children, onlyWhenDisabled = true, disabled = true }: Props) {
  const [visible, setVisible] = useState(false);
  const show = visible && (!onlyWhenDisabled || disabled);

  return (
    <div
      style={{ position: 'relative', display: 'inline-flex' }}
      onMouseEnter={() => setVisible(true)}
      onMouseLeave={() => setVisible(false)}
    >
      {children}
      {show && (
        <div style={{
          position: 'absolute',
          bottom: 'calc(100% + 8px)',
          left: '50%',
          transform: 'translateX(-50%)',
          padding: '6px 10px',
          background: '#010814',
          border: '1px solid rgba(0,245,255,0.25)',
          borderRadius: 5,
          fontFamily: 'JetBrains Mono, monospace',
          fontSize: 9,
          color: '#00f5ff',
          whiteSpace: 'nowrap',
          pointerEvents: 'none',
          zIndex: 200,
          boxShadow: '0 4px 20px rgba(0,0,0,0.7)',
          letterSpacing: 0.5,
        }}>
          {text}
          {/* Arrow */}
          <div style={{
            position: 'absolute',
            top: '100%',
            left: '50%',
            transform: 'translateX(-50%)',
            width: 0, height: 0,
            borderLeft: '5px solid transparent',
            borderRight: '5px solid transparent',
            borderTop: '5px solid rgba(0,245,255,0.25)',
          }} />
        </div>
      )}
    </div>
  );
}
