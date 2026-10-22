// A contained version of CircuitWires, sized to live inside one widget
// instead of behind the whole page — absolutely positioned (fills its
// parent, which must be `position: relative; overflow: hidden`), colored to
// match that widget's own accent instead of the fixed site-wide palette.
export default function WidgetWires({ accent }: { accent: string }) {
  return (
    <svg
      className="widget-wires"
      viewBox="0 0 400 200"
      preserveAspectRatio="none"
      aria-hidden="true"
    >
      <path className="widget-wire" d="M -20 30 C 80 10, 140 60, 240 35 S 360 15, 420 45" stroke={`var(--${accent})`} />
      <path className="widget-wire" d="M -20 100 C 90 130, 160 75, 250 110 S 380 140, 420 95" stroke={`var(--${accent})`} />
      <path className="widget-wire" d="M -20 170 C 70 150, 150 190, 230 160 S 370 125, 420 175" stroke={`var(--${accent})`} />
    </svg>
  );
}
