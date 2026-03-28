'use client';

interface PanelProps {
  title: string;
  children: React.ReactNode;
  className?: string;
  style?: React.CSSProperties;
}

export default function Panel({ title, children, className = '', style }: PanelProps) {
  return (
    <div className={`panel ${className}`} style={style}>
      <div className="panel-corner tl" />
      <div className="panel-corner tr" />
      <div className="panel-corner bl" />
      <div className="panel-corner br" />
      <div className="panel-title">{title}</div>
      {children}
    </div>
  );
}
