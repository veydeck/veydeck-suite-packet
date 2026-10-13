import { type CSSProperties, type ReactNode, useEffect, useRef, useState } from "react";

interface ResizableWorkspaceProps {
  left: ReactNode;
  right: ReactNode;
  className?: string;
  defaultLeftPercent?: number;
  minLeftPercent?: number;
  minRightPercent?: number;
  storageKey: string;
  dataUi?: string;
}

function clamp(value: number, min: number, max: number) {
  return Math.min(Math.max(value, min), max);
}

function readStoredPercent(storageKey: string, fallback: number) {
  const stored = window.localStorage.getItem(storageKey);
  if (!stored) return fallback;
  const parsed = Number(stored);
  return Number.isFinite(parsed) ? parsed : fallback;
}

export function ResizableWorkspace({
  left,
  right,
  className,
  defaultLeftPercent = 36,
  minLeftPercent = 22,
  minRightPercent = 32,
  storageKey,
  dataUi = "resizable-workspace",
}: ResizableWorkspaceProps) {
  const containerRef = useRef<HTMLDivElement | null>(null);
  const [leftPercent, setLeftPercent] = useState(() =>
    clamp(
      readStoredPercent(storageKey, defaultLeftPercent),
      minLeftPercent,
      100 - minRightPercent,
    ),
  );

  useEffect(() => {
    window.localStorage.setItem(storageKey, String(Math.round(leftPercent * 10) / 10));
  }, [leftPercent, storageKey]);

  const startResize = (handle: HTMLElement, pointerId: number) => {
    const container = containerRef.current;
    if (!container) return;

    const update = (clientX: number) => {
      const rect = container.getBoundingClientRect();
      if (rect.width <= 0) return;
      const nextPercent = ((clientX - rect.left) / rect.width) * 100;
      setLeftPercent(clamp(nextPercent, minLeftPercent, 100 - minRightPercent));
    };

    const handlePointerMove = (event: PointerEvent) => {
      update(event.clientX);
    };

    const stopResize = () => {
      window.removeEventListener("pointermove", handlePointerMove);
      window.removeEventListener("pointerup", stopResize);
      window.removeEventListener("pointercancel", stopResize);
    };

    handle?.setPointerCapture?.(pointerId);
    window.addEventListener("pointermove", handlePointerMove);
    window.addEventListener("pointerup", stopResize);
    window.addEventListener("pointercancel", stopResize);
  };

  return (
    <div
      className={`packet-workspace packet-resizable-workspace ${className ?? ""}`}
      data-ui={dataUi}
      ref={containerRef}
      style={{ "--packet-left-size": `${leftPercent}%` } as CSSProperties}
    >
      <div className="packet-resizable-pane packet-resizable-pane-left">{left}</div>
      <div
        aria-label="Resize panels"
        className="packet-resize-handle"
        data-resize-handle={storageKey}
        role="separator"
        tabIndex={0}
        onDoubleClick={() => setLeftPercent(defaultLeftPercent)}
        onKeyDown={(event) => {
          if (event.key === "ArrowLeft") {
            event.preventDefault();
            setLeftPercent((current) => clamp(current - 2, minLeftPercent, 100 - minRightPercent));
          }
          if (event.key === "ArrowRight") {
            event.preventDefault();
            setLeftPercent((current) => clamp(current + 2, minLeftPercent, 100 - minRightPercent));
          }
          if (event.key === "Home") {
            event.preventDefault();
            setLeftPercent(minLeftPercent);
          }
          if (event.key === "End") {
            event.preventDefault();
            setLeftPercent(100 - minRightPercent);
          }
        }}
        onPointerDown={(event) => {
          event.preventDefault();
          startResize(event.currentTarget, event.pointerId);
        }}
      />
      <div className="packet-resizable-pane packet-resizable-pane-right">{right}</div>
    </div>
  );
}
