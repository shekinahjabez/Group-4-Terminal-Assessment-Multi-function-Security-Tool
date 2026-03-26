import { useState, useEffect, useRef, useCallback } from "react";
import {
  X, ChevronRight, ChevronLeft, HelpCircle, Lightbulb,
  CheckCircle2, BookOpen
} from "lucide-react";

// ─── Types ────────────────────────────────────────────────────────────────────
export type TourStep = {
  target: string;        // CSS selector or element id
  title: string;
  content: string;
  tip?: string;          // optional pro-tip
  position?: "top" | "bottom" | "left" | "right";
};

type Props = {
  steps: TourStep[];
  isOpen: boolean;
  onClose: () => void;
  toolName: string;
};

const TOOLTIP_W = 320;
const TOOLTIP_H = 200; // rough estimate

// ─── TourGuide Component ──────────────────────────────────────────────────────
export function TourGuide({ steps, isOpen, onClose, toolName }: Props) {
  const [currentStep, setCurrentStep] = useState(0);
  const [rect, setRect] = useState<DOMRect | null>(null);
  const [visible, setVisible] = useState(false);
  const overlayRef = useRef<HTMLDivElement>(null);

  const step = steps[currentStep];

  // ── Measure rect AFTER scroll has settled ──────────────────────────────────
  const measureAfterScroll = useCallback((selector: string) => {
    setVisible(false);

    const el = (() => { try { return document.querySelector(selector); } catch { return null; } })();

    if (!el) {
      setRect(null);
      setVisible(true);
      return;
    }

    // 1. Scroll the element into view
    el.scrollIntoView({ behavior: "smooth", block: "center" });

    // 2. Wait for the smooth scroll to finish (~500 ms is enough for most
    //    browsers; we re-measure on every animation frame during that window
    //    and commit once two consecutive frames agree on the position.
    let lastY = -1;
    let stableFrames = 0;
    let rafId: number;
    let giveUpTimer: ReturnType<typeof setTimeout>;

    const poll = () => {
      const r = el.getBoundingClientRect();
      if (Math.abs(r.top - lastY) < 0.5) {
        stableFrames++;
      } else {
        stableFrames = 0;
      }
      lastY = r.top;

      if (stableFrames >= 3) {
        // Position is stable — commit
        clearTimeout(giveUpTimer);
        setRect(r);
        setVisible(true);
        return;
      }
      rafId = requestAnimationFrame(poll);
    };

    rafId = requestAnimationFrame(poll);

    // Safety net: if scroll never settles (e.g. no scrollable parent), just
    // measure after 600 ms regardless.
    giveUpTimer = setTimeout(() => {
      cancelAnimationFrame(rafId);
      const r = el.getBoundingClientRect();
      setRect(r);
      setVisible(true);
    }, 600);

    return () => {
      cancelAnimationFrame(rafId);
      clearTimeout(giveUpTimer);
    };
  }, []);

  // Recalculate target rect whenever step changes
  useEffect(() => {
    if (!isOpen) { setVisible(false); return; }
    const cleanup = measureAfterScroll(step.target);
    return cleanup;
  }, [currentStep, isOpen, step?.target, measureAfterScroll]);

  // Re-measure on window resize so highlight tracks the element
  useEffect(() => {
    if (!isOpen) return;
    const onResize = () => {
      try {
        const el = document.querySelector(step.target);
        if (el) setRect(el.getBoundingClientRect());
      } catch {}
    };
    window.addEventListener("resize", onResize);
    return () => window.removeEventListener("resize", onResize);
  }, [isOpen, step?.target]);

  // Reset on open
  useEffect(() => { if (isOpen) setCurrentStep(0); }, [isOpen]);

  if (!isOpen) return null;

  const total = steps.length;
  const isFirst = currentStep === 0;
  const isLast = currentStep === total - 1;
  const progress = ((currentStep + 1) / total) * 100;

  // ── Compute tooltip position ──────────────────────────────────────────────
  let tooltipStyle: React.CSSProperties = {};
  let arrowStyle: React.CSSProperties = {};
  let arrowPos: "top" | "bottom" | "left" | "right" = "bottom";

  if (rect) {
    const vw = window.innerWidth;
    const vh = window.innerHeight;
    const pref = step.position ?? "bottom";

    const place = (preferred: typeof pref) => {
      if (preferred === "bottom" && rect.bottom + TOOLTIP_H + 16 < vh) return "bottom";
      if (preferred === "top"    && rect.top    - TOOLTIP_H - 16 > 0)  return "top";
      if (preferred === "right"  && rect.right  + TOOLTIP_W + 16 < vw) return "right";
      if (preferred === "left"   && rect.left   - TOOLTIP_W - 16 > 0)  return "left";
      // fallback
      if (rect.bottom + TOOLTIP_H + 16 < vh) return "bottom";
      if (rect.top    - TOOLTIP_H - 16 > 0)  return "top";
      return "bottom";
    };

    const placement = place(pref);
    arrowPos = placement;

    const cx = rect.left + rect.width / 2;
    const cy = rect.top + rect.height / 2;
    const left = Math.max(8, Math.min(cx - TOOLTIP_W / 2, vw - TOOLTIP_W - 8));

    if (placement === "bottom") {
      tooltipStyle = { position: "fixed", top: rect.bottom + 12, left, width: TOOLTIP_W, zIndex: 10001 };
      arrowStyle   = { position: "absolute", top: -7, left: cx - left - 7, width: 14, height: 14 };
    } else if (placement === "top") {
      tooltipStyle = { position: "fixed", bottom: vh - rect.top + 12, left, width: TOOLTIP_W, zIndex: 10001 };
      arrowStyle   = { position: "absolute", bottom: -7, left: cx - left - 7, width: 14, height: 14 };
    } else if (placement === "right") {
      tooltipStyle = { position: "fixed", top: cy - 80, left: rect.right + 12, width: TOOLTIP_W, zIndex: 10001 };
      arrowStyle   = { position: "absolute", top: 60, left: -7, width: 14, height: 14 };
    } else {
      tooltipStyle = { position: "fixed", top: cy - 80, left: rect.left - TOOLTIP_W - 12, width: TOOLTIP_W, zIndex: 10001 };
      arrowStyle   = { position: "absolute", top: 60, right: -7, width: 14, height: 14 };
    }
  } else {
    // Centered fallback
    tooltipStyle = {
      position: "fixed",
      top: "50%", left: "50%",
      transform: "translate(-50%, -50%)",
      width: TOOLTIP_W,
      zIndex: 10001,
    };
  }

  // ── Highlight box position ────────────────────────────────────────────────
  const highlightStyle: React.CSSProperties = rect
    ? {
        position: "fixed",
        top:    rect.top    - 4,
        left:   rect.left   - 4,
        width:  rect.width  + 8,
        height: rect.height + 8,
        zIndex: 10000,
        borderRadius: 10,
        boxShadow: "0 0 0 9999px rgba(0,0,0,0.55), 0 0 0 3px #6366f1, 0 0 20px 4px rgba(99,102,241,0.5)",
        pointerEvents: "none",
        transition: "all 0.3s cubic-bezier(0.4, 0, 0.2, 1)",
        opacity: visible ? 1 : 0,
      }
    : {
        position: "fixed", inset: 0, zIndex: 10000,
        background: "rgba(0,0,0,0.55)",
        pointerEvents: "none",
      };

  const arrowRotate =
    arrowPos === "bottom" ? "rotate(45deg)" :
    arrowPos === "top"    ? "rotate(225deg)" :
    arrowPos === "right"  ? "rotate(315deg)" :
                            "rotate(135deg)";

  return (
    <>
      {/* Overlay / spotlight */}
      <div ref={overlayRef} style={{ position: "fixed", inset: 0, zIndex: 9999, pointerEvents: "none" }} />
      <div style={highlightStyle} />

      {/* Close button (always visible top-right) */}
      <button
        onClick={onClose}
        style={{
          position: "fixed", top: 16, right: 16, zIndex: 10002,
          width: 36, height: 36,
          backgroundColor: "#1e293b",
          border: "1px solid rgba(255,255,255,0.15)",
          borderRadius: "50%",
          display: "flex", alignItems: "center", justifyContent: "center",
          cursor: "pointer", color: "#94a3b8",
          boxShadow: "0 2px 8px rgba(0,0,0,0.3)",
          transition: "all 0.2s",
        }}
        onMouseEnter={e => { (e.currentTarget as HTMLButtonElement).style.backgroundColor = "#334155"; (e.currentTarget as HTMLButtonElement).style.color = "#fff"; }}
        onMouseLeave={e => { (e.currentTarget as HTMLButtonElement).style.backgroundColor = "#1e293b"; (e.currentTarget as HTMLButtonElement).style.color = "#94a3b8"; }}
        title="Close guide"
      >
        <X style={{ width: 15, height: 15 }} />
      </button>

      {/* Step counter (top-center) */}
      <div style={{
        position: "fixed", top: 16, left: "50%", transform: "translateX(-50%)",
        zIndex: 10002,
        display: "flex", alignItems: "center", gap: 10,
        backgroundColor: "#1e293b",
        border: "1px solid rgba(255,255,255,0.1)",
        borderRadius: 999,
        padding: "6px 14px",
        boxShadow: "0 2px 12px rgba(0,0,0,0.4)",
      }}>
        <BookOpen style={{ width: 13, height: 13, color: "#6366f1" }} />
        <span style={{ fontSize: 12, fontWeight: 600, color: "#fff", fontFamily: "monospace" }}>
          {toolName} Guide
        </span>
        <span style={{ fontSize: 11, color: "#64748b" }}>·</span>
        <span style={{ fontSize: 11, color: "#94a3b8", fontFamily: "monospace" }}>
          {currentStep + 1} / {total}
        </span>
      </div>

      {/* Tooltip card */}
      <div
        style={{
          ...tooltipStyle,
          backgroundColor: "#0f172a",
          border: "1px solid rgba(99,102,241,0.35)",
          borderRadius: 14,
          boxShadow: "0 8px 32px rgba(0,0,0,0.5), 0 0 0 1px rgba(99,102,241,0.15)",
          overflow: "hidden",
          opacity: visible ? 1 : 0,
          transform: visible ? "scale(1)" : "scale(0.95)",
          transition: "opacity 0.25s ease, transform 0.25s ease",
        }}
      >
        {/* Arrow */}
        {rect && (
          <div style={{
            ...arrowStyle,
            backgroundColor: "#0f172a",
            border: "1px solid rgba(99,102,241,0.35)",
            transform: arrowRotate,
            borderRight: "none",
            borderBottom: "none",
          }} />
        )}

        {/* Progress bar */}
        <div style={{ height: 3, backgroundColor: "#1e293b" }}>
          <div style={{
            height: "100%",
            width: `${progress}%`,
            background: "linear-gradient(90deg, #6366f1, #818cf8)",
            transition: "width 0.3s ease",
            borderRadius: "0 2px 2px 0",
          }} />
        </div>

        {/* Header */}
        <div style={{ padding: "14px 16px 10px", borderBottom: "1px solid rgba(255,255,255,0.06)" }}>
          <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
            <div style={{
              width: 26, height: 26, borderRadius: 8,
              background: "linear-gradient(135deg, #6366f1, #818cf8)",
              display: "flex", alignItems: "center", justifyContent: "center",
              fontSize: 11, fontWeight: 800, color: "#fff",
              flexShrink: 0,
            }}>
              {currentStep + 1}
            </div>
            <p style={{ margin: 0, fontSize: 13, fontWeight: 700, color: "#f1f5f9", lineHeight: 1.3 }}>
              {step.title}
            </p>
          </div>
        </div>

        {/* Body */}
        <div style={{ padding: "12px 16px" }}>
          <p style={{ margin: 0, fontSize: 12.5, color: "#94a3b8", lineHeight: 1.65 }}>
            {step.content}
          </p>

          {step.tip && (
            <div style={{
              marginTop: 10,
              padding: "8px 10px",
              backgroundColor: "rgba(99,102,241,0.1)",
              border: "1px solid rgba(99,102,241,0.2)",
              borderRadius: 8,
              display: "flex", alignItems: "flex-start", gap: 8,
            }}>
              <Lightbulb style={{ width: 13, height: 13, color: "#818cf8", flexShrink: 0, marginTop: 1 }} />
              <p style={{ margin: 0, fontSize: 11.5, color: "#a5b4fc", lineHeight: 1.55 }}>
                <strong style={{ color: "#818cf8" }}>Tip: </strong>{step.tip}
              </p>
            </div>
          )}
        </div>

        {/* Footer / nav */}
        <div style={{
          padding: "10px 16px 14px",
          display: "flex", alignItems: "center", justifyContent: "space-between",
          borderTop: "1px solid rgba(255,255,255,0.06)",
        }}>
          {/* Dot indicators */}
          <div style={{ display: "flex", gap: 5 }}>
            {steps.map((_, i) => (
              <button
                key={i}
                onClick={() => setCurrentStep(i)}
                style={{
                  width: i === currentStep ? 18 : 6,
                  height: 6,
                  borderRadius: 999,
                  border: "none",
                  cursor: "pointer",
                  padding: 0,
                  backgroundColor: i === currentStep ? "#6366f1" : "#334155",
                  transition: "all 0.3s ease",
                }}
              />
            ))}
          </div>

          <div style={{ display: "flex", gap: 8 }}>
            {!isFirst && (
              <button
                onClick={() => setCurrentStep(s => s - 1)}
                style={{
                  display: "flex", alignItems: "center", gap: 5,
                  backgroundColor: "#1e293b",
                  border: "1px solid rgba(255,255,255,0.1)",
                  borderRadius: 8,
                  padding: "6px 12px",
                  fontSize: 12, fontWeight: 600, color: "#94a3b8",
                  cursor: "pointer",
                  transition: "all 0.2s",
                }}
                onMouseEnter={e => { (e.currentTarget as HTMLButtonElement).style.color = "#fff"; }}
                onMouseLeave={e => { (e.currentTarget as HTMLButtonElement).style.color = "#94a3b8"; }}
              >
                <ChevronLeft style={{ width: 13, height: 13 }} />
                Back
              </button>
            )}
            {!isLast ? (
              <button
                onClick={() => setCurrentStep(s => s + 1)}
                style={{
                  display: "flex", alignItems: "center", gap: 5,
                  background: "linear-gradient(135deg, #6366f1, #818cf8)",
                  border: "none",
                  borderRadius: 8,
                  padding: "6px 14px",
                  fontSize: 12, fontWeight: 600, color: "#fff",
                  cursor: "pointer",
                  boxShadow: "0 2px 8px rgba(99,102,241,0.4)",
                  transition: "all 0.2s",
                }}
              >
                Next
                <ChevronRight style={{ width: 13, height: 13 }} />
              </button>
            ) : (
              <button
                onClick={onClose}
                style={{
                  display: "flex", alignItems: "center", gap: 5,
                  background: "linear-gradient(135deg, #16a34a, #22c55e)",
                  border: "none",
                  borderRadius: 8,
                  padding: "6px 14px",
                  fontSize: 12, fontWeight: 600, color: "#fff",
                  cursor: "pointer",
                  boxShadow: "0 2px 8px rgba(22,163,74,0.4)",
                  transition: "all 0.2s",
                }}
              >
                <CheckCircle2 style={{ width: 13, height: 13 }} />
                Done!
              </button>
            )}
          </div>
        </div>
      </div>
    </>
  );
}

// ─── Help Button ──────────────────────────────────────────────────────────────
export function TourHelpButton({ onClick, label = "How to use" }: { onClick: () => void; label?: string }) {
  return (
    <button
      onClick={onClick}
      style={{
        display: "inline-flex", alignItems: "center", gap: 6,
        backgroundColor: "#f0f9ff",
        border: "1px solid #bae6fd",
        borderRadius: 999,
        padding: "5px 12px",
        fontSize: 12, fontWeight: 600, color: "#0284c7",
        cursor: "pointer",
        transition: "all 0.2s",
        flexShrink: 0,
      }}
      onMouseEnter={e => {
        (e.currentTarget as HTMLButtonElement).style.backgroundColor = "#e0f2fe";
        (e.currentTarget as HTMLButtonElement).style.borderColor = "#7dd3fc";
      }}
      onMouseLeave={e => {
        (e.currentTarget as HTMLButtonElement).style.backgroundColor = "#f0f9ff";
        (e.currentTarget as HTMLButtonElement).style.borderColor = "#bae6fd";
      }}
    >
      <HelpCircle style={{ width: 13, height: 13 }} />
      {label}
    </button>
  );
}