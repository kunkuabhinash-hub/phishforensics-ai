import { useEffect, useRef, useState } from 'react';
import './ForensicCursor.css';

export default function ForensicCursor() {
  const cursorRef = useRef<HTMLDivElement | null>(null);
  const targetPos = useRef({ x: -100, y: -100 });
  const currentPos = useRef({ x: -100, y: -100 });
  const isMoving = useRef(false);
  const rafId = useRef<number | null>(null);
  const [isEnabled, setIsEnabled] = useState(false);

  useEffect(() => {
    // Only enable on devices that actually have a fine pointer (mouse) and hover capability
    const mediaQuery = window.matchMedia('(hover: hover) and (pointer: fine)');
    
    const checkCapability = () => {
      const supported = mediaQuery.matches;
      setIsEnabled(supported);
      if (supported) {
        document.body.classList.add('forensic-cursor-enabled');
      } else {
        document.body.classList.remove('forensic-cursor-enabled');
      }
    };

    checkCapability();
    mediaQuery.addEventListener('change', checkCapability);

    return () => {
      mediaQuery.removeEventListener('change', checkCapability);
      document.body.classList.remove('forensic-cursor-enabled');
    };
  }, []);

  useEffect(() => {
    if (!isEnabled) return;

    const cursorEl = cursorRef.current;
    if (!cursorEl) return;

    const prefersReducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

    // Smooth animation frame loop
    const render = () => {
      if (prefersReducedMotion) {
        currentPos.current.x = targetPos.current.x;
        currentPos.current.y = targetPos.current.y;
      } else {
        // Snappy, fluid spring interpolation without perceived lag
        const speed = 0.55;
        currentPos.current.x += (targetPos.current.x - currentPos.current.x) * speed;
        currentPos.current.y += (targetPos.current.y - currentPos.current.y) * speed;
      }

      if (cursorEl) {
        // Hotspot centered precisely at (13, 13) where the "+" sign is centered (36px total visual size)
        cursorEl.style.transform = `translate3d(${currentPos.current.x - 13}px, ${currentPos.current.y - 13}px, 0)`;
      }

      const dx = Math.abs(targetPos.current.x - currentPos.current.x);
      const dy = Math.abs(targetPos.current.y - currentPos.current.y);

      if (dx > 0.1 || dy > 0.1) {
        rafId.current = requestAnimationFrame(render);
      } else {
        isMoving.current = false;
      }
    };

    const scheduleRender = () => {
      if (!isMoving.current) {
        isMoving.current = true;
        rafId.current = requestAnimationFrame(render);
      }
    };

    const handleMouseMove = (e: MouseEvent) => {
      targetPos.current.x = e.clientX;
      targetPos.current.y = e.clientY;
      scheduleRender();
    };

    const handleMouseOver = (e: MouseEvent) => {
      const target = e.target as HTMLElement | null;
      if (!target || !cursorEl) return;

      // 1. Text input or editable text -> hide custom cursor, allow normal OS text cursor
      if (target.closest('input, textarea, select, [contenteditable], .text-selectable')) {
        cursorEl.classList.add('cursor-hidden');
        cursorEl.classList.remove('cursor-clickable', 'cursor-card');
        return;
      }

      // 2. Disabled controls -> hide custom cursor, show native disabled cursor
      if (target.closest('button:disabled, [aria-disabled="true"], input:disabled, select:disabled')) {
        cursorEl.classList.add('cursor-hidden');
        cursorEl.classList.remove('cursor-clickable', 'cursor-card');
        return;
      }

      cursorEl.classList.remove('cursor-hidden');

      // 3. Clickable buttons, links, controls, investigation feature buttons
      if (target.closest('button, a, [role="button"], .btn-primary, .btn-secondary, .btn-primary-large, .btn-header-action, .filter-btn, .btn-ioc-action, .clickable-evidence-ref, .sim-tab-btn, .sim-control-btn, .tactic-link-badge, .nav-back-button, .evidence-preview-toggle, .btn-close-feature-panel, .btn-close-feature-panel-bottom, .feature-card-btn, .nav-link-item, .dropdown-menu-item')) {
        cursorEl.classList.add('cursor-clickable');
        cursorEl.classList.remove('cursor-card');
      }
      // 4. Interactive cards, evidence items, pills, observables, findings
      else if (target.closest('.evidence-item-card, .ioc-item-card, .dna-trait-pill, .fingerprint-meta-item, .impact-card, .exec-finding-box, .mitre-primary-card, .guidance-item-card, .insight-box, .stepper-node, .stepper-content, .metric-box-card, .export-action-card')) {
        cursorEl.classList.add('cursor-card');
        cursorEl.classList.remove('cursor-clickable');
      } else {
        cursorEl.classList.remove('cursor-clickable', 'cursor-card');
      }
    };

    const handleMouseDown = () => {
      if (cursorEl) cursorEl.classList.add('cursor-active');
    };

    const handleMouseUp = () => {
      if (cursorEl) cursorEl.classList.remove('cursor-active');
    };

    const handleMouseLeave = () => {
      if (cursorEl) cursorEl.classList.add('cursor-hidden');
    };

    const handleMouseEnter = () => {
      if (cursorEl) cursorEl.classList.remove('cursor-hidden');
    };

    window.addEventListener('mousemove', handleMouseMove, { passive: true });
    document.addEventListener('mouseover', handleMouseOver, { passive: true });
    window.addEventListener('mousedown', handleMouseDown, { passive: true });
    window.addEventListener('mouseup', handleMouseUp, { passive: true });
    document.documentElement.addEventListener('mouseleave', handleMouseLeave, { passive: true });
    document.documentElement.addEventListener('mouseenter', handleMouseEnter, { passive: true });

    return () => {
      window.removeEventListener('mousemove', handleMouseMove);
      document.removeEventListener('mouseover', handleMouseOver);
      window.removeEventListener('mousedown', handleMouseDown);
      window.removeEventListener('mouseup', handleMouseUp);
      document.documentElement.removeEventListener('mouseleave', handleMouseLeave);
      document.documentElement.removeEventListener('mouseenter', handleMouseEnter);
      if (rafId.current) cancelAnimationFrame(rafId.current);
    };
  }, [isEnabled]);

  if (!isEnabled) return null;

  return (
    <div ref={cursorRef} className="forensic-cursor-container" aria-hidden="true">
      <svg
        className="forensic-cursor-svg"
        width="36"
        height="36"
        viewBox="0 0 36 36"
        fill="none"
        xmlns="http://www.w3.org/2000/svg"
      >
        {/* Outer Focus Aura Ring (illuminates on hover) */}
        <circle
          className="cursor-focus-ring"
          cx="13"
          cy="13"
          r="12.2"
          stroke="#2563EB"
          strokeWidth="1.2"
          strokeDasharray="3 3"
          opacity="0"
        />

        {/* Circular Magnifying Lens - Clean Thin Outline */}
        <circle
          className="cursor-lens-frame"
          cx="13"
          cy="13"
          r="10.2"
          stroke="#0F172A"
          strokeWidth="1.8"
          fill="rgba(241, 245, 249, 0.45)"
        />

        {/* Lens Inner Glass Reflection Arc */}
        <path
          className="cursor-lens-glare"
          d="M 8 10.5 A 7.5 7.5 0 0 1 16 6.5"
          stroke="rgba(255, 255, 255, 0.9)"
          strokeWidth="1.2"
          strokeLinecap="round"
        />

        {/* Clearly Visible Centered "+" Sign */}
        {/* Horizontal bar of "+" */}
        <line
          className="cursor-plus-line cursor-plus-h"
          x1="8"
          y1="13"
          x2="18"
          y2="13"
          stroke="#2563EB"
          strokeWidth="2.2"
          strokeLinecap="round"
        />
        {/* Vertical bar of "+" */}
        <line
          className="cursor-plus-line cursor-plus-v"
          x1="13"
          y1="8"
          x2="13"
          y2="18"
          stroke="#2563EB"
          strokeWidth="2.2"
          strokeLinecap="round"
        />

        {/* Small Precision Handle Extending Proportionally from Lens */}
        <line
          className="cursor-handle"
          x1="20.5"
          y1="20.5"
          x2="31"
          y2="31"
          stroke="#0F172A"
          strokeWidth="2.8"
          strokeLinecap="round"
        />
        {/* Subtle Grip Accent Band on Handle */}
        <line
          className="cursor-handle-accent"
          x1="24"
          y1="24"
          x2="27"
          y2="27"
          stroke="#2563EB"
          strokeWidth="2.8"
          strokeLinecap="round"
        />
      </svg>
    </div>
  );
}
