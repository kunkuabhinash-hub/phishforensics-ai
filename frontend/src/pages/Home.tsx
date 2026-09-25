import React, { useState, useRef, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { apiService } from '../services/api';
import type { AnalysisRequest, InputType } from '../types';

/* ─────────────────────────────────────────────────────────────────
   LOADING STAGES
   ───────────────────────────────────────────────────────────────── */
const STAGES = [
  { id: '01', label: 'INGESTING ARTIFACT' },
  { id: '02', label: 'EXTRACTING SIGNALS' },
  { id: '03', label: 'ANALYZING INDICATORS' },
  { id: '04', label: 'BUILDING ATTACK DNA' },
  { id: '05', label: 'RECONSTRUCTING ATTACK' },
  { id: '06', label: 'GENERATING REPORT' },
];

/* ─────────────────────────────────────────────────────────────────
   DEMO DATA — Visual display only. Clearly labeled. Never
   used in production. Never passed to the API.
   ───────────────────────────────────────────────────────────────── */
const DEMO_DNA = [
  { label: 'Impersonation',      value: 87, color: 'var(--red-400)' },
  { label: 'Authority Signals',  value: 74, color: 'var(--red-400)' },
  { label: 'Urgency Triggers',   value: 68, color: 'var(--amber-300)' },
  { label: 'Fear Induction',     value: 55, color: 'var(--amber-300)' },
  { label: 'Credential Harvest', value: 91, color: 'var(--red-400)' },
  { label: 'Social Engineering', value: 62, color: 'var(--amber-300)' },
];

const DEMO_HISTORY = [
  { date: '2025-11-14', target: 'paypa1-secure.example.com', type: 'Credential Harvest', risk: 'HIGH',   status: 'COMPLETED' },
  { date: '2025-11-13', target: 'Email: IT Helpdesk Alert', type: 'Authority Impersonation', risk: 'HIGH',   status: 'COMPLETED' },
  { date: '2025-11-12', target: 'microsoft-update.example.net', type: 'Software Delivery', risk: 'MEDIUM', status: 'COMPLETED' },
  { date: '2025-11-10', target: 'Email: FedEx Delivery',    type: 'Package Phishing',  risk: 'MEDIUM', status: 'COMPLETED' },
  { date: '2025-11-09', target: 'secure-bank.example.org',  type: 'Financial Fraud',   risk: 'HIGH',   status: 'COMPLETED' },
];

const CAPABILITIES = [
  { label: 'AI Threat Analysis',        desc: 'Deep behavioral and structural analysis of phishing artifacts using AI.', wide: false },
  { label: 'Attack DNA',                desc: 'Converts attack signals into a structured behavioral fingerprint.',       wide: true  },
  { label: 'Email Forensics',           desc: 'Parse headers, SPF, DKIM, DMARC, and routing metadata.',                 wide: false },
  { label: 'Domain Intelligence',       desc: 'Lookalike detection, registration age, DNS analysis.',                   wide: false },
  { label: 'Social Engineering Detect', desc: 'Identify urgency, fear, authority, and manipulation tactics.',           wide: false },
  { label: 'Attack Reconstruction',     desc: 'Rebuild the probable attack chain step by step.',                        wide: true  },
  { label: 'Safe Simulation',           desc: 'See where the attack leads without executing malicious activity.',        wide: false },
  { label: 'Security Education',        desc: 'Learn from every investigation. Understand what happened and why.',      wide: false },
];

const PIPELINE_STEPS = [
  { n: '01', title: 'INGEST',       desc: 'Submit a suspicious URL, email, message, or image artifact.' },
  { n: '02', title: 'ANALYZE',      desc: 'AI examines language, structure, domains, auth signals, and threat patterns.' },
  { n: '03', title: 'FINGERPRINT',  desc: 'Generate Attack DNA — a behavioral fingerprint describing how the attack works.' },
  { n: '04', title: 'RECONSTRUCT',  desc: 'Rebuild the probable attack chain: trust, urgency, deception, action, compromise.' },
  { n: '05', title: 'EDUCATE',      desc: 'Understand what happened, why it worked, and how to recognize it next time.' },
];

/* ─────────────────────────────────────────────────────────────────
   COMPONENT
   ───────────────────────────────────────────────────────────────── */

export default function Home() {
  const navigate = useNavigate();
  const [inputType, setInputType] = useState<InputType>('url');
  const [inputValue, setInputValue] = useState('');
  const [imagePreview, setImagePreview] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [loadingStage, setLoadingStage] = useState(-1);
  const [error, setError] = useState<string | null>(null);
  const [validationError, setValidationError] = useState<string | null>(null);
  const fileRef = useRef<HTMLInputElement>(null);
  const [historyFilter, setHistoryFilter] = useState<'ALL' | 'HIGH' | 'MEDIUM' | 'LOW'>('ALL');
  const [demoAnimated, setDemoAnimated] = useState(false);
  const dnaRef = useRef<HTMLDivElement>(null);

  /* Animate DNA bars on scroll into view */
  useEffect(() => {
    if (!dnaRef.current) return;
    const obs = new IntersectionObserver(
      ([entry]) => { if (entry.isIntersecting) setDemoAnimated(true); },
      { threshold: 0.3 }
    );
    obs.observe(dnaRef.current);
    return () => obs.disconnect();
  }, []);

  /* Advance loading stage indicator */
  useEffect(() => {
    if (!isLoading) { setLoadingStage(-1); return; }
    let cancelled = false;
    STAGES.forEach(({ }, idx) => {
      setTimeout(() => { if (!cancelled) setLoadingStage(idx); }, idx * 900);
    });
    return () => { cancelled = true; };
  }, [isLoading]);

  /* ── Form handlers ── */
  const handleTextChange = (e: React.ChangeEvent<HTMLTextAreaElement | HTMLInputElement>) => {
    setInputValue(e.target.value);
    setValidationError(null);
    setError(null);
  };

  const handleImageUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    if (!file.type.startsWith('image/')) { setValidationError('Please upload a valid image file.'); return; }
    const reader = new FileReader();
    reader.onloadend = () => {
      const b64 = reader.result as string;
      setInputValue(b64);
      setImagePreview(b64);
      setValidationError(null);
      setError(null);
    };
    reader.readAsDataURL(file);
  };

  const validate = (): boolean => {
    if (inputType === 'url') {
      if (!inputValue.trim()) { setValidationError('URL cannot be empty.'); return false; }
      try { new URL(inputValue); } catch { setValidationError('Please enter a valid URL (include https://).'); return false; }
    } else if (inputType === 'text') {
      if (!inputValue.trim()) { setValidationError('Content cannot be empty.'); return false; }
    } else if (inputType === 'image') {
      if (!inputValue) { setValidationError('Please select an image.'); return false; }
    }
    return true;
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!validate() || isLoading) return;
    setIsLoading(true);
    setError(null);
    try {
      const request: AnalysisRequest = { type: inputType, content: inputValue };
      const response = await apiService.submitAnalysis(request);
      navigate('/dashboard', { state: { analysisResult: { ...response, originalRequest: request } } });
    } catch (err: any) {
      setError(err.message || 'Analysis engine unavailable. Ensure the backend API is running.');
      setIsLoading(false);
    }
  };

  const switchTab = (type: InputType) => {
    setInputType(type);
    setInputValue('');
    setImagePreview(null);
    setError(null);
    setValidationError(null);
  };

  const filteredHistory = historyFilter === 'ALL'
    ? DEMO_HISTORY
    : DEMO_HISTORY.filter(h => h.risk === historyFilter);

  /* ── RENDER ── */
  return (
    <div style={{ position: 'relative' }}>

      {/* ══════════════════════════════════════════════
          CINEMATIC LOADING OVERLAY
          ══════════════════════════════════════════════ */}
      {isLoading && (
        <div className="loading-overlay" role="status" aria-live="polite" aria-label="Forensic analysis in progress">
          <div className="loading-panel">
            <div className="l-spinner" aria-hidden="true" />
            <div className="loading-title">FORENSIC ENGINE INITIALIZING</div>
            <div className="loading-stages">
              {STAGES.map(({ id, label }, idx) => {
                const done   = idx < loadingStage;
                const active = idx === loadingStage;
                return (
                  <div key={id} className={`loading-stage-row ${active ? 'l-active' : ''} ${done ? 'l-done' : ''}`}>
                    <span className="l-dot" aria-hidden="true" />
                    <span style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: '0.72rem' }}>
                      {id} / {label}{done ? ' ✓' : ''}
                    </span>
                  </div>
                );
              })}
            </div>
          </div>
        </div>
      )}

      {/* ══════════════════════════════════════════════
          HERO
          ══════════════════════════════════════════════ */}
      <section
        aria-label="Hero"
        style={{
          paddingTop: 'clamp(80px, 12vw, 140px)',
          paddingBottom: 'clamp(80px, 10vw, 120px)',
          position: 'relative',
          overflow: 'hidden',
        }}
      >
        {/* Radial glow behind headline */}
        <div aria-hidden="true" style={{
          position: 'absolute',
          top: '-20%',
          left: '50%',
          transform: 'translateX(-50%)',
          width: '900px',
          height: '600px',
          background: 'radial-gradient(ellipse at center, rgba(34,211,238,0.07) 0%, transparent 65%)',
          pointerEvents: 'none',
        }} />

        <div className="container">
          <div style={{ display: 'grid', gridTemplateColumns: '1fr', gap: 64, alignItems: 'center' }}>
            {/* LEFT: Editorial headline */}
            <div style={{ maxWidth: 820, animation: 'fadeUp 0.7s var(--ease-premium) both' }}>
              {/* Eyebrow */}
              <p className="eyebrow" style={{ marginBottom: 28 }}>
                AI-Powered Digital Threat Forensics
              </p>

              {/* Large display headline */}
              <div style={{ marginBottom: 32 }}>
                <h1 style={{
                  fontFamily: 'Inter, sans-serif',
                  fontSize: 'clamp(3.2rem, 8.5vw, 7.5rem)',
                  fontWeight: 900,
                  lineHeight: 0.91,
                  letterSpacing: '-0.04em',
                  color: 'var(--text-0)',
                  textTransform: 'uppercase',
                }}>
                  Don't just<br />
                  detect the<br />
                  <span style={{ color: 'var(--cyan)' }}>phishing.</span>
                </h1>
                <p style={{
                  fontFamily: 'Inter, sans-serif',
                  fontSize: 'clamp(3.2rem, 8.5vw, 7.5rem)',
                  fontWeight: 900,
                  lineHeight: 0.91,
                  letterSpacing: '-0.04em',
                  color: 'transparent',
                  WebkitTextStroke: '1.5px rgba(248,250,252,0.25)',
                  textTransform: 'uppercase',
                  marginTop: 4,
                }}>
                  Reconstruct<br />the attack.
                </p>
              </div>

              {/* Subhead */}
              <p style={{
                fontSize: 'clamp(0.95rem, 2vw, 1.125rem)',
                lineHeight: 1.7,
                color: 'var(--text-2)',
                maxWidth: 520,
                marginBottom: 40,
              }}>
                PhishForensics AI transforms suspicious emails, URLs, and digital
                artifacts into a structured forensic investigation — extracting
                Attack DNA and reconstructing the attacker's full strategy.
              </p>

              {/* CTAs */}
              <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>
                <a
                  href="#investigate"
                  className="btn btn-primary btn-lg btn-arrow"
                  style={{ textDecoration: 'none' }}
                >
                  Start Investigation
                </a>
                <a
                  href="#how-it-works"
                  className="btn btn-ghost btn-lg"
                  style={{ textDecoration: 'none' }}
                >
                  Explore Forensics
                </a>
              </div>
            </div>

            {/* RIGHT: Forensic preview card — illustrative demo */}
            <div
              aria-label="Illustrative forensic signal display — demo only"
              style={{
                maxWidth: 420,
                animation: 'fadeUp 0.9s 0.15s var(--ease-premium) both',
              }}
            >
              <div
                style={{
                  background: 'var(--surface-0)',
                  border: '1px solid var(--border-0)',
                  borderRadius: 14,
                  overflow: 'hidden',
                  boxShadow: '0 0 60px rgba(34,211,238,0.06), 0 24px 80px rgba(0,0,0,0.5)',
                }}
              >
                {/* Card header */}
                <div style={{
                  padding: '12px 16px',
                  borderBottom: '1px solid var(--border-0)',
                  display: 'flex',
                  justifyContent: 'space-between',
                  alignItems: 'center',
                  background: 'rgba(8,12,18,0.6)',
                }}>
                  <span style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: '0.65rem', letterSpacing: '0.18em', color: 'var(--text-3)', textTransform: 'uppercase' }}>
                    Forensic Signal — DEMO
                  </span>
                  <span className="badge badge-red">● LIVE</span>
                </div>

                <div style={{ padding: '24px 20px' }}>
                  {/* Big score */}
                  <div style={{ display: 'flex', alignItems: 'flex-end', gap: 12, marginBottom: 20 }}>
                    <div style={{
                      fontFamily: 'JetBrains Mono, monospace',
                      fontSize: '5rem',
                      fontWeight: 700,
                      lineHeight: 1,
                      color: 'var(--red-400)',
                      letterSpacing: '-0.04em',
                    }}>87</div>
                    <div>
                      <div style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: '0.65rem', letterSpacing: '0.18em', color: 'var(--text-3)', marginBottom: 4, textTransform: 'uppercase' }}>Threat Score</div>
                      <span className="badge badge-red">HIGH RISK</span>
                    </div>
                  </div>

                  {/* Meta grid */}
                  {[
                    ['Attack Type',  'Credential Harvest'],
                    ['Confidence',   '94%'],
                    ['Signals',      '17 indicators'],
                    ['Attack Vector','Lookalike Domain'],
                  ].map(([k, v]) => (
                    <div key={k} className="data-row">
                      <span className="data-label">{k}</span>
                      <span className="data-value" style={{ color: 'var(--text-1)' }}>{v}</span>
                    </div>
                  ))}

                  {/* Mini DNA bars */}
                  <div style={{ marginTop: 20 }}>
                    <p style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: '0.62rem', letterSpacing: '0.18em', color: 'var(--text-4)', textTransform: 'uppercase', marginBottom: 10 }}>Attack DNA Preview</p>
                    {DEMO_DNA.slice(0, 3).map(({ label, value, color }) => (
                      <div key={label} style={{ marginBottom: 8 }}>
                        <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}>
                          <span style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: '0.65rem', color: 'var(--text-3)' }}>{label}</span>
                          <span style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: '0.65rem', color }}>{value}%</span>
                        </div>
                        <div style={{ height: 3, background: 'var(--border-0)', borderRadius: 2 }}>
                          <div style={{ height: '100%', width: `${value}%`, borderRadius: 2, background: color, transition: 'width 1.2s var(--ease-premium)' }} />
                        </div>
                      </div>
                    ))}
                  </div>

                  <p style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: '0.6rem', color: 'var(--text-4)', marginTop: 16, letterSpacing: '0.08em' }}>
                    * Illustrative demo values only. Not a real analysis.
                  </p>
                </div>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* ══════════════════════════════════════════════
          INVESTIGATE INPUT MODULE
          ══════════════════════════════════════════════ */}
      <section
        id="investigate"
        aria-labelledby="investigate-heading"
        style={{ paddingBottom: 'clamp(80px, 10vw, 120px)' }}
      >
        <div className="container">
          <div style={{ maxWidth: 780, margin: '0 auto' }}>
            {/* Section label */}
            <div style={{ display: 'flex', alignItems: 'center', gap: 16, marginBottom: 40 }}>
              <div style={{ flex: 1, height: 1, background: 'var(--border-0)' }} />
              <p className="eyebrow" style={{ whiteSpace: 'nowrap' }}>
                Start a Forensic Investigation
              </p>
              <div style={{ flex: 1, height: 1, background: 'var(--border-0)' }} />
            </div>

            {/* Panel */}
            <div style={{
              background: 'var(--surface-0)',
              border: '1px solid var(--border-0)',
              borderRadius: 14,
              overflow: 'hidden',
              boxShadow: '0 0 40px rgba(34,211,238,0.05), 0 24px 60px rgba(0,0,0,0.4)',
              position: 'relative',
            }}>
              {/* Top glow edge */}
              <div aria-hidden="true" style={{
                position: 'absolute',
                top: 0,
                left: '10%',
                right: '10%',
                height: 1,
                background: 'linear-gradient(90deg, transparent, var(--cyan), transparent)',
                opacity: 0.5,
              }} />

              {/* Console metadata strip */}
              <div style={{
                padding: '10px 20px',
                borderBottom: '1px solid var(--border-0)',
                background: 'rgba(5,7,10,0.7)',
                display: 'flex',
                gap: 20,
                alignItems: 'center',
              }}>
                {[
                  ['INPUT CHANNEL', inputType.toUpperCase()],
                  ['ANALYSIS ENGINE', 'FORENSIC AI'],
                  ['MODE', 'THREAT ANALYSIS'],
                ].map(([k, v]) => (
                  <div key={k} style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
                    <span style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: '0.58rem', letterSpacing: '0.18em', color: 'var(--text-4)', textTransform: 'uppercase' }}>{k}</span>
                    <span style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: '0.65rem', color: 'var(--cyan)', fontWeight: 600 }}>{v}</span>
                  </div>
                ))}
              </div>

              {/* Tabs */}
              <div role="tablist" aria-label="Artifact type" style={{ display: 'flex', borderBottom: '1px solid var(--border-0)', background: 'rgba(8,12,18,0.5)' }}>
                {(['url', 'text', 'image'] as InputType[]).map((type) => {
                  const labels: Record<InputType, string> = { url: 'URL', text: 'Email / Text', image: 'Screenshot' };
                  const active = inputType === type;
                  return (
                    <button
                      key={type}
                      role="tab"
                      id={`tab-${type}`}
                      aria-selected={active}
                      aria-controls={`panel-${type}`}
                      onClick={() => switchTab(type)}
                      type="button"
                      style={{
                        flex: 1,
                        background: 'transparent',
                        border: 'none',
                        borderBottom: active ? '2px solid var(--cyan)' : '2px solid transparent',
                        color: active ? 'var(--cyan)' : 'var(--text-3)',
                        padding: '12px 16px',
                        fontFamily: 'JetBrains Mono, monospace',
                        fontSize: '0.7rem',
                        fontWeight: 600,
                        letterSpacing: '0.14em',
                        textTransform: 'uppercase',
                        cursor: 'pointer',
                        transition: 'all 0.2s',
                        marginBottom: -1,
                      }}
                    >
                      {labels[type]}
                    </button>
                  );
                })}
              </div>

              {/* Form */}
              <form onSubmit={handleSubmit} style={{ padding: '24px 24px 20px' }} noValidate aria-label="Forensic investigation form">

                {inputType === 'url' && (
                  <div role="tabpanel" id="panel-url" aria-labelledby="tab-url" className="form-group" style={{ marginBottom: 0 }}>
                    <label htmlFor="url-input" className="form-label">Target URL</label>
                    <input
                      id="url-input"
                      type="url"
                      placeholder="https://suspicious-domain.example.com/verify"
                      value={inputValue}
                      onChange={handleTextChange}
                      disabled={isLoading}
                      aria-invalid={!!validationError}
                      autoComplete="off"
                      spellCheck={false}
                      style={{ fontSize: '0.9rem' }}
                    />
                  </div>
                )}

                {inputType === 'text' && (
                  <div role="tabpanel" id="panel-text" aria-labelledby="tab-text" className="form-group" style={{ marginBottom: 0 }}>
                    <label htmlFor="text-input" className="form-label">Email Headers / Body / Suspicious Text</label>
                    <textarea
                      id="text-input"
                      placeholder={"Paste email headers, HTML body, or suspicious message content here...\n\nFrom: no-reply@paypa1-security.example.com\nSubject: Your account has been suspended\n..."}
                      value={inputValue}
                      onChange={handleTextChange}
                      rows={8}
                      disabled={isLoading}
                      aria-invalid={!!validationError}
                      spellCheck={false}
                    />
                    <div className="char-count">{inputValue.length.toLocaleString()} chars</div>
                  </div>
                )}

                {inputType === 'image' && (
                  <div role="tabpanel" id="panel-image" aria-labelledby="tab-image" className="form-group" style={{ marginBottom: 0 }}>
                    <label htmlFor="image-input" className="form-label">Screenshot or Image Evidence</label>
                    <div className="file-input-zone">
                      <input
                        id="image-input"
                        type="file"
                        accept="image/*"
                        onChange={handleImageUpload}
                        ref={fileRef}
                        disabled={isLoading}
                        className="file-input"
                        aria-invalid={!!validationError}
                      />
                      <p style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: '0.75rem', color: 'var(--text-3)', letterSpacing: '0.08em' }}>
                        Drop image or <span style={{ color: 'var(--cyan)', fontWeight: 600 }}>browse</span>
                      </p>
                      <p style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: '0.62rem', color: 'var(--text-4)', marginTop: 6 }}>PNG · JPG · WEBP · GIF</p>
                    </div>
                    {imagePreview && (
                      <div style={{ marginTop: 12, border: '1px solid var(--border-0)', borderRadius: 8, overflow: 'hidden', background: 'var(--void)' }}>
                        <p style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: '0.62rem', letterSpacing: '0.14em', color: 'var(--text-4)', textTransform: 'uppercase', padding: '6px 12px', borderBottom: '1px solid var(--border-0)' }}>Evidence Preview</p>
                        <img src={imagePreview} alt="Uploaded evidence" style={{ maxWidth: '100%', maxHeight: 220, display: 'block', margin: '0 auto', padding: 12, objectFit: 'contain' }} />
                      </div>
                    )}
                  </div>
                )}

                {/* Error messages */}
                {validationError && (
                  <div className="error-message validation-error" role="alert" aria-live="assertive">
                    ⚠ {validationError}
                  </div>
                )}
                {error && (
                  <div className="error-message api-error" role="alert" aria-live="assertive">
                    <strong>ENGINE UNAVAILABLE:</strong> {error}
                  </div>
                )}

                {/* Action bar */}
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginTop: 20, paddingTop: 16, borderTop: '1px solid var(--border-0)', gap: 12, flexWrap: 'wrap' }}>
                  <span style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: '0.62rem', color: 'var(--text-4)', letterSpacing: '0.1em' }}>
                    POST /api/analyze → FORENSIC ENGINE
                  </span>
                  <button
                    type="submit"
                    className={`analyze-btn btn-arrow${isLoading ? ' loading' : ''}`}
                    disabled={isLoading}
                    aria-busy={isLoading}
                  >
                    {isLoading ? 'Analyzing…' : 'Analyze Threat'}
                  </button>
                </div>
              </form>
            </div>
          </div>
        </div>
      </section>

      {/* ══════════════════════════════════════════════
          THE PROBLEM
          ══════════════════════════════════════════════ */}
      <section
        className="section"
        style={{ borderTop: '1px solid var(--border-0)' }}
        aria-labelledby="problem-heading"
      >
        <div className="container">
          <div style={{ display: 'grid', gridTemplateColumns: '1fr', gap: 64 }}>
            <div style={{ animation: 'fadeUp 0.6s var(--ease-premium) both' }}>
              <p className="eyebrow" style={{ marginBottom: 24 }}>01 / The Problem</p>
              <h2 style={{
                fontSize: 'clamp(2.4rem, 6vw, 5.5rem)',
                fontWeight: 900,
                lineHeight: 0.92,
                letterSpacing: '-0.03em',
                color: 'var(--text-0)',
                textTransform: 'uppercase',
                marginBottom: 32,
              }}>
                Phishing isn't<br />
                just a suspicious<br />
                <span style={{ color: 'var(--red-400)' }}>link.</span>
              </h2>
              <p style={{ fontSize: '1.05rem', lineHeight: 1.75, color: 'var(--text-2)', maxWidth: 540, marginBottom: 24 }}>
                Modern phishing attacks combine impersonation, urgency, social engineering,
                malicious infrastructure, credential harvesting, and psychological
                manipulation into a precisely crafted deception.
              </p>
              <p style={{ fontSize: '1.05rem', lineHeight: 1.75, color: 'var(--text-2)', maxWidth: 540, marginBottom: 32 }}>
                Traditional detection answers one question:{' '}
                <em style={{ color: 'var(--text-1)', fontStyle: 'normal', fontWeight: 600 }}>"Is this phishing?"</em>
                <br /><br />
                PhishForensics AI asks the deeper question:{' '}
                <em style={{ color: 'var(--cyan)', fontStyle: 'normal', fontWeight: 700 }}>"HOW DID THE ATTACK WORK?"</em>
              </p>

              {/* Flow */}
              <div style={{ display: 'flex', alignItems: 'center', gap: 12, flexWrap: 'wrap' }}>
                {['DETECT', 'UNDERSTAND', 'RECONSTRUCT', 'EDUCATE'].map((step, i, arr) => (
                  <React.Fragment key={step}>
                    <div style={{
                      padding: '8px 16px',
                      border: '1px solid var(--border-1)',
                      borderRadius: 6,
                      fontFamily: 'JetBrains Mono, monospace',
                      fontSize: '0.72rem',
                      fontWeight: 600,
                      letterSpacing: '0.12em',
                      color: i === arr.length - 1 ? 'var(--cyan)' : 'var(--text-2)',
                      borderColor: i === arr.length - 1 ? 'rgba(34,211,238,0.35)' : 'var(--border-0)',
                      background: i === arr.length - 1 ? 'rgba(34,211,238,0.05)' : 'transparent',
                    }}>
                      {step}
                    </div>
                    {i < arr.length - 1 && (
                      <span style={{ color: 'var(--text-4)', fontFamily: 'JetBrains Mono, monospace', fontSize: '0.7rem' }}>→</span>
                    )}
                  </React.Fragment>
                ))}
              </div>
            </div>

            {/* Differentiator columns */}
            <div>
              <h3 style={{ fontSize: 'clamp(1.4rem, 3vw, 2rem)', fontWeight: 800, letterSpacing: '-0.02em', color: 'var(--text-0)', textTransform: 'uppercase', marginBottom: 32 }}>
                From Detection<br />to Digital Forensics.
              </h3>
              <div className="grid-2">
                {/* Traditional */}
                <div style={{ padding: 24, border: '1px solid var(--border-0)', borderRadius: 10, background: 'rgba(5,7,10,0.4)' }}>
                  <p style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: '0.65rem', letterSpacing: '0.18em', color: 'var(--text-4)', textTransform: 'uppercase', marginBottom: 16 }}>
                    Traditional Detection
                  </p>
                  <ul style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
                    {['Suspicious / Safe verdict', 'Basic indicator list', 'Isolated signal analysis', 'Minimal explanation', 'No attack context'].map(item => (
                      <li key={item} style={{ display: 'flex', gap: 10, alignItems: 'flex-start', fontSize: '0.875rem', color: 'var(--text-3)' }}>
                        <span style={{ color: 'var(--border-2)', flexShrink: 0, marginTop: 2 }}>—</span> {item}
                      </li>
                    ))}
                  </ul>
                </div>
                {/* PhishForensics */}
                <div style={{ padding: 24, border: '1px solid rgba(34,211,238,0.2)', borderRadius: 10, background: 'rgba(34,211,238,0.03)' }}>
                  <p style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: '0.65rem', letterSpacing: '0.18em', color: 'var(--cyan)', textTransform: 'uppercase', marginBottom: 16 }}>
                    PhishForensics AI
                  </p>
                  <ul style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
                    {['Full threat analysis', 'Evidence extraction', 'Attacker intent mapping', 'Psychological signal detection', 'Attack DNA fingerprint', 'Attack-chain reconstruction', 'Safe consequence simulation', 'Security education layer'].map(item => (
                      <li key={item} style={{ display: 'flex', gap: 10, alignItems: 'flex-start', fontSize: '0.875rem', color: 'var(--text-1)' }}>
                        <span style={{ color: 'var(--cyan)', flexShrink: 0, marginTop: 2, fontWeight: 700 }}>+</span> {item}
                      </li>
                    ))}
                  </ul>
                </div>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* ══════════════════════════════════════════════
          FORENSIC PIPELINE
          ══════════════════════════════════════════════ */}
      <section
        id="how-it-works"
        className="section"
        style={{ borderTop: '1px solid var(--border-0)' }}
        aria-labelledby="pipeline-heading"
      >
        <div className="container">
          <p className="eyebrow" style={{ marginBottom: 24 }}>02 / Forensic Pipeline</p>
          <h2
            id="pipeline-heading"
            style={{
              fontSize: 'clamp(2.4rem, 6vw, 5.5rem)',
              fontWeight: 900,
              lineHeight: 0.92,
              letterSpacing: '-0.03em',
              color: 'var(--text-0)',
              textTransform: 'uppercase',
              marginBottom: 64,
            }}
          >
            From Signal<br />
            to Attack<br />
            <span style={{ color: 'var(--cyan)' }}>Story.</span>
          </h2>

          {/* Steps */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: 0 }}>
            {PIPELINE_STEPS.map(({ n, title, desc }, i) => (
              <div
                key={n}
                style={{
                  display: 'grid',
                  gridTemplateColumns: '80px 1fr',
                  gap: 32,
                  padding: '32px 0',
                  borderBottom: i < PIPELINE_STEPS.length - 1 ? '1px solid var(--border-0)' : 'none',
                  alignItems: 'start',
                }}
              >
                <div style={{
                  fontFamily: 'JetBrains Mono, monospace',
                  fontSize: 'clamp(2rem, 4vw, 3rem)',
                  fontWeight: 700,
                  color: 'rgba(38,52,73,0.8)',
                  lineHeight: 1,
                  letterSpacing: '-0.02em',
                }}>
                  {n}
                </div>
                <div>
                  <p style={{
                    fontFamily: 'JetBrains Mono, monospace',
                    fontSize: '0.72rem',
                    letterSpacing: '0.18em',
                    color: 'var(--cyan)',
                    textTransform: 'uppercase',
                    fontWeight: 700,
                    marginBottom: 8,
                  }}>
                    {title}
                  </p>
                  <p style={{ fontSize: '1.05rem', lineHeight: 1.6, color: 'var(--text-2)', maxWidth: 540 }}>{desc}</p>
                </div>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* ══════════════════════════════════════════════
          ATTACK DNA
          ══════════════════════════════════════════════ */}
      <section
        id="attack-dna"
        className="section"
        style={{ borderTop: '1px solid var(--border-0)' }}
        aria-labelledby="dna-heading"
        ref={dnaRef}
      >
        <div className="container">
          <div style={{ display: 'grid', gridTemplateColumns: '1fr', gap: 64 }}>
            {/* Copy */}
            <div>
              <p className="eyebrow" style={{ marginBottom: 24 }}>03 / Attack DNA</p>
              <h2
                id="dna-heading"
                style={{
                  fontSize: 'clamp(2.4rem, 6vw, 5.5rem)',
                  fontWeight: 900,
                  lineHeight: 0.92,
                  letterSpacing: '-0.03em',
                  color: 'var(--text-0)',
                  textTransform: 'uppercase',
                  marginBottom: 24,
                }}
              >
                Every Phish<br />Leaves a<br />
                <span style={{ color: 'var(--cyan)' }}>Fingerprint.</span>
              </h2>
              <p style={{ fontSize: '1.05rem', lineHeight: 1.7, color: 'var(--text-2)', maxWidth: 500 }}>
                Attack DNA converts multiple phishing signals — language patterns,
                structural manipulation, psychological triggers, domain characteristics —
                into a structured behavioral fingerprint that describes how the attack
                was designed to work.
              </p>
            </div>

            {/* Demo DNA bars — clearly labeled illustrative */}
            <div
              style={{
                background: 'var(--surface-0)',
                border: '1px solid var(--border-0)',
                borderRadius: 14,
                overflow: 'hidden',
              }}
              aria-label="Attack DNA visualization — illustrative demo values only"
            >
              <div style={{
                padding: '12px 20px',
                borderBottom: '1px solid var(--border-0)',
                background: 'rgba(5,7,10,0.7)',
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'center',
              }}>
                <span style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: '0.65rem', letterSpacing: '0.16em', color: 'var(--text-3)', textTransform: 'uppercase' }}>
                  Attack DNA — DEMO
                </span>
                <span className="badge badge-red">HIGH RISK</span>
              </div>
              <div style={{ padding: '24px 20px' }}>
                {DEMO_DNA.map(({ label, value, color }) => (
                  <div key={label} style={{ marginBottom: 18 }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 7 }}>
                      <span style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: '0.72rem', color: 'var(--text-2)', letterSpacing: '0.04em' }}>{label}</span>
                      <span style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: '0.72rem', fontWeight: 600, color }}>{value}%</span>
                    </div>
                    <div style={{ height: 5, background: 'rgba(27,38,53,0.8)', borderRadius: 3, overflow: 'hidden' }}>
                      <div style={{
                        height: '100%',
                        width: demoAnimated ? `${value}%` : '0%',
                        borderRadius: 3,
                        background: color,
                        transition: `width 1.2s ${0.1 + DEMO_DNA.indexOf({ label, value, color } as typeof DEMO_DNA[0]) * 0.1}s var(--ease-premium)`,
                        boxShadow: `0 0 8px ${color}`,
                      }} />
                    </div>
                  </div>
                ))}
                <p style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: '0.6rem', color: 'var(--text-4)', marginTop: 8, letterSpacing: '0.08em' }}>
                  * Illustrative demo values. Real investigations use backend-derived data.
                </p>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* ══════════════════════════════════════════════
          ATTACK RECONSTRUCTION
          ══════════════════════════════════════════════ */}
      <section
        className="section"
        style={{ borderTop: '1px solid var(--border-0)' }}
        aria-labelledby="reconstruction-heading"
      >
        <div className="container">
          <p className="eyebrow" style={{ marginBottom: 24 }}>04 / Attack Reconstruction</p>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr', gap: 64, alignItems: 'start' }}>
            <div>
              <h2
                id="reconstruction-heading"
                style={{
                  fontSize: 'clamp(2.4rem, 6vw, 5.5rem)',
                  fontWeight: 900,
                  lineHeight: 0.92,
                  letterSpacing: '-0.03em',
                  color: 'var(--text-0)',
                  textTransform: 'uppercase',
                  marginBottom: 24,
                }}
              >
                Reconstruct<br />
                <span style={{ color: 'var(--red-400)' }}>The Attack.</span>
              </h2>
              <p style={{ fontSize: '1.05rem', lineHeight: 1.7, color: 'var(--text-2)', maxWidth: 500, marginBottom: 24 }}>
                PhishForensics doesn't just flag suspicious content. It rebuilds the
                probable attack chain — showing each stage the attacker designed
                to move the victim from trust to compromise.
              </p>
              <p style={{ fontSize: '0.875rem', lineHeight: 1.6, color: 'var(--text-3)' }}>
                The actual reconstruction sequence is dynamically generated by the AI
                from each submitted artifact. The chain below is illustrative.
              </p>
            </div>

            {/* Attack chain — illustrative */}
            <div
              aria-label="Illustrative attack chain — demo only"
              style={{ position: 'relative' }}
            >
              {/* Vertical line */}
              <div aria-hidden="true" style={{
                position: 'absolute',
                top: 0,
                bottom: 0,
                left: 23,
                width: 1,
                background: 'linear-gradient(to bottom, var(--cyan), rgba(244,63,94,0.4))',
              }} />

              <div style={{ display: 'flex', flexDirection: 'column', gap: 0, paddingLeft: 48 }}>
                {[
                  { n: '01', stage: 'TRUST', label: 'Impersonation Setup',   desc: 'Attacker mimics a trusted brand or authority figure.',             color: 'var(--cyan)' },
                  { n: '02', stage: 'URGENCY', label: 'Trigger Mechanism',   desc: 'Creates artificial time pressure to bypass critical thinking.',     color: 'var(--amber)' },
                  { n: '03', stage: 'DECEPTION', label: 'Content Payload',   desc: 'Delivers the phishing message with crafted persuasion elements.',   color: 'var(--amber)' },
                  { n: '04', stage: 'ACTION', label: 'Victim Engagement',    desc: 'Victim clicks link, opens attachment, or responds to request.',     color: 'var(--red-400)' },
                  { n: '05', stage: 'HARVEST', label: 'Credential Request',  desc: 'Fake login or form collects victim credentials or data.',           color: 'var(--red-400)' },
                  { n: '06', stage: 'COMPROMISE', label: 'Account Access',   desc: 'Attacker gains unauthorized access to victim accounts or data.',    color: 'var(--red)' },
                ].map(({ n, stage, label, desc, color }) => (
                  <div
                    key={n}
                    style={{
                      position: 'relative',
                      paddingBottom: 28,
                      paddingTop: 4,
                    }}
                  >
                    {/* Node */}
                    <div aria-hidden="true" style={{
                      position: 'absolute',
                      left: -37,
                      top: 8,
                      width: 14,
                      height: 14,
                      borderRadius: '50%',
                      border: `2px solid ${color}`,
                      background: 'var(--bg-0)',
                      boxShadow: `0 0 8px ${color}`,
                    }} />
                    <div style={{ display: 'flex', gap: 16, alignItems: 'flex-start' }}>
                      <span style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: '0.62rem', color: 'var(--text-4)', flexShrink: 0, paddingTop: 2 }}>{n}</span>
                      <div>
                        <div style={{ display: 'flex', gap: 10, alignItems: 'center', marginBottom: 4 }}>
                          <span style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: '0.72rem', fontWeight: 700, color, letterSpacing: '0.12em' }}>{stage}</span>
                          <span style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: '0.62rem', color: 'var(--text-4)', letterSpacing: '0.08em' }}>{label}</span>
                        </div>
                        <p style={{ fontSize: '0.875rem', color: 'var(--text-2)', lineHeight: 1.5 }}>{desc}</p>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
              <p style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: '0.6rem', color: 'var(--text-4)', paddingLeft: 48, letterSpacing: '0.08em' }}>
                * Illustrative sequence. Real reconstruction generated per investigation.
              </p>
            </div>
          </div>
        </div>
      </section>

      {/* ══════════════════════════════════════════════
          EVIDENCE BENTO
          ══════════════════════════════════════════════ */}
      <section
        className="section"
        style={{ borderTop: '1px solid var(--border-0)' }}
        aria-labelledby="evidence-heading"
      >
        <div className="container">
          <p className="eyebrow" style={{ marginBottom: 24 }}>Evidence Layer</p>
          <h2
            id="evidence-heading"
            style={{
              fontSize: 'clamp(2rem, 5vw, 4rem)',
              fontWeight: 900,
              lineHeight: 0.95,
              letterSpacing: '-0.03em',
              color: 'var(--text-0)',
              textTransform: 'uppercase',
              marginBottom: 48,
            }}
          >
            The Evidence<br />
            <span style={{ color: 'var(--cyan)' }}>Behind the Verdict.</span>
          </h2>

          {/* Bento grid */}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))', gap: 12 }}>
            {[
              { label: 'Email Headers', desc: 'Return-Path, Received, X-Originating-IP — full routing metadata extraction.', icon: '◼', color: 'var(--cyan)' },
              { label: 'SPF / DKIM / DMARC', desc: 'Authentication chain analysis — pass, fail, or softfail with context.', icon: '◼', color: 'var(--green-400)' },
              { label: 'Domain Intelligence', desc: 'Lookalike domain detection, registration age, DNS anomalies.', icon: '◼', color: 'var(--amber)' },
              { label: 'URL Analysis', desc: 'Redirect chains, suspicious TLDs, path patterns, and encoded payloads.', icon: '◼', color: 'var(--red-400)' },
              { label: 'Social Engineering', desc: 'Urgency, authority, fear, and manipulation language pattern detection.', icon: '◼', color: 'var(--magenta)' },
              { label: 'Attachment Signals', desc: 'Filename patterns, MIME types, and embedded link extraction.', icon: '◼', color: 'var(--amber)' },
            ].map(({ label, desc, icon, color }) => (
              <div
                key={label}
                style={{
                  background: 'var(--surface-0)',
                  border: '1px solid var(--border-0)',
                  borderRadius: 10,
                  padding: '20px 20px',
                  transition: 'all 0.25s var(--ease-premium)',
                  cursor: 'default',
                }}
                onMouseEnter={(e) => {
                  (e.currentTarget as HTMLDivElement).style.borderColor = 'var(--border-1)';
                  (e.currentTarget as HTMLDivElement).style.transform = 'translateY(-3px)';
                }}
                onMouseLeave={(e) => {
                  (e.currentTarget as HTMLDivElement).style.borderColor = 'var(--border-0)';
                  (e.currentTarget as HTMLDivElement).style.transform = 'translateY(0)';
                }}
              >
                <span style={{ fontSize: '0.7rem', color, display: 'block', marginBottom: 12 }}>{icon}</span>
                <p style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: '0.72rem', fontWeight: 700, letterSpacing: '0.1em', color: 'var(--text-1)', textTransform: 'uppercase', marginBottom: 8 }}>{label}</p>
                <p style={{ fontSize: '0.82rem', lineHeight: 1.6, color: 'var(--text-3)' }}>{desc}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* ══════════════════════════════════════════════
          SAFE SIMULATION + EDUCATION
          ══════════════════════════════════════════════ */}
      <section
        className="section"
        style={{ borderTop: '1px solid var(--border-0)' }}
        aria-labelledby="simulation-heading"
      >
        <div className="container">
          <div style={{ display: 'grid', gridTemplateColumns: '1fr', gap: 80 }}>
            {/* Simulation */}
            <div>
              <p className="eyebrow" style={{ marginBottom: 24 }}>Safe Simulation</p>
              <h2
                id="simulation-heading"
                style={{
                  fontSize: 'clamp(2rem, 5vw, 4rem)',
                  fontWeight: 900,
                  lineHeight: 0.95,
                  letterSpacing: '-0.03em',
                  color: 'var(--text-0)',
                  textTransform: 'uppercase',
                  marginBottom: 24,
                }}
              >
                See Where<br />The Attack<br /><span style={{ color: 'var(--amber)' }}>Leads.</span>
              </h2>
              <p style={{ fontSize: '1.05rem', lineHeight: 1.7, color: 'var(--text-2)', maxWidth: 500, marginBottom: 32 }}>
                The system safely reconstructs a likely consequence path — showing what
                the attacker designed the victim to do — without executing any malicious
                activity, fetching any malicious URLs, or collecting any credentials.
              </p>

              {/* Chain */}
              <div
                style={{ display: 'flex', alignItems: 'center', gap: 0, overflowX: 'auto', paddingBottom: 8 }}
                aria-label="Illustrative safe simulation consequence chain"
              >
                {[
                  'Suspicious Message',
                  'Victim Engagement',
                  'Credential Request',
                  'Account Risk',
                  'Data Exposure',
                ].map((step, i, arr) => (
                  <React.Fragment key={step}>
                    <div style={{
                      padding: '10px 16px',
                      background: 'var(--surface-0)',
                      border: '1px solid var(--border-0)',
                      borderRadius: 6,
                      whiteSpace: 'nowrap',
                      flexShrink: 0,
                    }}>
                      <p style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: '0.62rem', letterSpacing: '0.1em', color: 'var(--text-4)', textTransform: 'uppercase', marginBottom: 2 }}>
                        {String(i + 1).padStart(2, '0')}
                      </p>
                      <p style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: '0.72rem', fontWeight: 600, color: i >= arr.length - 2 ? 'var(--red-400)' : 'var(--text-1)' }}>
                        {step}
                      </p>
                    </div>
                    {i < arr.length - 1 && (
                      <div style={{ flexShrink: 0, padding: '0 4px', color: 'var(--border-2)' }}>→</div>
                    )}
                  </React.Fragment>
                ))}
              </div>
              <p style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: '0.6rem', color: 'var(--text-4)', marginTop: 12, letterSpacing: '0.08em' }}>
                SAFE SIMULATION — No real attack is performed. No malicious code executed.
              </p>
            </div>

            {/* Education */}
            <div>
              <p className="eyebrow" style={{ marginBottom: 24 }}>04 / Learn From the Attack</p>
              <h2
                style={{
                  fontSize: 'clamp(2rem, 5vw, 4rem)',
                  fontWeight: 900,
                  lineHeight: 0.95,
                  letterSpacing: '-0.03em',
                  color: 'var(--text-0)',
                  textTransform: 'uppercase',
                  marginBottom: 24,
                }}
              >
                Every Investigation<br />Should Teach<br /><span style={{ color: 'var(--green-400)' }}>Something.</span>
              </h2>
              <p style={{ fontSize: '1.05rem', lineHeight: 1.7, color: 'var(--text-2)', maxWidth: 500, marginBottom: 32 }}>
                After every analysis, PhishForensics generates a structured security
                lesson — helping users recognize similar attacks, understand attacker
                psychology, and build lasting defensive awareness.
              </p>

              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: 10 }}>
                {[
                  { q: 'Why did it look real?',     sub: 'Impersonation & trust signals explained' },
                  { q: 'What signals were missed?', sub: 'Detection indicators from the analysis' },
                  { q: 'What did the attacker want?', sub: 'Intent and objective decoded' },
                  { q: 'What to check next time?',  sub: 'Actionable defensive guidance' },
                ].map(({ q, sub }) => (
                  <div key={q} style={{
                    padding: '16px',
                    background: 'rgba(16,185,129,0.04)',
                    border: '1px solid rgba(16,185,129,0.15)',
                    borderRadius: 8,
                  }}>
                    <p style={{ fontSize: '0.85rem', fontWeight: 600, color: 'var(--text-0)', lineHeight: 1.4, marginBottom: 6 }}>{q}</p>
                    <p style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: '0.65rem', color: 'var(--text-3)', letterSpacing: '0.05em' }}>{sub}</p>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* ══════════════════════════════════════════════
          CAPABILITIES GRID
          ══════════════════════════════════════════════ */}
      <section
        className="section"
        style={{ borderTop: '1px solid var(--border-0)' }}
        aria-labelledby="capabilities-heading"
      >
        <div className="container">
          <p className="eyebrow" style={{ marginBottom: 24 }}>Capabilities</p>
          <h2
            id="capabilities-heading"
            style={{
              fontSize: 'clamp(2rem, 4vw, 3.5rem)',
              fontWeight: 900,
              lineHeight: 0.95,
              letterSpacing: '-0.03em',
              color: 'var(--text-0)',
              textTransform: 'uppercase',
              marginBottom: 48,
            }}
          >
            Built for Complete<br />
            <span style={{ color: 'var(--cyan)' }}>Forensic Analysis.</span>
          </h2>

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))', gap: 10 }}>
            {CAPABILITIES.map(({ label, desc, wide }) => (
              <div
                key={label}
                style={{
                  gridColumn: wide ? 'span 2' : 'span 1',
                  background: 'var(--surface-0)',
                  border: '1px solid var(--border-0)',
                  borderRadius: 10,
                  padding: wide ? '28px 28px' : '20px 20px',
                  display: 'flex',
                  flexDirection: 'column',
                  gap: 10,
                  transition: 'all 0.25s var(--ease-premium)',
                }}
                onMouseEnter={(e) => {
                  const el = e.currentTarget as HTMLDivElement;
                  el.style.borderColor = 'rgba(34,211,238,0.25)';
                  el.style.transform = 'translateY(-2px)';
                }}
                onMouseLeave={(e) => {
                  const el = e.currentTarget as HTMLDivElement;
                  el.style.borderColor = 'var(--border-0)';
                  el.style.transform = 'translateY(0)';
                }}
              >
                <p style={{
                  fontFamily: 'JetBrains Mono, monospace',
                  fontSize: wide ? '0.82rem' : '0.72rem',
                  fontWeight: 700,
                  letterSpacing: '0.1em',
                  color: 'var(--text-0)',
                  textTransform: 'uppercase',
                }}>
                  {label}
                </p>
                <p style={{ fontSize: '0.82rem', lineHeight: 1.6, color: 'var(--text-3)' }}>{desc}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* ══════════════════════════════════════════════
          DASHBOARD HISTORY PREVIEW — DEMO DATA
          ══════════════════════════════════════════════ */}
      <section
        className="section"
        style={{ borderTop: '1px solid var(--border-0)' }}
        aria-labelledby="history-heading"
      >
        <div className="container">
          <p className="eyebrow" style={{ marginBottom: 24 }}>Investigation History</p>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-end', flexWrap: 'wrap', gap: 24, marginBottom: 40 }}>
            <h2
              id="history-heading"
              style={{
                fontSize: 'clamp(2rem, 4vw, 3.5rem)',
                fontWeight: 900,
                lineHeight: 0.95,
                letterSpacing: '-0.03em',
                color: 'var(--text-0)',
                textTransform: 'uppercase',
              }}
            >
              Your Investigations.<br />
              <span style={{ color: 'var(--cyan)' }}>One Forensic View.</span>
            </h2>
            <p style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: '0.65rem', color: 'var(--text-4)', letterSpacing: '0.12em', textTransform: 'uppercase' }}>
              * Development preview — demo data only
            </p>
          </div>

          {/* Filter controls */}
          <div style={{ display: 'flex', gap: 6, marginBottom: 16, flexWrap: 'wrap' }}>
            {(['ALL', 'HIGH', 'MEDIUM', 'LOW'] as const).map(f => (
              <button
                key={f}
                onClick={() => setHistoryFilter(f)}
                style={{
                  fontFamily: 'JetBrains Mono, monospace',
                  fontSize: '0.65rem',
                  fontWeight: 600,
                  letterSpacing: '0.12em',
                  textTransform: 'uppercase',
                  padding: '6px 14px',
                  border: '1px solid',
                  borderRadius: 999,
                  cursor: 'pointer',
                  transition: 'all 0.2s',
                  background: historyFilter === f
                    ? f === 'HIGH' ? 'rgba(244,63,94,0.1)' : f === 'MEDIUM' ? 'rgba(245,158,11,0.1)' : f === 'LOW' ? 'rgba(16,185,129,0.1)' : 'rgba(34,211,238,0.1)'
                    : 'transparent',
                  borderColor: historyFilter === f
                    ? f === 'HIGH' ? 'rgba(244,63,94,0.3)' : f === 'MEDIUM' ? 'rgba(245,158,11,0.3)' : f === 'LOW' ? 'rgba(16,185,129,0.3)' : 'rgba(34,211,238,0.3)'
                    : 'var(--border-0)',
                  color: historyFilter === f
                    ? f === 'HIGH' ? 'var(--red-400)' : f === 'MEDIUM' ? 'var(--amber-300)' : f === 'LOW' ? 'var(--green-400)' : 'var(--cyan)'
                    : 'var(--text-3)',
                }}
              >
                {f}
              </button>
            ))}
          </div>

          {/* Table */}
          <div style={{ border: '1px solid var(--border-0)', borderRadius: 10, overflow: 'hidden' }}>
            {/* Header */}
            <div style={{
              display: 'grid',
              gridTemplateColumns: '100px 1fr 180px 80px 100px',
              gap: 0,
              padding: '10px 20px',
              background: 'rgba(5,7,10,0.7)',
              borderBottom: '1px solid var(--border-0)',
            }}>
              {['DATE', 'TARGET', 'ATTACK TYPE', 'RISK', 'STATUS'].map(h => (
                <span key={h} style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: '0.62rem', letterSpacing: '0.14em', color: 'var(--text-4)', textTransform: 'uppercase' }}>{h}</span>
              ))}
            </div>
            {filteredHistory.map((row, i) => (
              <div
                key={i}
                style={{
                  display: 'grid',
                  gridTemplateColumns: '100px 1fr 180px 80px 100px',
                  gap: 0,
                  padding: '14px 20px',
                  borderBottom: i < filteredHistory.length - 1 ? '1px solid rgba(27,38,53,0.5)' : 'none',
                  background: 'var(--surface-0)',
                  transition: 'background 0.15s',
                  cursor: 'default',
                }}
                onMouseEnter={(e) => { (e.currentTarget as HTMLDivElement).style.background = 'var(--surface-1)'; }}
                onMouseLeave={(e) => { (e.currentTarget as HTMLDivElement).style.background = 'var(--surface-0)'; }}
              >
                <span style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: '0.72rem', color: 'var(--text-3)' }}>{row.date}</span>
                <span style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: '0.72rem', color: 'var(--text-1)', paddingRight: 16, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{row.target}</span>
                <span style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: '0.72rem', color: 'var(--text-2)' }}>{row.type}</span>
                <span style={{
                  fontFamily: 'JetBrains Mono, monospace',
                  fontSize: '0.65rem',
                  fontWeight: 700,
                  color: row.risk === 'HIGH' ? 'var(--red-400)' : row.risk === 'MEDIUM' ? 'var(--amber-300)' : 'var(--green-400)',
                }}>
                  {row.risk}
                </span>
                <span className={`badge badge-muted`} style={{ fontSize: '0.6rem', letterSpacing: '0.08em' }}>{row.status}</span>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* ══════════════════════════════════════════════
          ARCHITECTURE
          ══════════════════════════════════════════════ */}
      <section
        className="section"
        style={{ borderTop: '1px solid var(--border-0)' }}
        aria-labelledby="arch-heading"
      >
        <div className="container">
          <p className="eyebrow" style={{ marginBottom: 24 }}>Architecture</p>
          <h2
            id="arch-heading"
            style={{
              fontSize: 'clamp(1.8rem, 4vw, 3.5rem)',
              fontWeight: 900,
              lineHeight: 0.95,
              letterSpacing: '-0.03em',
              color: 'var(--text-0)',
              textTransform: 'uppercase',
              marginBottom: 48,
            }}
          >
            Built for<br />
            <span style={{ color: 'var(--cyan)' }}>Fast Forensic Analysis.</span>
          </h2>

          <div style={{ display: 'flex', gap: 0, alignItems: 'stretch', flexWrap: 'wrap', border: '1px solid var(--border-0)', borderRadius: 12, overflow: 'hidden' }}>
            {[
              { label: 'USER INPUT',     sub: 'URL / Email / Image / Text',   color: 'var(--text-2)' },
              { label: 'FRONTEND',       sub: 'React + Vite + TypeScript',     color: 'var(--cyan)' },
              { label: 'BACKEND API',    sub: '/api/analyze → POST',           color: 'var(--text-2)' },
              { label: 'AI ANALYSIS',    sub: 'Threat extraction engine',      color: 'var(--magenta)' },
              { label: 'ATTACK DNA',     sub: 'Behavioral fingerprint',        color: 'var(--amber)' },
              { label: 'RECONSTRUCTION', sub: 'Attack chain rebuild',          color: 'var(--red-400)' },
              { label: 'EDUCATION',      sub: 'Security lesson layer',         color: 'var(--green-400)' },
            ].map(({ label, sub, color }, i, arr) => (
              <div
                key={label}
                style={{
                  flex: '1 1 120px',
                  padding: '20px 16px',
                  borderRight: i < arr.length - 1 ? '1px solid var(--border-0)' : 'none',
                  background: 'var(--surface-0)',
                  textAlign: 'center',
                  transition: 'background 0.2s',
                }}
                onMouseEnter={(e) => { (e.currentTarget as HTMLDivElement).style.background = 'var(--surface-1)'; }}
                onMouseLeave={(e) => { (e.currentTarget as HTMLDivElement).style.background = 'var(--surface-0)'; }}
              >
                <p style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: '0.65rem', fontWeight: 700, letterSpacing: '0.12em', color, textTransform: 'uppercase', marginBottom: 6 }}>{label}</p>
                <p style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: '0.6rem', color: 'var(--text-4)', lineHeight: 1.4 }}>{sub}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* ══════════════════════════════════════════════
          FINAL CTA
          ══════════════════════════════════════════════ */}
      <section
        className="section"
        style={{ borderTop: '1px solid var(--border-0)', position: 'relative', overflow: 'hidden' }}
        aria-labelledby="cta-heading"
      >
        {/* Glow */}
        <div aria-hidden="true" style={{
          position: 'absolute',
          bottom: '-30%',
          left: '50%',
          transform: 'translateX(-50%)',
          width: '700px',
          height: '400px',
          background: 'radial-gradient(ellipse at center, rgba(34,211,238,0.06) 0%, transparent 65%)',
          pointerEvents: 'none',
        }} />

        <div className="container" style={{ position: 'relative', zIndex: 1 }}>
          <p className="eyebrow" style={{ marginBottom: 32, justifyContent: 'center', textAlign: 'center' }}>05 / Start Investigation</p>
          <h2
            id="cta-heading"
            style={{
              fontSize: 'clamp(2.5rem, 7vw, 6.5rem)',
              fontWeight: 900,
              lineHeight: 0.91,
              letterSpacing: '-0.04em',
              color: 'var(--text-0)',
              textTransform: 'uppercase',
              textAlign: 'center',
              marginBottom: 24,
            }}
          >
            What Looks Like<br />a Message<br />
            <span style={{ color: 'var(--cyan)' }}>May Be an Attack.</span>
          </h2>
          <p style={{ fontSize: '1.05rem', lineHeight: 1.7, color: 'var(--text-2)', textAlign: 'center', maxWidth: 480, margin: '0 auto 40px' }}>
            Investigate the evidence. Understand the intent.<br />Reconstruct the attack.
          </p>
          <div style={{ display: 'flex', gap: 12, justifyContent: 'center', flexWrap: 'wrap' }}>
            <a href="#investigate" className="btn btn-primary btn-lg btn-arrow" style={{ textDecoration: 'none' }}>
              Analyze a Threat
            </a>
            <a href="#how-it-works" className="btn btn-ghost btn-lg" style={{ textDecoration: 'none' }}>
              Explore Forensics
            </a>
          </div>
        </div>
      </section>

    </div>
  );
}
