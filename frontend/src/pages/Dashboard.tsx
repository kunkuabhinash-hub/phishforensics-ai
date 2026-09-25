import { useState } from 'react';
import { useLocation, useNavigate } from 'react-router-dom';
import type { AnalysisResponse, AnalysisRequest } from '../types';
import './Dashboard.css';

/* ─────────────────────────────────────────────────────────────────
   HELPERS
   ───────────────────────────────────────────────────────────────── */

function getRiskClass(level?: string): string {
  const l = level?.toLowerCase();
  if (l === 'high' || l === 'critical' || l === 'phishing' || l === 'malicious') return 'risk-high';
  if (l === 'medium' || l === 'suspicious') return 'risk-medium';
  if (l === 'low' || l === 'safe' || l === 'clean') return 'risk-low';
  return '';
}

function getRiskBadgeClass(level?: string): string {
  const l = level?.toLowerCase();
  if (l === 'high' || l === 'critical' || l === 'phishing' || l === 'malicious') return 'badge badge-red';
  if (l === 'medium' || l === 'suspicious') return 'badge badge-amber';
  if (l === 'low' || l === 'safe' || l === 'clean') return 'badge badge-green';
  return 'badge badge-muted';
}

function getDnaLevel(score: number): string {
  if (score >= 70) return 'high';
  if (score >= 40) return 'medium';
  return '';
}

/* ─────────────────────────────────────────────────────────────────
   SUB-COMPONENTS
   ───────────────────────────────────────────────────────────────── */

function OriginalEvidence({ req }: { req?: AnalysisRequest }) {
  if (!req) {
    return <div className="empty-state">No original evidence attached to this investigation.</div>;
  }

  if (req.type === 'image') {
    return (
      <div>
        <span className="data-label" style={{ marginBottom: '1rem' }}>Image Artifact</span>
        <div style={{ padding: '1rem', border: '1px solid var(--border-light)', backgroundColor: 'var(--bg-warm-white)' }}>
          <img src={req.content} alt="Original submitted image evidence" style={{ maxWidth: '100%', maxHeight: '300px', objectFit: 'contain' }} />
        </div>
      </div>
    );
  }

  return (
    <div>
      <span className="data-label" style={{ marginBottom: '1rem' }}>
        {req.type === 'url' ? 'Target URL' : 'Email / Text Content'}
      </span>
      <div className="evidence-panel">{req.content}</div>
    </div>
  );
}

function AttackDnaSection({ attackDna }: { attackDna?: Record<string, number> }) {
  if (!attackDna || Object.keys(attackDna).length === 0) {
    return (
      <div className="empty-state">
        Attack DNA unavailable — no dimensional data returned by the analysis engine.
      </div>
    );
  }
  return (
    <>
      {Object.entries(attackDna).map(([dimension, score]) => (
        <div key={dimension} className="dna-bar-container">
          <div className="dna-label-row">
            <span className="dna-label-name">{dimension.replace(/([A-Z])/g, ' $1').trim()}</span>
            <span className="dna-label-score">{score}%</span>
          </div>
          <div
            className="dna-bar-bg"
            role="progressbar"
            aria-valuenow={score}
            aria-valuemin={0}
            aria-valuemax={100}
            aria-label={`${dimension}: ${score}%`}
          >
            <div
              className="dna-bar-fill"
              data-level={getDnaLevel(score)}
              style={{ width: `${score}%` }}
            />
          </div>
        </div>
      ))}
    </>
  );
}

function RiskDisplay({ riskScore, riskLevel }: { riskScore?: number; riskLevel?: string }) {
  const cls = getRiskClass(riskLevel);
  const display = riskScore !== undefined ? String(riskScore) : '—';
  return (
    <div className="risk-display">
      <div className={`risk-score-circle ${cls}`} aria-label={`Risk score ${display} out of 100`}>
        <span className={`risk-score-num ${cls}`}>{display}</span>
        <span className="risk-score-sub">/100</span>
      </div>
      {riskLevel && (
        <div className="risk-details">
          <p className="risk-level-label">Threat Level</p>
          <p className={`risk-level-value ${cls}`}>{riskLevel.toUpperCase()}</p>
        </div>
      )}
    </div>
  );
}

/* ─────────────────────────────────────────────────────────────────
   MAIN DASHBOARD
   ───────────────────────────────────────────────────────────────── */

export default function Dashboard() {
  const location = useLocation();
  const navigate  = useNavigate();
  const [activeStage, setActiveStage] = useState<number>(0);

  const result: AnalysisResponse | undefined = location.state?.analysisResult;

  /* ── No result state ── */
  if (!result) {
    return (
      <div className="container">
        <div className="dashboard-container">
          <div className="no-result-card">
            <h2>No Investigation Loaded</h2>
            <p>
              Submit a suspicious artifact from the Analyze page to begin
              a forensic investigation.
            </p>
            <button className="btn-primary" onClick={() => navigate('/')}>
              Start Investigation →
            </button>
          </div>
        </div>
      </div>
    );
  }

  const stages = result.simulation?.stages ?? [];

  return (
    <div className="container">
      <div className="dashboard-container" aria-label="Forensic investigation results">

        {/* ── HEADER ────────────────────────────────────────────── */}
        <div className="dashboard-header">
          <div className="investigation-meta">
            <p className="investigation-id" aria-label="Investigation ID">
              INVESTIGATION / {result.id} · <span style={{ textTransform: 'capitalize' }}>{result.status}</span>
            </p>
            <h1>Forensic Report</h1>
            <div className="verdict-row">
              {result.riskLevel && (
                <span className={getRiskBadgeClass(result.riskLevel)} role="status">
                  {result.riskLevel.toUpperCase()}
                </span>
              )}
              {result.intent && (
                <span className="badge badge-muted">{result.intent}</span>
              )}
            </div>
          </div>
          <button
            className="btn-secondary"
            onClick={() => navigate('/')}
            aria-label="Start a new investigation"
          >
            ← New Investigation
          </button>
        </div>

        {/* ── GRID: EVIDENCE + SUMMARY ──────────────────────────── */}
        <div className="grid-2">

          {/* 01 — Original Evidence */}
          <section aria-labelledby="s-evidence" className="editorial-section">
            <span className="section-index">01</span>
            <h2 id="s-evidence" className="card-title">Original Evidence</h2>
            <OriginalEvidence req={result.originalRequest} />
          </section>

          {/* 02 — Investigation Summary */}
          <section aria-labelledby="s-summary" className="editorial-section">
            <span className="section-index">02</span>
            <h2 id="s-summary" className="card-title">Investigation Summary</h2>

            {(result.riskScore !== undefined || result.riskLevel) && (
              <RiskDisplay riskScore={result.riskScore} riskLevel={result.riskLevel} />
            )}

            <div className="data-row">
              <span className="data-label">Status</span>
              <span className="data-value" style={{ textTransform: 'capitalize' }}>
                {result.status}
              </span>
            </div>

            {result.riskScore !== undefined && (
              <div className="data-row">
                <span className="data-label">Risk Score</span>
                <span className={`data-value ${getRiskClass(result.riskLevel)}`}>
                  {result.riskScore} / 100
                </span>
              </div>
            )}

            {result.riskLevel && (
              <div className="data-row">
                <span className="data-label">Risk Level</span>
                <span className={`data-value ${getRiskClass(result.riskLevel)}`}>
                  {result.riskLevel.toUpperCase()}
                </span>
              </div>
            )}

            {result.intent && (
              <div className="data-row">
                <span className="data-label">Detected Intent</span>
                <span className="data-value">{result.intent}</span>
              </div>
            )}
          </section>
        </div>

        {/* ── GRID: ATTACK DNA + INDICATORS ─────────────────────── */}
        <div className="grid-2">

          {/* 03 — Threat Indicators */}
          <section aria-labelledby="s-indicators" className="editorial-section">
            <span className="section-index">03</span>
            <h2 id="s-indicators" className="card-title">Threat Indicators</h2>
            {result.indicators && result.indicators.length > 0 ? (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }} aria-label="Detected threat indicators">
                {result.indicators.map((ind, idx) => (
                  <div key={idx} style={{ display: 'flex', alignItems: 'flex-start', gap: '1rem' }}>
                    <div style={{ width: '4px', height: '4px', backgroundColor: 'var(--danger)', borderRadius: '50%', marginTop: '8px' }}></div>
                    <span style={{ fontSize: '1rem', color: 'var(--text-secondary)' }}>{ind}</span>
                  </div>
                ))}
              </div>
            ) : (
              <div className="empty-state">
                No specific threat indicators returned by the analysis engine.
              </div>
            )}
          </section>

          {/* 04 — Attack DNA */}
          <section aria-labelledby="s-dna" className="editorial-section section-navy" style={{ borderRadius: '0' }}>
            <span className="section-index" style={{ color: 'rgba(255,255,255,0.5)' }}>04</span>
            <h2 id="s-dna" className="card-title" style={{ color: 'white' }}>Attack DNA</h2>
            <AttackDnaSection attackDna={result.attackDna} />
          </section>
        </div>

        {/* ── 05 / TIMELINE ─────────────────────────────────────── */}
        <section
          aria-labelledby="s-timeline"
          className="editorial-section"
        >
          <span className="section-index">05</span>
          <h2 id="s-timeline" className="card-title">Attack Reconstruction Timeline</h2>
          {result.timeline && result.timeline.length > 0 ? (
            <div className="timeline" aria-label="Attack reconstruction timeline">
              {result.timeline.map((item, idx) => (
                <div key={idx} className="timeline-item">
                  <div className="timeline-dot" aria-hidden="true" />
                  <p className="timeline-stage">{item.stage}</p>
                  <p className="timeline-desc">{item.description}</p>
                </div>
              ))}
            </div>
          ) : (
            <div className="empty-state">
              Attack sequence not established — insufficient forensic data returned.
            </div>
          )}
        </section>

        {/* ── 06 / SAFE SIMULATION ──────────────────────────────── */}
        <section
          aria-labelledby="s-simulation"
          className="editorial-section section-soft-blue"
        >
          <span className="section-index">06</span>
          <h2 id="s-simulation" className="card-title" style={{ color: 'var(--blue-primary)' }}>Safe Simulation &amp; Interactive Attack Chain</h2>

          {!result.simulation && (
            <div className="empty-state" style={{ backgroundColor: 'white' }}>
              Attack reconstruction unavailable. Backend simulation data not present.
            </div>
          )}
          {result.simulation?.status === 'unavailable' && (
            <div className="empty-state" style={{ backgroundColor: 'white' }}>Simulation endpoint is currently unavailable.</div>
          )}
          {result.simulation?.status === 'failed' && (
            <div className="empty-state" style={{ border: '1px solid var(--danger)', color: 'var(--danger)', backgroundColor: '#FFF1F2' }}>
              Safe simulation failed to generate. No real attack was performed.
            </div>
          )}
          {result.simulation?.status === 'running' && (
            <div className="empty-state" style={{ border: '1px solid var(--blue-primary)', color: 'var(--blue-primary)', backgroundColor: 'rgba(37,99,235,0.05)' }}>
              Safe simulation is currently running…
            </div>
          )}

          {result.simulation && (result.simulation.status === 'completed' || result.simulation.status === 'ready') && (
            <div>
              <div className="simulation-header-badge">
                SAFE SIMULATION — No real attack performed
              </div>

              <div className="grid-2" style={{ marginBottom: '2rem' }}>
                {result.simulation.attackerObjective && (
                  <div className="simulation-box">
                    <span className="box-label">Attacker Objective</span>
                    <div className="box-value">{result.simulation.attackerObjective}</div>
                  </div>
                )}
                {result.simulation.victimAction && (
                  <div className="simulation-box">
                    <span className="box-label">Targeted Victim Action</span>
                    <div className="box-value">{result.simulation.victimAction}</div>
                  </div>
                )}
              </div>

              {result.simulation.consequencePreview && (
                <div className="consequence-panel">
                  <span className="box-label">Expected Consequence (Safe Preview)</span>
                  <p>{result.simulation.consequencePreview}</p>
                </div>
              )}

              {stages.length > 0 && (
                <div style={{ border: '1px solid var(--border-strong)', padding: '2rem', backgroundColor: 'var(--bg-pure-white)' }} aria-label="Interactive attack chain navigator">
                  <p className="data-label" style={{ marginBottom: '1.5rem' }}>Attack Chain — {stages.length} stages</p>

                  <div style={{ display: 'flex', gap: '0.5rem', marginBottom: '2rem', overflowX: 'auto', paddingBottom: '0.5rem' }} role="tablist" aria-label="Attack chain stages">
                    {stages.map((stage, idx) => (
                      <button
                        key={stage.id || idx}
                        role="tab"
                        aria-selected={idx === activeStage}
                        aria-controls={`stage-${idx}`}
                        style={{
                          padding: '0.5rem 1rem',
                          border: '1px solid var(--border-strong)',
                          backgroundColor: idx === activeStage ? 'var(--text-primary)' : 'transparent',
                          color: idx === activeStage ? 'white' : 'var(--text-primary)',
                          fontFamily: 'var(--font-mono)',
                          fontSize: '0.75rem',
                          fontWeight: 700,
                          cursor: 'pointer'
                        }}
                        onClick={() => setActiveStage(idx)}
                      >
                        STAGE {String(idx + 1).padStart(2, '0')}
                      </button>
                    ))}
                  </div>

                  <div
                    id={`stage-${activeStage}`}
                    role="tabpanel"
                    aria-label={`Stage ${activeStage + 1}`}
                    style={{ backgroundColor: 'var(--bg-light)', padding: '2rem', border: '1px solid var(--border-light)', marginBottom: '2rem' }}
                  >
                    <h3 style={{ fontSize: '1.25rem', marginBottom: '0.5rem' }}>{stages[activeStage].title}</h3>
                    <p style={{ color: 'var(--text-secondary)', marginBottom: '2rem' }}>{stages[activeStage].description}</p>
                    
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem', borderTop: '1px solid var(--border-strong)', paddingTop: '1.5rem' }}>
                      {stages[activeStage].attackerAction && (
                        <div>
                          <span className="data-label">Attacker Action</span>
                          <span style={{ fontSize: '0.95rem', color: 'var(--text-primary)' }}>{stages[activeStage].attackerAction}</span>
                        </div>
                      )}
                      {stages[activeStage].victimInteraction && (
                        <div>
                          <span className="data-label">Victim Interaction</span>
                          <span style={{ fontSize: '0.95rem', color: 'var(--text-primary)' }}>{stages[activeStage].victimInteraction}</span>
                        </div>
                      )}
                      {stages[activeStage].expectedConsequence && (
                        <div>
                          <span className="data-label" style={{ color: 'var(--danger)' }}>Expected Consequence</span>
                          <span style={{ fontSize: '0.95rem', color: 'var(--danger)' }}>{stages[activeStage].expectedConsequence}</span>
                        </div>
                      )}
                    </div>
                  </div>

                  <div style={{ display: 'flex', justifyContent: 'space-between', gap: '1rem' }}>
                    <button
                      className="btn-secondary"
                      style={{ opacity: activeStage === 0 ? 0.3 : 1, padding: '12px 24px' }}
                      disabled={activeStage === 0}
                      onClick={() => setActiveStage(Math.max(0, activeStage - 1))}
                      aria-label="Previous stage"
                    >
                      ← Previous
                    </button>
                    <button
                      className="btn-secondary"
                      style={{ opacity: activeStage === stages.length - 1 ? 0.3 : 1, padding: '12px 24px' }}
                      disabled={activeStage === stages.length - 1}
                      onClick={() => setActiveStage(Math.min(stages.length - 1, activeStage + 1))}
                      aria-label="Next stage"
                    >
                      Next →
                    </button>
                  </div>
                </div>
              )}
            </div>
          )}
        </section>

        {/* ── 07 / EDUCATION ────────────────────────────────────── */}
        <section
          aria-labelledby="s-education"
          className="editorial-section"
        >
          <span className="section-index">07</span>
          <h2
            id="s-education"
            className="card-title"
          >
            Why This Matters
          </h2>

          {result.explanation && (
            <div style={{ marginBottom: result.educationalLesson ? '2rem' : 0 }}>
              <span className="data-label" style={{ marginBottom: '1rem' }}>Forensic Explanation</span>
              <p style={{ fontSize: '1rem', color: 'var(--text-secondary)', lineHeight: 1.6 }}>{result.explanation}</p>
            </div>
          )}

          {result.educationalLesson && (
            <div style={{ marginBottom: result.forensicTakeaways ? '2rem' : 0 }}>
              <span className="data-label" style={{ marginBottom: '1rem' }}>Security Lesson</span>
              <div className="lesson-panel">{result.educationalLesson}</div>
            </div>
          )}

          {result.forensicTakeaways && (
            <div>
              <span className="data-label" style={{ marginBottom: '1rem' }}>Key Takeaways</span>
              <div className="grid-2">
                {result.forensicTakeaways.tactic && (
                  <div className="takeaway-item">
                    <span className="data-label" style={{ marginBottom: '0.5rem' }}>Attacker Tactic</span>
                    <p style={{ fontSize: '1rem', color: 'var(--text-primary)', lineHeight: 1.5 }}>
                      {result.forensicTakeaways.tactic}
                    </p>
                  </div>
                )}
                {result.forensicTakeaways.manipulation && (
                  <div className="takeaway-item">
                    <span className="data-label" style={{ marginBottom: '0.5rem' }}>Manipulation Technique</span>
                    <p style={{ fontSize: '1rem', color: 'var(--text-primary)', lineHeight: 1.5 }}>
                      {result.forensicTakeaways.manipulation}
                    </p>
                  </div>
                )}
                {result.forensicTakeaways.target && (
                  <div className="takeaway-item">
                    <span className="data-label" style={{ marginBottom: '0.5rem' }}>Targeted Information</span>
                    <p style={{ fontSize: '1rem', color: 'var(--text-primary)', lineHeight: 1.5 }}>
                      {result.forensicTakeaways.target}
                    </p>
                  </div>
                )}
              </div>
            </div>
          )}

          {!result.explanation && !result.educationalLesson && !result.forensicTakeaways && (
            <div className="empty-state">No educational content available for this analysis.</div>
          )}
        </section>

        {/* ── 08 / RECOMMENDATIONS ──────────────────────────────── */}
        <section
          aria-labelledby="s-rec"
          className="editorial-section"
        >
          <span className="section-index">08</span>
          <h2
            id="s-rec"
            className="card-title"
          >
            Defensive Recommendations
          </h2>
          {result.recommendations && result.recommendations.length > 0 ? (
            <ul className="recommendations-list" aria-label="Security recommendations">
              {result.recommendations.map((rec, idx) => (
                <li key={idx} className="recommendation-item">
                  <span className="check-icon" aria-hidden="true">✓</span>
                  <span>{rec}</span>
                </li>
              ))}
            </ul>
          ) : (
            <div className="empty-state">
              No recommendations provided by the analysis engine.
            </div>
          )}
        </section>

        {/* ── FINAL ACTIONS ─────────────────────────────────────── */}
        <div style={{ display: 'flex', justifyContent: 'center', padding: '4rem 0' }}>
          <button
            className="btn-primary"
            onClick={() => navigate('/')}
            aria-label="Start a new forensic investigation"
          >
            ANALYZE ANOTHER ARTIFACT →
          </button>
        </div>

      </div>
    </div>
  );
}
