import { useState } from 'react';
import { useLocation, useNavigate } from 'react-router-dom';
import type { AnalysisResponse, AnalysisRequest } from '../types';
import './Dashboard.css';

/* ─────────────────────────────────────────────────────────────────
   HELPERS
   ───────────────────────────────────────────────────────────────── */

function getRiskClass(level?: string): string {
  const l = level?.toLowerCase();
  if (l === 'high' || l === 'critical' || l === 'phishing' || l === 'malicious') return 'risk-high risk-critical';
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
        <p className="data-label" style={{ marginBottom: 12 }}>Image Artifact</p>
        <div className="evidence-image-wrap">
          <img src={req.content} alt="Original submitted image evidence" />
        </div>
      </div>
    );
  }

  return (
    <div>
      <p className="data-label" style={{ marginBottom: 8 }}>
        {req.type === 'url' ? 'Target URL' : 'Email / Text Content'}
      </p>
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
          <div className="card no-result-card">
            <h2>No Investigation Loaded</h2>
            <p>
              Submit a suspicious artifact from the Analyze page to begin
              a forensic investigation.
            </p>
            <button className="analyze-btn btn-arrow" onClick={() => navigate('/')}>
              Start Investigation
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
              INVESTIGATION&ensp;/&ensp;{result.id}&ensp;·&ensp;
              <span style={{ textTransform: 'capitalize' }}>{result.status}</span>
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
            className="back-btn"
            onClick={() => navigate('/')}
            aria-label="Start a new investigation"
          >
            ← New Investigation
          </button>
        </div>

        {/* ── GRID: EVIDENCE + SUMMARY ──────────────────────────── */}
        <div className="grid-2">

          {/* 01 — Original Evidence */}
          <section aria-labelledby="s-evidence" className="card" style={{ animationDelay: '0.05s' }}>
            <h2 id="s-evidence" className="card-title">
              <span className="section-index">01</span>
              Original Evidence
            </h2>
            <OriginalEvidence req={result.originalRequest} />
          </section>

          {/* 02 — Investigation Summary */}
          <section aria-labelledby="s-summary" className="card" style={{ animationDelay: '0.1s' }}>
            <h2 id="s-summary" className="card-title">
              <span className="section-index">02</span>
              Investigation Summary
            </h2>

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
        <div className="grid-2" style={{ animationDelay: '0.15s' }}>

          {/* 03 — Threat Indicators */}
          <section aria-labelledby="s-indicators" className="card">
            <h2 id="s-indicators" className="card-title">
              <span className="section-index">03</span>
              Threat Indicators
            </h2>
            {result.indicators && result.indicators.length > 0 ? (
              <div className="indicator-list" aria-label="Detected threat indicators">
                {result.indicators.map((ind, idx) => (
                  <span key={idx} className="indicator-tag">{ind}</span>
                ))}
              </div>
            ) : (
              <div className="empty-state">
                No specific threat indicators returned by the analysis engine.
              </div>
            )}
          </section>

          {/* 04 — Attack DNA */}
          <section aria-labelledby="s-dna" className="card">
            <h2 id="s-dna" className="card-title">
              <span className="section-index">04</span>
              Attack DNA
            </h2>
            <AttackDnaSection attackDna={result.attackDna} />
          </section>
        </div>

        {/* ── 05 / TIMELINE ─────────────────────────────────────── */}
        <section
          aria-labelledby="s-timeline"
          className="card"
          style={{ animationDelay: '0.2s' }}
        >
          <h2 id="s-timeline" className="card-title">
            <span className="section-index">05</span>
            Attack Reconstruction Timeline
          </h2>
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
          className="card simulation-card"
          style={{ animationDelay: '0.25s' }}
        >
          <h2 id="s-simulation" className="card-title simulation-title">
            <span className="section-index">06</span>
            Safe Simulation &amp; Interactive Attack Chain
          </h2>

          {!result.simulation && (
            <div className="empty-state">
              Attack reconstruction unavailable. Backend simulation data not present.
            </div>
          )}
          {result.simulation?.status === 'unavailable' && (
            <div className="empty-state">Simulation endpoint is currently unavailable.</div>
          )}
          {result.simulation?.status === 'failed' && (
            <div className="empty-state" style={{ borderColor: 'rgba(244,63,94,0.25)', color: 'var(--red-400)' }}>
              Safe simulation failed to generate. No real attack was performed.
            </div>
          )}
          {result.simulation?.status === 'running' && (
            <div className="empty-state" style={{ borderColor: 'rgba(34,211,238,0.25)', color: 'var(--cyan)' }}>
              Safe simulation is currently running…
            </div>
          )}

          {result.simulation && (result.simulation.status === 'completed' || result.simulation.status === 'ready') && (
            <div>
              <div className="simulation-header-badge">
                SAFE SIMULATION — No real attack performed
              </div>

              <div className="grid-2" style={{ marginBottom: 14 }}>
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
                <div className="reconstruction-interactive" aria-label="Interactive attack chain navigator">
                  <p className="section-subtitle">Attack Chain — {stages.length} stages</p>

                  <div className="stage-controls" role="tablist" aria-label="Attack chain stages">
                    {stages.map((stage, idx) => (
                      <button
                        key={stage.id || idx}
                        role="tab"
                        aria-selected={idx === activeStage}
                        aria-controls={`stage-${idx}`}
                        className={`stage-btn ${idx === activeStage ? 'active' : ''}`}
                        onClick={() => setActiveStage(idx)}
                      >
                        {String(idx + 1).padStart(2, '0')}
                      </button>
                    ))}
                  </div>

                  <div
                    id={`stage-${activeStage}`}
                    role="tabpanel"
                    aria-label={`Stage ${activeStage + 1}`}
                    className="stage-details"
                  >
                    <h3 className="stage-title">{stages[activeStage].title}</h3>
                    <p className="stage-desc">{stages[activeStage].description}</p>
                    <div className="stage-breakdown">
                      {stages[activeStage].attackerAction && (
                        <div className="breakdown-item">
                          <strong>Attacker Action</strong>
                          {stages[activeStage].attackerAction}
                        </div>
                      )}
                      {stages[activeStage].victimInteraction && (
                        <div className="breakdown-item">
                          <strong>Victim Interaction</strong>
                          {stages[activeStage].victimInteraction}
                        </div>
                      )}
                      {stages[activeStage].expectedConsequence && (
                        <div className="breakdown-item warning-text">
                          <strong>Expected Consequence</strong>
                          {stages[activeStage].expectedConsequence}
                        </div>
                      )}
                    </div>
                  </div>

                  <div className="stage-nav">
                    <button
                      className="nav-btn"
                      disabled={activeStage === 0}
                      onClick={() => setActiveStage(Math.max(0, activeStage - 1))}
                      aria-label="Previous stage"
                    >
                      ← Previous
                    </button>
                    <button
                      className="nav-btn"
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
          className="card education-card"
          style={{ animationDelay: '0.3s' }}
        >
          <h2
            id="s-education"
            className="card-title"
            style={{ color: '#a855f7' }}
          >
            <span className="section-index">07</span>
            Why This Matters
          </h2>

          {result.explanation && (
            <div style={{ marginBottom: result.educationalLesson ? 20 : 0 }}>
              <p className="section-subtitle">Forensic Explanation</p>
              <p className="explanation-text">{result.explanation}</p>
            </div>
          )}

          {result.educationalLesson && (
            <div style={{ marginBottom: result.forensicTakeaways ? 20 : 0 }}>
              <p className="section-subtitle">Security Lesson</p>
              <div className="lesson-panel">{result.educationalLesson}</div>
            </div>
          )}

          {result.forensicTakeaways && (
            <div>
              <p className="section-subtitle">Key Takeaways</p>
              <div className="grid-3">
                {result.forensicTakeaways.tactic && (
                  <div className="takeaway-item">
                    <p className="data-label" style={{ marginBottom: 6 }}>Attacker Tactic</p>
                    <p style={{ fontSize: '0.875rem', color: 'var(--text-1)', lineHeight: 1.5 }}>
                      {result.forensicTakeaways.tactic}
                    </p>
                  </div>
                )}
                {result.forensicTakeaways.manipulation && (
                  <div className="takeaway-item">
                    <p className="data-label" style={{ marginBottom: 6 }}>Manipulation Technique</p>
                    <p style={{ fontSize: '0.875rem', color: 'var(--text-1)', lineHeight: 1.5 }}>
                      {result.forensicTakeaways.manipulation}
                    </p>
                  </div>
                )}
                {result.forensicTakeaways.target && (
                  <div className="takeaway-item">
                    <p className="data-label" style={{ marginBottom: 6 }}>Targeted Information</p>
                    <p style={{ fontSize: '0.875rem', color: 'var(--text-1)', lineHeight: 1.5 }}>
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
          className="card recommendations-card"
          style={{ animationDelay: '0.35s' }}
        >
          <h2
            id="s-rec"
            className="card-title"
            style={{ color: 'var(--green-400)' }}
          >
            <span className="section-index">08</span>
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
        <div className="dashboard-actions" style={{ animationDelay: '0.4s' }}>
          <button
            className="analyze-btn btn-arrow"
            onClick={() => navigate('/')}
            aria-label="Start a new forensic investigation"
          >
            Analyze Another Artifact
          </button>
        </div>

      </div>
    </div>
  );
}
