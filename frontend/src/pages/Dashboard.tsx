import { useState } from 'react';
import { useLocation, useNavigate } from 'react-router-dom';
import type { AnalysisRequest } from '../types';
import './Dashboard.css';

export default function Dashboard() {
  const location = useLocation();
  const navigate = useNavigate();
  const [activeStage, setActiveStage] = useState<number>(0);
  
  const result: any = location.state?.analysisResult;

  if (!result) {
    return (
      <div className="dashboard-container">
        <div className="card">
          <h2>No Analysis Result Found</h2>
          <p>Please submit an artifact for investigation first.</p>
          <button className="back-btn" onClick={() => navigate('/')}>
            Start Investigation
          </button>
        </div>
      </div>
    );
  }

  // Unified contract extraction with graceful legacy fallbacks
  const threatAssessment = result.threatAssessment || {
    verdict: result.riskLevel || 'unknown',
    severity: result.riskLevel || 'unknown',
    riskScore: result.riskScore !== undefined ? result.riskScore : null,
    confidence: 0,
    justification: result.explanation || ''
  };

  const attackerIntent = result.attackerIntent || {
    primaryGoal: result.intent || 'Unknown',
    description: '',
    potentialImpact: null
  };

  const evidenceItems: any[] = result.evidence || (result.indicators || []).map((ind: string, idx: number) => ({
    id: `IND-${idx + 1}`,
    category: 'technical',
    value: ind,
    description: ind
  }));

  const attackDNA = result.attackDNA || null;
  const reconstruction = result.reconstruction || null;
  const safeSimulation = result.safeSimulation || result.simulation || null;
  const safetyGuidance = result.safetyGuidance || null;
  const mitreAttack = result.mitreAttack || null;

  const getRiskColor = (level?: string) => {
    const l = level?.toLowerCase();
    if (l === 'high' || l === 'critical') return 'risk-high';
    if (l === 'medium') return 'risk-medium';
    if (l === 'low') return 'risk-low';
    return '';
  };

  const getMitreStatusColor = (status?: string) => {
    if (status === 'mapped') return '#10b981';
    if (status === 'partial') return '#f59e0b';
    return '#94a3b8';
  };

  const renderOriginalEvidence = (req?: AnalysisRequest) => {
    if (!req) return <div className="empty-state">No original evidence available</div>;
    
    if (req.type === 'image') {
      return (
        <div>
          <span className="data-label">Image Artifact:</span>
          <img src={req.content} alt="Original Evidence" style={{ maxWidth: '100%', maxHeight: '300px', marginTop: '10px' }} />
        </div>
      );
    }
    
    return (
      <div>
        <span className="data-label">{req.type === 'url' ? 'Analyzed URL:' : 'Analyzed Text:'}</span>
        <div className="evidence-panel">{req.content}</div>
      </div>
    );
  };

  const reconstructionStages: any[] = reconstruction?.stages || safeSimulation?.stages || [];

  return (
    <div className="dashboard-container">
      <div className="dashboard-header">
        <div>
          <h1>Forensic Investigation Results</h1>
          {result.analysisId && (
            <span style={{ fontSize: '0.85rem', color: 'var(--text-muted)' }}>
              Analysis ID: {result.analysisId}
            </span>
          )}
        </div>
        <button className="back-btn" onClick={() => navigate('/')}>
          New Investigation
        </button>
      </div>

      {/* 1. ORIGINAL EVIDENCE */}
      <div className="card">
        <h2 className="card-title">01 / Original Evidence</h2>
        {renderOriginalEvidence(result.originalRequest || result.input)}
      </div>

      {/* 2. THREAT ASSESSMENT & ATTACKER INTENT */}
      <div className="grid-2">
        <div className="card">
          <h2 className="card-title">02 / Threat Assessment</h2>
          <div className="data-row">
            <span className="data-label">Verdict</span>
            <span className={`data-value ${getRiskColor(threatAssessment.verdict)}`} style={{ textTransform: 'capitalize' }}>
              {threatAssessment.verdict}
            </span>
          </div>
          <div className="data-row">
            <span className="data-label">Severity</span>
            <span className={`data-value ${getRiskColor(threatAssessment.severity)}`} style={{ textTransform: 'capitalize' }}>
              {threatAssessment.severity}
            </span>
          </div>
          <div className="data-row">
            <span className="data-label">Risk Score</span>
            <span className="data-value">
              {threatAssessment.riskScore !== null ? `${threatAssessment.riskScore} / 100` : 'Inconclusive / N/A'}
            </span>
          </div>
          <div className="data-row">
            <span className="data-label">Confidence</span>
            <span className="data-value">{threatAssessment.confidence}%</span>
          </div>
          {threatAssessment.justification && (
            <div style={{ marginTop: '0.75rem', fontSize: '0.9rem', color: 'var(--text-muted)' }}>
              <strong>Justification:</strong> {threatAssessment.justification}
            </div>
          )}
        </div>

        <div className="card">
          <h2 className="card-title">Attacker Intent</h2>
          <div className="data-row">
            <span className="data-label">Primary Goal</span>
            <span className="data-value">{attackerIntent.primaryGoal}</span>
          </div>
          {attackerIntent.description && (
            <div className="data-row">
              <span className="data-label">Action Target</span>
              <span className="data-value">{attackerIntent.description}</span>
            </div>
          )}
          {attackerIntent.potentialImpact && (
            <div className="data-row">
              <span className="data-label">Potential Impact</span>
              <span className="data-value" style={{ color: '#ef4444' }}>{attackerIntent.potentialImpact}</span>
            </div>
          )}
        </div>
      </div>

      {/* 3. FORENSIC EVIDENCE */}
      <div className="card">
        <h2 className="card-title">03 / Forensic Evidence & Indicators</h2>
        {evidenceItems.length > 0 ? (
          <div className="indicator-list" style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
            {evidenceItems.map((ev, idx) => (
              <div key={ev.id || idx} style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', background: 'rgba(255,255,255,0.03)', padding: '0.5rem 0.75rem', borderRadius: '4px' }}>
                <span className="indicator-tag" style={{ textTransform: 'uppercase', fontSize: '0.75rem' }}>
                  {ev.category || 'indicator'}
                </span>
                <span style={{ fontWeight: 600, color: '#38bdf8' }}>{ev.defangedValue || ev.value}</span>
                {ev.description && ev.description !== ev.value && (
                  <span style={{ color: 'var(--text-muted)', fontSize: '0.85rem' }}>— {ev.description}</span>
                )}
              </div>
            ))}
          </div>
        ) : (
          <div className="empty-state">No specific forensic indicators returned by analysis engine</div>
        )}
      </div>

      {/* 4. ATTACK DNA & ATTACK RECONSTRUCTION */}
      <div className="grid-2">
        <div className="card">
          <h2 className="card-title">04 / Attack DNA</h2>
          {attackDNA ? (
            <div>
              <p style={{ fontStyle: 'italic', marginBottom: '1rem', color: '#cbd5e1' }}>
                {attackDNA.profileSummary}
              </p>
              <div className="data-row">
                <span className="data-label">Complexity</span>
                <span className="data-value" style={{ textTransform: 'capitalize' }}>{attackDNA.complexity}</span>
              </div>
              <div className="data-row">
                <span className="data-label">Delivery Vector</span>
                <span className="data-value">{attackDNA.deliveryVector}</span>
              </div>
              {attackDNA.traits && attackDNA.traits.length > 0 && (
                <div style={{ marginTop: '1rem' }}>
                  <span className="data-label" style={{ display: 'block', marginBottom: '0.5rem' }}>Observed Traits:</span>
                  <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.5rem' }}>
                    {attackDNA.traits.map((tr: any) => (
                      <span key={tr.key} className="indicator-tag" style={{ background: tr.present ? 'rgba(56, 189, 248, 0.2)' : 'rgba(255,255,255,0.05)' }}>
                        {tr.label || tr.key} {tr.intensity ? `(${tr.intensity})` : ''}
                      </span>
                    ))}
                  </div>
                </div>
              )}
            </div>
          ) : (
            <div className="empty-state">Attack DNA profile not established</div>
          )}
        </div>

        <div className="card">
          <h2 className="card-title">05 / Attack Reconstruction</h2>
          {reconstruction ? (
            <div>
              {reconstruction.attackFlowSummary && (
                <p style={{ color: '#cbd5e1', fontSize: '0.9rem', marginBottom: '1rem' }}>
                  {reconstruction.attackFlowSummary}
                </p>
              )}
              {reconstructionStages.length > 0 ? (
                <div className="timeline">
                  {reconstructionStages.map((stg: any, idx: number) => (
                    <div key={stg.stageId || idx} className="timeline-item">
                      <div className="timeline-dot"></div>
                      <div className="timeline-stage">{stg.stageTitle || stg.stage || `Stage ${idx + 1}`}</div>
                      <div className="timeline-desc">{stg.stageDescription || stg.description}</div>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="empty-state">Reconstruction sequence not established</div>
              )}
            </div>
          ) : (
            <div className="empty-state">Attack reconstruction not available</div>
          )}
        </div>
      </div>

      {/* 5. SAFE SIMULATION */}
      <div className="card simulation-card">
        <h2 className="card-title simulation-title">
          06 / Safe Simulation & Interactive Attack Chain
        </h2>
        
        {!safeSimulation ? (
          <div className="empty-state">Simulation data unavailable.</div>
        ) : (
          <div className="simulation-content">
            {safeSimulation.scenarioOverview && (
              <p style={{ color: 'var(--text-muted)', marginBottom: '1rem' }}>
                {safeSimulation.scenarioOverview}
              </p>
            )}

            {reconstructionStages.length > 0 && (
              <div className="reconstruction-interactive">
                <h3 className="section-subtitle">Simulated Attack Progression</h3>
                <div className="stage-controls">
                  {reconstructionStages.map((stage: any, idx: number) => (
                    <button
                      key={stage.stageId || stage.id || idx}
                      className={`stage-btn ${idx === activeStage ? 'active' : ''}`}
                      onClick={() => setActiveStage(idx)}
                    >
                      Stage {idx + 1}
                    </button>
                  ))}
                </div>
                
                {reconstructionStages[activeStage] && (
                  <div className="stage-details">
                    <h4 className="stage-title">
                      {reconstructionStages[activeStage].stageTitle || reconstructionStages[activeStage].title || `Stage ${activeStage + 1}`}
                    </h4>
                    <p className="stage-desc">
                      {reconstructionStages[activeStage].stageDescription || reconstructionStages[activeStage].description}
                    </p>
                    {reconstructionStages[activeStage].mechanism && (
                      <div className="breakdown-item" style={{ marginTop: '0.5rem' }}>
                        <strong>Mechanism:</strong> {reconstructionStages[activeStage].mechanism}
                      </div>
                    )}
                    {reconstructionStages[activeStage].possibleConsequence && (
                      <div className="breakdown-item warning-text" style={{ marginTop: '0.5rem' }}>
                        <strong>Hypothetical Consequence:</strong> {reconstructionStages[activeStage].possibleConsequence.detailedConsequence || reconstructionStages[activeStage].possibleConsequence.shortImpact}
                      </div>
                    )}
                  </div>
                )}
                
                <div className="stage-nav">
                  <button 
                    disabled={activeStage === 0} 
                    onClick={() => setActiveStage(Math.max(0, activeStage - 1))}
                    className="nav-btn"
                  >
                    ← Previous Stage
                  </button>
                  <button 
                    disabled={activeStage === reconstructionStages.length - 1} 
                    onClick={() => setActiveStage(Math.min(reconstructionStages.length - 1, activeStage + 1))}
                    className="nav-btn"
                  >
                    Next Stage →
                  </button>
                </div>
              </div>
            )}

            {safeSimulation.safetyDisclaimer && (
              <div style={{ marginTop: '1rem', fontStyle: 'italic', fontSize: '0.8rem', color: 'var(--text-muted)' }}>
                ℹ {safeSimulation.safetyDisclaimer}
              </div>
            )}
          </div>
        )}
      </div>

      {/* 6. MITRE ATT&CK ENTERPRISE MAPPING */}
      <div className="card">
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderBottom: '1px solid var(--border)', paddingBottom: '0.5rem', marginBottom: '1rem' }}>
          <h2 className="card-title" style={{ borderBottom: 'none', margin: 0 }}>
            07 / MITRE ATT&CK® Enterprise Mapping
          </h2>
          {mitreAttack && (
            <span style={{
              background: 'rgba(255,255,255,0.05)',
              border: `1px solid ${getMitreStatusColor(mitreAttack.status)}`,
              color: getMitreStatusColor(mitreAttack.status),
              padding: '0.2rem 0.6rem',
              borderRadius: '12px',
              fontSize: '0.75rem',
              fontWeight: 600,
              textTransform: 'uppercase'
            }}>
              Status: {mitreAttack.status}
            </span>
          )}
        </div>

        {!mitreAttack ? (
          <div className="empty-state">MITRE ATT&CK mapping not generated for this artifact.</div>
        ) : mitreAttack.status === 'unmapped' ? (
          <div>
            <div className="empty-state">No verified MITRE ATT&CK techniques matched the provided evidence.</div>
            {mitreAttack.uncertaintyNotes && mitreAttack.uncertaintyNotes.length > 0 && (
              <div style={{ marginTop: '0.75rem', padding: '0.75rem', background: 'rgba(255,255,255,0.02)', borderRadius: '4px', borderLeft: '3px solid #94a3b8' }}>
                <span style={{ fontSize: '0.85rem', color: 'var(--text-muted)' }}>
                  {mitreAttack.uncertaintyNotes.join(' ')}
                </span>
              </div>
            )}
          </div>
        ) : (
          <div>
            {/* Primary Technique Card */}
            {mitreAttack.primaryTechnique && (
              <div style={{ background: 'rgba(56, 189, 248, 0.05)', border: '1px solid rgba(56, 189, 248, 0.2)', borderRadius: '6px', padding: '1rem', marginBottom: '1rem' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '0.5rem' }}>
                  <div>
                    <span style={{ fontSize: '0.8rem', color: '#38bdf8', fontWeight: 600, textTransform: 'uppercase' }}>
                      Primary Entry Technique
                    </span>
                    <h3 style={{ margin: '0.25rem 0', color: '#f8fafc' }}>
                      {mitreAttack.primaryTechnique.techniqueId} — {mitreAttack.primaryTechnique.techniqueName}
                      {mitreAttack.primaryTechnique.subTechniqueId && (
                        <span style={{ color: '#94a3b8', fontSize: '0.9rem', marginLeft: '0.5rem' }}>
                          ({mitreAttack.primaryTechnique.subTechniqueId} {mitreAttack.primaryTechnique.subTechniqueName})
                        </span>
                      )}
                    </h3>
                  </div>
                  <span style={{ fontSize: '0.85rem', color: '#94a3b8', background: 'rgba(255,255,255,0.05)', padding: '0.2rem 0.5rem', borderRadius: '4px' }}>
                    Tactic: {mitreAttack.primaryTechnique.tactic?.name || 'Initial Access'} ({mitreAttack.primaryTechnique.tactic?.id})
                  </span>
                </div>
                <p style={{ margin: '0.5rem 0 0 0', fontSize: '0.9rem', color: '#cbd5e1' }}>
                  {mitreAttack.primaryTechnique.mappingRationale}
                </p>
              </div>
            )}

            {/* Observed Tactics */}
            {mitreAttack.observedTactics && mitreAttack.observedTactics.length > 0 && (
              <div style={{ marginBottom: '1rem' }}>
                <span className="data-label" style={{ display: 'block', marginBottom: '0.4rem' }}>Observed ATT&CK Tactics:</span>
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.5rem' }}>
                  {mitreAttack.observedTactics.map((tac: any) => (
                    <a
                      key={tac.id}
                      href={tac.referenceUrl}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="indicator-tag"
                      style={{ textDecoration: 'none', color: '#f8fafc', background: 'rgba(255,255,255,0.08)' }}
                    >
                      {tac.name} ({tac.id}) ↗
                    </a>
                  ))}
                </div>
              </div>
            )}

            {/* Uncertainty / Missing Evidence Notes */}
            {mitreAttack.uncertaintyNotes && mitreAttack.uncertaintyNotes.length > 0 && (
              <div style={{ padding: '0.75rem 1rem', background: 'rgba(245, 158, 11, 0.08)', borderLeft: '3px solid #f59e0b', borderRadius: '4px', fontSize: '0.85rem', color: '#fcd34d' }}>
                <strong>Evidence Qualification Note:</strong> {mitreAttack.uncertaintyNotes.join(' ')}
              </div>
            )}
          </div>
        )}
      </div>

      {/* 7. SAFETY GUIDANCE & RECOMMENDATIONS */}
      <div className="card recommendations-card">
        <h2 className="card-title" style={{ color: '#10b981', borderBottomColor: 'rgba(16, 185, 129, 0.3)' }}>
          08 / Safety Guidance & Recommendations
        </h2>
        {safetyGuidance?.summary && (
          <p style={{ color: '#cbd5e1', marginBottom: '1rem' }}>{safetyGuidance.summary}</p>
        )}
        {safetyGuidance?.immediateActions && safetyGuidance.immediateActions.length > 0 ? (
          <ul className="recommendations-list">
            {safetyGuidance.immediateActions.map((rec: any, idx: number) => (
              <li key={idx} className="recommendation-item">
                <span className="check-icon">✓</span>
                <div>
                  <strong>{rec.action}</strong>
                  {rec.reason && <p style={{ margin: '0.25rem 0 0 0', fontSize: '0.85rem', color: 'var(--text-muted)' }}>{rec.reason}</p>}
                </div>
              </li>
            ))}
          </ul>
        ) : result.recommendations && result.recommendations.length > 0 ? (
          <ul className="recommendations-list">
            {result.recommendations.map((rec: string, idx: number) => (
              <li key={idx} className="recommendation-item">
                <span className="check-icon">✓</span> {rec}
              </li>
            ))}
          </ul>
        ) : (
          <div className="empty-state">No immediate defensive recommendations required.</div>
        )}
      </div>

      {/* FINAL ACTIONS */}
      <div className="dashboard-actions" style={{ display: 'flex', justifyContent: 'center', marginTop: '1rem' }}>
        <button 
          className="analyze-btn" 
          onClick={() => navigate('/')}
          style={{ padding: '1rem 3rem', fontSize: '1.1rem' }}
        >
          Analyze Another Item
        </button>
      </div>
    </div>
  );
}
