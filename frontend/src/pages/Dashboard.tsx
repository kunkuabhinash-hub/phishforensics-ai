import { useState } from 'react';
import { useLocation, useNavigate } from 'react-router-dom';
import { AnalysisResponse, AnalysisRequest } from '../types';
import './Dashboard.css';

export default function Dashboard() {
  const location = useLocation();
  const navigate = useNavigate();
  const [activeStage, setActiveStage] = useState<number>(0);
  
  const result: AnalysisResponse | undefined = location.state?.analysisResult;

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

  const getRiskColor = (level?: string) => {
    const l = level?.toLowerCase();
    if (l === 'high' || l === 'critical') return 'risk-high';
    if (l === 'medium') return 'risk-medium';
    if (l === 'low') return 'risk-low';
    return '';
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

  return (
    <div className="dashboard-container">
      <div className="dashboard-header">
        <h1>Forensic Investigation Results</h1>
        <button className="back-btn" onClick={() => navigate('/')}>
          New Investigation
        </button>
      </div>

      {/* 1. EVIDENCE */}
      <div className="card">
        <h2 className="card-title">Original Evidence</h2>
        {renderOriginalEvidence(result.originalRequest)}
      </div>

      {/* 2. ANALYSIS */}
      <div className="grid-2">
        <div className="card">
          <h2 className="card-title">Investigation Summary</h2>
          <div className="data-row">
            <span className="data-label">Status</span>
            <span className="data-value" style={{textTransform: 'capitalize'}}>{result.status}</span>
          </div>
          {result.riskLevel && (
            <div className="data-row">
              <span className="data-label">Risk Level</span>
              <span className={`data-value ${getRiskColor(result.riskLevel)}`}>{result.riskLevel.toUpperCase()}</span>
            </div>
          )}
          {result.riskScore !== undefined && (
            <div className="data-row">
              <span className="data-label">Risk Score</span>
              <span className="data-value">{result.riskScore} / 100</span>
            </div>
          )}
          {result.intent && (
            <div className="data-row">
              <span className="data-label">Detected Intent</span>
              <span className="data-value">{result.intent}</span>
            </div>
          )}
        </div>

        <div className="card">
          <h2 className="card-title">Detected Indicators</h2>
          {result.indicators && result.indicators.length > 0 ? (
            <div className="indicator-list">
              {result.indicators.map((ind, idx) => (
                <span key={idx} className="indicator-tag">{ind}</span>
              ))}
            </div>
          ) : (
            <div className="empty-state">No specific indicators returned by analysis engine</div>
          )}
        </div>
      </div>

      {/* 3. ATTACK DNA & RECONSTRUCTION (TIMELINE) */}
      <div className="grid-2">
        <div className="card">
          <h2 className="card-title">Attack DNA</h2>
          {result.attackDna && Object.keys(result.attackDna).length > 0 ? (
            Object.entries(result.attackDna).map(([dimension, score]) => (
              <div key={dimension} className="dna-bar-container">
                <div className="dna-label-row">
                  <span style={{textTransform: 'capitalize'}}>{dimension.replace(/([A-Z])/g, ' $1').trim()}</span>
                  <span>{score}%</span>
                </div>
                <div className="dna-bar-bg">
                  <div className="dna-bar-fill" style={{ width: `${score}%` }}></div>
                </div>
              </div>
            ))
          ) : (
            <div className="empty-state">Analysis data not available</div>
          )}
        </div>

        <div className="card">
          <h2 className="card-title">Attack Reconstruction Timeline</h2>
          {result.timeline && result.timeline.length > 0 ? (
            <div className="timeline">
              {result.timeline.map((item, idx) => (
                <div key={idx} className="timeline-item">
                  <div className="timeline-dot"></div>
                  <div className="timeline-stage">{item.stage}</div>
                  <div className="timeline-desc">{item.description}</div>
                </div>
              ))}
            </div>
          ) : (
            <div className="empty-state">Attack sequence not established</div>
          )}
        </div>
      </div>

      {/* 4. SAFE SIMULATION */}
      <div className="card simulation-card">
        <h2 className="card-title simulation-title">
          Safe Simulation & Interactive Attack Chain
        </h2>
        
        {!result.simulation ? (
          <div className="empty-state">Attack reconstruction unavailable. Backend simulation not yet integrated.</div>
        ) : result.simulation.status === 'unavailable' ? (
          <div className="empty-state">Simulation endpoint is currently unavailable.</div>
        ) : result.simulation.status === 'failed' ? (
          <div className="empty-state" style={{color: 'var(--error)'}}>Safe simulation failed to generate.</div>
        ) : result.simulation.status === 'running' ? (
          <div className="empty-state" style={{color: 'var(--primary)'}}>Safe simulation is currently running...</div>
        ) : (
          <div className="simulation-content">
            <div className="grid-2" style={{marginBottom: '1.5rem'}}>
              {result.simulation.attackerObjective && (
                <div className="simulation-box objective-box">
                  <span className="box-label">Attacker Objective</span>
                  <div className="box-value">{result.simulation.attackerObjective}</div>
                </div>
              )}
              {result.simulation.victimAction && (
                <div className="simulation-box action-box">
                  <span className="box-label">Targeted Victim Action</span>
                  <div className="box-value">{result.simulation.victimAction}</div>
                </div>
              )}
            </div>

            {result.simulation.consequencePreview && (
              <div className="consequence-panel">
                <span className="box-label" style={{color: '#ef4444'}}>Expected Consequence (Safe Preview):</span>
                <p>{result.simulation.consequencePreview}</p>
              </div>
            )}

            {result.simulation.stages && result.simulation.stages.length > 0 && (
              <div className="reconstruction-interactive">
                <h3 className="section-subtitle">Attack Chain</h3>
                <div className="stage-controls">
                  {result.simulation.stages.map((stage, idx) => (
                     <button
                      key={stage.id || idx}
                      className={`stage-btn ${idx === activeStage ? 'active' : ''}`}
                      onClick={() => setActiveStage(idx)}
                     >
                       Stage {idx + 1}
                     </button>
                  ))}
                </div>
                
                <div className="stage-details">
                  <h4 className="stage-title">{result.simulation.stages[activeStage].title}</h4>
                  <p className="stage-desc">{result.simulation.stages[activeStage].description}</p>
                  
                  <div className="stage-breakdown">
                    {result.simulation.stages[activeStage].attackerAction && (
                      <div className="breakdown-item">
                        <strong>Attacker Action:</strong> {result.simulation.stages[activeStage].attackerAction}
                      </div>
                    )}
                    {result.simulation.stages[activeStage].victimInteraction && (
                      <div className="breakdown-item">
                        <strong>Victim Interaction:</strong> {result.simulation.stages[activeStage].victimInteraction}
                      </div>
                    )}
                    {result.simulation.stages[activeStage].expectedConsequence && (
                      <div className="breakdown-item warning-text">
                        <strong>Consequence:</strong> {result.simulation.stages[activeStage].expectedConsequence}
                      </div>
                    )}
                  </div>
                </div>
                
                <div className="stage-nav">
                  <button 
                    disabled={activeStage === 0} 
                    onClick={() => setActiveStage(Math.max(0, activeStage - 1))}
                    className="nav-btn"
                  >
                    ← Previous Stage
                  </button>
                  <button 
                    disabled={activeStage === result.simulation!.stages!.length - 1} 
                    onClick={() => setActiveStage(Math.min(result.simulation!.stages!.length - 1, activeStage + 1))}
                    className="nav-btn"
                  >
                    Next Stage →
                  </button>
                </div>
              </div>
            )}
          </div>
        )}
      </div>

      {/* 5. EDUCATION */}
      <div className="card education-card">
        <h2 className="card-title" style={{color: '#a855f7', borderBottomColor: 'rgba(168, 85, 247, 0.3)'}}>
          Why This Matters
        </h2>
        
        {result.explanation ? (
          <div className="education-section">
            <h3 className="section-subtitle">Forensic Explanation</h3>
            <p style={{ color: 'var(--text-muted)' }}>{result.explanation}</p>
          </div>
        ) : (
          <div className="empty-state">No detailed explanation provided</div>
        )}

        {result.educationalLesson && (
          <div className="education-section" style={{marginTop: '1.5rem'}}>
             <h3 className="section-subtitle">Security Lesson</h3>
             <div className="lesson-panel">
               {result.educationalLesson}
             </div>
          </div>
        )}

        {result.forensicTakeaways && (
          <div className="takeaways-section" style={{marginTop: '1.5rem', paddingTop: '1.5rem', borderTop: '1px solid var(--border)'}}>
            <h3 className="section-subtitle">Key Takeaways</h3>
            <div className="grid-2">
              {result.forensicTakeaways.tactic && (
                <div className="takeaway-item">
                  <span className="data-label">Attacker Tactic</span>
                  <div className="data-value">{result.forensicTakeaways.tactic}</div>
                </div>
              )}
              {result.forensicTakeaways.manipulation && (
                <div className="takeaway-item">
                  <span className="data-label">Manipulation Technique</span>
                  <div className="data-value">{result.forensicTakeaways.manipulation}</div>
                </div>
              )}
              {result.forensicTakeaways.target && (
                <div className="takeaway-item">
                  <span className="data-label">Targeted Information</span>
                  <div className="data-value">{result.forensicTakeaways.target}</div>
                </div>
              )}
            </div>
          </div>
        )}
      </div>

      {/* 6. RECOMMENDATIONS */}
      <div className="card recommendations-card">
        <h2 className="card-title" style={{color: '#10b981', borderBottomColor: 'rgba(16, 185, 129, 0.3)'}}>
          Defensive Recommendations
        </h2>
        {result.recommendations && result.recommendations.length > 0 ? (
          <ul className="recommendations-list">
            {result.recommendations.map((rec, idx) => (
              <li key={idx} className="recommendation-item">
                <span className="check-icon">✓</span> {rec}
              </li>
            ))}
          </ul>
        ) : (
          <div className="empty-state">No recommendations provided</div>
        )}
      </div>

      {/* 7. FINAL ACTIONS */}
      <div className="dashboard-actions" style={{display: 'flex', justifyContent: 'center', marginTop: '1rem'}}>
         <button 
           className="analyze-btn" 
           onClick={() => navigate('/')}
           style={{padding: '1rem 3rem', fontSize: '1.1rem'}}
         >
           Analyze Another Item
         </button>
      </div>
      
    </div>
  );
}
