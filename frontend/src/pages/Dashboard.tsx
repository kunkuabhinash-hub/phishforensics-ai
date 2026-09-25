import { useLocation, useNavigate } from 'react-router-dom';
import { AnalysisResponse, AnalysisRequest } from '../types';
import './Dashboard.css';

export default function Dashboard() {
  const location = useLocation();
  const navigate = useNavigate();
  
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

      <div className="grid-2">
        {/* INVESTIGATION SUMMARY */}
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

        {/* EVIDENCE / INDICATORS */}
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

      <div className="grid-2">
        {/* ATTACK DNA */}
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

        {/* ATTACK TIMELINE */}
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

      {/* FORENSIC EXPLANATION */}
      <div className="card">
        <h2 className="card-title">Forensic Explanation</h2>
        {result.explanation ? (
          <p style={{ color: 'var(--text-muted)' }}>{result.explanation}</p>
        ) : (
          <div className="empty-state">No detailed explanation provided</div>
        )}
      </div>

      <div className="grid-2">
        {/* RECOMMENDATIONS */}
        <div className="card">
          <h2 className="card-title">Security Recommendations</h2>
          {result.recommendations && result.recommendations.length > 0 ? (
            <ul className="recommendations-list">
              {result.recommendations.map((rec, idx) => (
                <li key={idx}>{rec}</li>
              ))}
            </ul>
          ) : (
            <div className="empty-state">No recommendations provided</div>
          )}
        </div>

        {/* ORIGINAL EVIDENCE */}
        <div className="card">
          <h2 className="card-title">Original Evidence</h2>
          {renderOriginalEvidence(result.originalRequest)}
        </div>
      </div>

    </div>
  );
}
