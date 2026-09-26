import { useState } from 'react';
import { useLocation, useNavigate } from 'react-router-dom';
import './Dashboard.css';

// ─── HELPER: SAFE INDICATOR DEFANGING ─────────────────────────────────
function defangIndicator(val: string): string {
  if (!val) return '';
  let defanged = val.trim();
  // Defang http:// and https://
  defanged = defanged.replace(/^https:\/\//i, 'hxxps://');
  defanged = defanged.replace(/^http:\/\//i, 'hxxp://');
  // Defang @ in email addresses
  defanged = defanged.replace(/@/g, '[at]');
  // Defang IPv4 addresses
  defanged = defanged.replace(/\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b/g, '$1[.]$2[.]$3[.]$4');
  // Defang common TLD domains
  defanged = defanged.replace(/(\w+)\.(com|org|net|io|edu|gov|xyz|info|biz|ru|cn|top|live|online|security|app|co|uk|de|eu)/gi, '$1[.]$2');
  return defanged;
}

// ─── HELPER: EXTRACT OBSERVABLE IOCS ──────────────────────────────────
interface ObservableIOC {
  id: string;
  type: string;
  rawValue: string;
  defangedValue: string;
  originEvidenceId?: string;
}

function extractObservables(evidenceItems: any[], rawIndicators: string[] = []): ObservableIOC[] {
  const iocs: ObservableIOC[] = [];
  const seenValues = new Set<string>();

  evidenceItems.forEach((ev, idx) => {
    const val = (ev.value || '').trim();
    if (!val || seenValues.has(val.toLowerCase())) return;

    const lower = val.toLowerCase();
    let type = '';

    if (lower.startsWith('http://') || lower.startsWith('https://') || lower.includes('://')) {
      type = 'URL';
    } else if (val.includes('@') && !val.includes('://')) {
      type = 'Email Address';
    } else if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(val)) {
      type = 'IP Address';
    } else if (/^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{64}$/.test(val)) {
      type = 'File Hash';
    } else if (/\+?\d{1,4}?[-.\s]?\(?\d{1,3}?\)?[-.\s]?\d{1,4}[-.\s]?\d{1,4}[-.\s]?\d{1,9}/.test(val) && val.length >= 7) {
      type = 'Phone Number';
    } else if (ev.category === 'technical') {
      type = 'Technical Indicator';
    }

    if (type) {
      seenValues.add(val.toLowerCase());
      iocs.push({
        id: `IOC-${idx + 1}`,
        type,
        rawValue: val,
        defangedValue: defangIndicator(val),
        originEvidenceId: ev.id
      });
    }
  });

  // Extract any raw indicators not already captured
  rawIndicators.forEach((ind, idx) => {
    const val = (ind || '').trim();
    if (!val || seenValues.has(val.toLowerCase())) return;
    seenValues.add(val.toLowerCase());

    const lower = val.toLowerCase();
    let type = 'Indicator';
    if (lower.startsWith('http://') || lower.startsWith('https://') || lower.includes('://')) {
      type = 'URL';
    } else if (val.includes('@')) {
      type = 'Email Address';
    } else if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(val)) {
      type = 'IP Address';
    }

    iocs.push({
      id: `IOC-RAW-${idx + 1}`,
      type,
      rawValue: val,
      defangedValue: defangIndicator(val)
    });
  });

  return iocs;
}

// ─── HELPER: DERIVE VICTIM IMPACT ANALYSIS ─────────────────────────────
interface VictimImpactItem {
  category: string;
  isEstablished: boolean;
  severity: 'Critical' | 'High' | 'Medium' | 'Low' | null;
  explanation: string;
  evidenceRefs: string[];
}

function deriveVictimImpacts(result: any, evidenceItems: any[]): VictimImpactItem[] {
  const verdict = (result.threatAssessment?.verdict || '').toLowerCase();
  const primaryGoal = (result.attackerIntent?.primaryGoal || '').toLowerCase();
  const intentDesc = (result.attackerIntent?.description || '').toLowerCase();

  const isPhishingOrSuspicious = verdict === 'phishing' || verdict === 'malicious' || verdict === 'suspicious';

  // 1. Credential Exposure
  const credRefs = evidenceItems
    .filter(e => {
      const text = `${e.value || ''} ${e.description || ''}`.toLowerCase();
      return text.includes('password') || text.includes('login') || text.includes('credential') || 
             text.includes('verify') || text.includes('suspend') || text.includes('account');
    })
    .map(e => e.id);

  const credEstablished = isPhishingOrSuspicious && (
    primaryGoal.includes('credential') || intentDesc.includes('credential') || credRefs.length > 0
  );

  // 2. Account Takeover
  const atoEstablished = credEstablished;

  // 3. Financial Loss
  const finRefs = evidenceItems
    .filter(e => {
      const text = `${e.value || ''} ${e.description || ''}`.toLowerCase();
      return text.includes('payment') || text.includes('invoice') || text.includes('wire') || 
             text.includes('bank') || text.includes('crypto') || text.includes('transfer') || text.includes('gift card');
    })
    .map(e => e.id);

  const finEstablished = isPhishingOrSuspicious && (
    primaryGoal.includes('financial') || primaryGoal.includes('money') || intentDesc.includes('payment') || finRefs.length > 0
  );

  // 4. Data Exposure
  const dataRefs = evidenceItems
    .filter(e => {
      const text = `${e.value || ''} ${e.description || ''}`.toLowerCase();
      return text.includes('data') || text.includes('recon') || text.includes('ssn') || text.includes('personal');
    })
    .map(e => e.id);

  const dataEstablished = isPhishingOrSuspicious && (
    primaryGoal.includes('recon') || primaryGoal.includes('data') || dataRefs.length > 0
  );

  // 5. Malware Exposure
  const malRefs = evidenceItems
    .filter(e => {
      const text = `${e.value || ''} ${e.description || ''}`.toLowerCase();
      return text.includes('attachment') || text.includes('.exe') || text.includes('.zip') || 
             text.includes('payload') || text.includes('script') || text.includes('download');
    })
    .map(e => e.id);

  const malEstablished = isPhishingOrSuspicious && (
    primaryGoal.includes('malware') || malRefs.length > 0
  );

  // 6. Privacy Exposure
  const privRefs = evidenceItems
    .filter(e => {
      const text = `${e.value || ''} ${e.description || ''}`.toLowerCase();
      return text.includes('email') || text.includes('recipient') || text.includes('profile') || text.includes('contact');
    })
    .map(e => e.id);

  const privEstablished = isPhishingOrSuspicious;

  return [
    {
      category: 'Credential Exposure',
      isEstablished: credEstablished,
      severity: credEstablished ? 'High' : null,
      explanation: credEstablished 
        ? 'Observed pretext or links solicit authentication credentials or sensitive account verification details.'
        : 'Not established from available evidence.',
      evidenceRefs: credRefs
    },
    {
      category: 'Account Takeover Risk',
      isEstablished: atoEstablished,
      severity: atoEstablished ? 'High' : null,
      explanation: atoEstablished
        ? 'Compromised credentials may lead directly to unauthorized access and session hijacking.'
        : 'Not established from available evidence.',
      evidenceRefs: credRefs
    },
    {
      category: 'Financial Loss',
      isEstablished: finEstablished,
      severity: finEstablished ? 'Critical' : null,
      explanation: finEstablished
        ? 'Artifact incorporates financial urgency, fraudulent billing, or payment modification cues.'
        : 'Not established from available evidence.',
      evidenceRefs: finRefs
    },
    {
      category: 'Data Exposure',
      isEstablished: dataEstablished,
      severity: dataEstablished ? 'Medium' : null,
      explanation: dataEstablished
        ? 'Observed patterns may facilitate unauthorized collection of personal or organisational data.'
        : 'Not established from available evidence.',
      evidenceRefs: dataRefs
    },
    {
      category: 'Malware Exposure',
      isEstablished: malEstablished,
      severity: malEstablished ? 'Critical' : null,
      explanation: malEstablished
        ? 'Artifact contains potential payload delivery vectors or executable attachments.'
        : 'Not established from available evidence.',
      evidenceRefs: malRefs
    },
    {
      category: 'Privacy Exposure',
      isEstablished: privEstablished,
      severity: privEstablished ? 'Low' : null,
      explanation: privEstablished
        ? 'Observed indicators target recipient contact identifiers or delivery validation.'
        : 'Not established from available evidence.',
      evidenceRefs: privRefs
    }
  ];
}

// Feature Panel identifiers
export type FeaturePanelId = 
  | 'evidence' 
  | 'dna' 
  | 'fingerprint' 
  | 'reconstruction' 
  | 'mitre' 
  | 'iocs' 
  | 'impact' 
  | 'simulation' 
  | 'guidance' 
  | 'export';

// ─── MAIN COMPONENT ───────────────────────────────────────────────────
export default function Dashboard() {
  const location = useLocation();
  const navigate = useNavigate();
  const result: any = location.state?.analysisResult;

  // Active feature panel (null by default for "Simple by Default, Deep When Requested")
  const [activePanel, setActivePanel] = useState<FeaturePanelId | null>(null);

  // State controls for interactive features
  const [activeSimStage, setActiveSimStage] = useState<number>(0);
  const [showArtifactContent, setShowArtifactContent] = useState<boolean>(false);
  const [evidenceFilter, setEvidenceFilter] = useState<'all' | 'technical' | 'psychological' | 'contextual'>('all');
  const [highlightedEvId, setHighlightedEvId] = useState<string | null>(null);
  const [copiedIoc, setCopiedIoc] = useState<string | null>(null);
  const [showCompareModal, setShowCompareModal] = useState<boolean>(false);
  const [showExportDropdown, setShowExportDropdown] = useState<boolean>(false);
  const [investigationHistory] = useState<any[]>(() => {
    try {
      const stored = localStorage.getItem('phishforensics_investigation_history');
      let hist: any[] = stored ? JSON.parse(stored) : [];
      if (result && result.analysisId) {
        const existsIndex = hist.findIndex(item => item.analysisId === result.analysisId);
        if (existsIndex >= 0) {
          hist[existsIndex] = result;
        } else {
          hist.unshift(result);
        }
        if (hist.length > 10) hist = hist.slice(0, 10);
        localStorage.setItem('phishforensics_investigation_history', JSON.stringify(hist));
      }
      return hist;
    } catch {
      return result ? [result] : [];
    }
  });

  const [compareAttackAId, setCompareAttackAId] = useState<string>(() => result?.analysisId || '');
  const [compareAttackBId, setCompareAttackBId] = useState<string>(() => {
    try {
      const stored = localStorage.getItem('phishforensics_investigation_history');
      const hist: any[] = stored ? JSON.parse(stored) : [];
      return hist.length > 1 ? hist[1].analysisId : (result?.analysisId || '');
    } catch {
      return result?.analysisId || '';
    }
  });

  if (!result) {
    return (
      <div className="dashboard-container">
        <div className="forensic-card empty-state-box" style={{ maxWidth: '600px', margin: '4rem auto' }}>
          <h2 style={{ fontSize: '1.25rem', marginBottom: '0.75rem', color: 'var(--text-primary)' }}>
            No Analysis Result Found
          </h2>
          <p style={{ color: 'var(--text-muted)', marginBottom: '1.5rem', fontSize: '0.9rem' }}>
            Please submit an artifact for investigation first to generate a forensic report.
          </p>
          <button className="btn-primary-large" onClick={() => navigate('/')}>
            ← Start New Investigation
          </button>
        </div>
      </div>
    );
  }

  // Contract data extraction
  const threatAssessment = result.threatAssessment || {
    verdict: result.riskLevel || 'unknown',
    severity: result.riskLevel || 'unknown',
    riskScore: result.riskScore !== undefined ? result.riskScore : null,
    confidence: 0,
    justification: result.explanation || 'No justification provided.'
  };

  const attackerIntent = result.attackerIntent || {
    primaryGoal: result.intent || 'Unknown',
    description: '',
    potentialImpact: null
  };

  const evidenceItems: any[] = (result.evidence || []).map((ev: any, idx: number) => ({
    id: ev.id || `EV-${String(idx + 1).padStart(3, '0')}`,
    category: ev.category || 'contextual',
    value: ev.value || '',
    defangedValue: ev.defangedValue || defangIndicator(ev.value || ''),
    description: ev.description || ev.value || '',
    confidence: ev.confidence !== undefined ? ev.confidence : null
  }));

  const attackDNA = result.attackDNA || null;
  const reconstruction = result.reconstruction || null;
  const safeSimulation = result.safeSimulation || result.simulation || null;
  const safetyGuidance = result.safetyGuidance || null;
  const mitreAttack = result.mitreAttack || null;

  const rawInput = result.originalRequest || result.input || null;
  const inputType = rawInput?.sourceType || rawInput?.type || 'artifact';
  const inputContent = rawInput?.content || '';

  const reconstructionStages: any[] = reconstruction?.stages || safeSimulation?.stages || [];
  const simulationStages: any[] = safeSimulation?.stages || reconstructionStages;

  // Extracted observables & impacts
  const extractedIOCs = extractObservables(evidenceItems, result.indicators || []);
  const victimImpacts = deriveVictimImpacts(result, evidenceItems);

  // Helper functions
  const getVerdictClass = (verdict?: string) => {
    const v = verdict?.toLowerCase() || '';
    if (v === 'malicious' || v === 'phishing') return 'verdict-malicious';
    if (v === 'suspicious') return 'verdict-suspicious';
    if (v === 'benign' || v === 'safe') return 'verdict-benign';
    return 'verdict-unknown';
  };

  const getVerdictIcon = (verdict?: string) => {
    const v = verdict?.toLowerCase() || '';
    if (v === 'malicious' || v === 'phishing') return '🚨';
    if (v === 'suspicious') return '⚠';
    if (v === 'benign' || v === 'safe') return '🛡️';
    return '❓';
  };

  const getSeverityPillClass = (severity?: string) => {
    const s = severity?.toLowerCase() || '';
    if (s === 'critical' || s === 'high') return 'pill-danger';
    if (s === 'medium') return 'pill-warning';
    if (s === 'low' || s === 'info') return 'pill-success';
    return 'pill-neutral';
  };

  const getEvidenceCategoryPillClass = (category?: string) => {
    const c = category?.toLowerCase() || '';
    if (c === 'technical') return 'pill-info';
    if (c === 'psychological') return 'pill-warning';
    return 'pill-neutral';
  };

  const getMitreStatusBadgeClass = (status?: string) => {
    const s = status?.toLowerCase() || '';
    if (s === 'mapped') return 'pill-success';
    if (s === 'partial') return 'pill-warning';
    return 'pill-neutral';
  };

  const getRiskMeterClass = (score: number | null) => {
    if (score === null || score === undefined) return 'meter-info';
    if (score >= 70) return 'meter-danger';
    if (score >= 40) return 'meter-warning';
    return 'meter-success';
  };

  // Plain English explanation resolution
  const plainEnglishExplanation = 
    threatAssessment.justification || 
    result.explanation || 
    'The forensic reasoning engine analyzed this artifact against contextual heuristics and behavioral models.';

  // Short potential impact resolution
  const resolvedPotentialImpact = attackerIntent.potentialImpact || (() => {
    const established = victimImpacts.filter(v => v.isEstablished);
    if (established.length > 0) {
      return established.map(e => e.category).join(', ') + ' risk';
    }
    const verdictLower = (threatAssessment.verdict || '').toLowerCase();
    if (verdictLower === 'phishing' || verdictLower === 'suspicious' || verdictLower === 'malicious') {
      return 'Credential exposure and possible unauthorized account access';
    }
    return null;
  })();

  // Toggle feature panel (Simple by default, Deep when requested)
  const toggleFeaturePanel = (panelId: FeaturePanelId) => {
    if (activePanel === panelId) {
      setActivePanel(null);
    } else {
      setActivePanel(panelId);
      setTimeout(() => {
        const panelEl = document.getElementById('active-feature-panel');
        if (panelEl) {
          panelEl.scrollIntoView({ behavior: 'smooth', block: 'start' });
        }
      }, 50);
    }
  };

  // Scroll to and highlight evidence item (switches to evidence panel automatically)
  const scrollToEvidence = (evId: string) => {
    setActivePanel('evidence');
    setEvidenceFilter('all');
    setHighlightedEvId(evId);
    setTimeout(() => {
      const el = document.getElementById(`evidence-${evId}`);
      if (el) {
        el.scrollIntoView({ behavior: 'smooth', block: 'center' });
      }
    }, 100);
    setTimeout(() => setHighlightedEvId(null), 3500);
  };

  // Filtered evidence items
  const filteredEvidence = evidenceItems.filter(ev => {
    if (evidenceFilter === 'all') return true;
    return (ev.category || '').toLowerCase() === evidenceFilter;
  });

  // Export handlers
  const handleExportJson = () => {
    const reportData = {
      exportMetadata: {
        reportType: 'PhishForensics AI Unified Forensic Investigation Report',
        version: '1.0.0',
        exportedAt: new Date().toISOString(),
        analysisId: result.analysisId || 'UNKNOWN',
        sourceType: inputType
      },
      sections: {
        '01_primaryThreatAnalysis': {
          verdict: threatAssessment.verdict,
          severity: threatAssessment.severity,
          riskScore: threatAssessment.riskScore,
          confidence: threatAssessment.confidence,
          plainEnglishExplanation,
          primaryIntent: attackerIntent.primaryGoal,
          potentialImpact: resolvedPotentialImpact
        },
        '02_threatAssessment': threatAssessment,
        '03_attackerIntent': attackerIntent,
        '04_forensicEvidence': evidenceItems,
        '05_evidenceConfidence': evidenceItems.map(e => ({ id: e.id, confidence: e.confidence })),
        '06_iocExtraction': extractedIOCs,
        '07_attackDNA': attackDNA,
        '08_attackerFingerprint': {
          deliveryVector: attackDNA?.deliveryVector || inputType,
          targetFocus: attackerIntent.description || 'Target Recipient',
          primaryObjective: attackerIntent.primaryGoal,
          complexity: attackDNA?.complexity || 'Standard'
        },
        '09_attackReconstruction': reconstruction,
        '10_safeSimulation': safeSimulation,
        '11_victimImpactAnalysis': victimImpacts,
        '12_mitreAttackMapping': mitreAttack,
        '13_safetyGuidance': safetyGuidance
      }
    };

    const blob = new Blob([JSON.stringify(reportData, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `phishforensics-report-${result.analysisId || 'investigation'}.json`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
    setShowExportDropdown(false);
  };

  const handleExportPdf = () => {
    setShowExportDropdown(false);
    window.print();
  };

  const formattedTimestamp = result.timestamp 
    ? new Date(result.timestamp).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' })
    : 'Live Session';

  // Compare investigations lookup
  const attackA = investigationHistory.find(item => item.analysisId === compareAttackAId) || result;
  const attackB = investigationHistory.find(item => item.analysisId === compareAttackBId) || result;

  // Panel tag and title helpers
  const getPanelTag = (panel: FeaturePanelId) => {
    switch (panel) {
      case 'evidence': return 'SEC // 04 • FORENSIC EVIDENCE MATRIX';
      case 'dna': return 'SEC // 06A • ATTACK DNA HEURISTICS';
      case 'fingerprint': return 'SEC // 06B • ATTACKER FINGERPRINT';
      case 'reconstruction': return 'SEC // 07 • ATTACK RECONSTRUCTION';
      case 'mitre': return 'SEC // 10 • MITRE ATT&CK® ENTERPRISE MAPPING';
      case 'iocs': return 'SEC // 05 • DEFANGED OBSERVABLES & IOCS';
      case 'impact': return 'SEC // 09 • VICTIM IMPACT ANALYSIS';
      case 'simulation': return 'SEC // 08 • SAFE EDUCATIONAL SIMULATION';
      case 'guidance': return 'SEC // 11 • ACTIONABLE COUNTERMEASURES';
      case 'export': return 'REPORT // EXPORT OPTIONS';
    }
  };

  const getPanelTitle = (panel: FeaturePanelId) => {
    switch (panel) {
      case 'evidence': return 'Forensic Evidence Indicators';
      case 'dna': return 'Attack DNA Behavioral Signatures';
      case 'fingerprint': return 'Attacker Tactical Fingerprint';
      case 'reconstruction': return 'Multi-Stage Attack Reconstruction Timeline';
      case 'mitre': return 'MITRE ATT&CK® Enterprise Mapping';
      case 'iocs': return 'Indicators of Compromise (Defanged IOCs)';
      case 'impact': return 'Potential Victim Impact Assessment';
      case 'simulation': return 'Safe Educational Simulation Walkthrough';
      case 'guidance': return 'Actionable Safety Guidance & Countermeasures';
      case 'export': return 'Forensic Report Export Center';
    }
  };

  return (
    <div className="dashboard-container">
      
      {/* ─── INVESTIGATION TOP UTILITY BAR ─────────────────────────────────── */}
      <section className="investigation-top-bar" aria-label="Investigation Metadata and Actions">
        <div className="header-meta-group">
          <span className="meta-chip">
            INVESTIGATION ID: <strong>{result.analysisId ? result.analysisId.substring(0, 14) + '...' : 'UNKNOWN'}</strong>
          </span>
          <span className="meta-chip">
            TYPE: <strong>{inputType.toUpperCase()}</strong>
          </span>
          <span className="meta-chip">
            TIMESTAMP: <strong>{formattedTimestamp}</strong>
          </span>
        </div>

        <div className="header-actions-group">
          {/* Compare Attacks Button */}
          <button 
            className="btn-header-action" 
            onClick={() => setShowCompareModal(true)}
            type="button"
            aria-label="Compare Investigations"
          >
            ⚖ Compare Attacks
          </button>

          {/* Export Dropdown */}
          <div style={{ position: 'relative' }}>
            <button 
              className="btn-header-action btn-highlight" 
              onClick={() => setShowExportDropdown(!showExportDropdown)}
              type="button"
              aria-expanded={showExportDropdown}
              aria-label="Export Report Options"
            >
              📄 Export Report ▾
            </button>

            {showExportDropdown && (
              <div className="export-dropdown-menu">
                <button 
                  className="dropdown-menu-item"
                  onClick={handleExportPdf}
                  type="button"
                >
                  📄 Export PDF Report
                </button>
                <button 
                  className="dropdown-menu-item"
                  onClick={handleExportJson}
                  type="button"
                >
                  { } Export JSON Report
                </button>
              </div>
            )}
          </div>

          <button className="nav-back-button" onClick={() => navigate('/')}>
            ← New Investigation
          </button>
        </div>
      </section>

      {/* ─── 1. PRIMARY ANALYSIS RESULT: THREAT ANALYSIS ──────────────────── */}
      <section className="primary-threat-analysis-card" aria-label="Primary Threat Analysis">
        <div className="threat-analysis-header-row">
          <div className="threat-analysis-title-wrap">
            <span className="section-tag-hero">SECURITY INTELLIGENCE</span>
            <h1 className="threat-analysis-title">THREAT ANALYSIS</h1>
          </div>
          <div className="threat-status-pills-row">
            <span className={`pill-badge ${getSeverityPillClass(threatAssessment.severity)}`}>
              {threatAssessment.severity.toUpperCase()} SEVERITY
            </span>
          </div>
        </div>

        <div className="threat-analysis-main-grid">
          {/* Left Column: Verdict Hero + Plain-English Explanation */}
          <div className="verdict-summary-column">
            <div className={`verdict-hero-badge-box ${getVerdictClass(threatAssessment.verdict)}`}>
              <div className="verdict-hero-icon" aria-hidden="true">
                {getVerdictIcon(threatAssessment.verdict)}
              </div>
              <div className="verdict-hero-content">
                <span className="verdict-subtitle">Threat Verdict</span>
                <span className="verdict-main-text">{threatAssessment.verdict}</span>
              </div>
            </div>

            {/* Plain-English Explanation */}
            <div className="threat-explanation-card">
              <span className="data-field-label">Executive Explanation</span>
              <p className="threat-explanation-narrative">
                {plainEnglishExplanation}
              </p>
            </div>
          </div>

          {/* Right Column: Quantitative Metrics + Intent + Impact */}
          <div className="threat-details-column">
            {/* Risk & Confidence Metrics */}
            <div className="metrics-side-grid">
              <div className="metric-box-card">
                <span className="metric-box-label">Risk Score</span>
                <div className="metric-box-val">
                  {threatAssessment.riskScore !== null ? (
                    <>
                      <span className="metric-num">{threatAssessment.riskScore}</span>
                      <span className="metric-denom">/ 100</span>
                    </>
                  ) : (
                    <span className="metric-denom">N/A</span>
                  )}
                </div>
                <div className="meter-track">
                  <div 
                    className={`meter-fill ${getRiskMeterClass(threatAssessment.riskScore)}`}
                    style={{ width: `${Math.min(100, Math.max(0, threatAssessment.riskScore ?? 0))}%` }}
                  />
                </div>
              </div>

              <div className="metric-box-card">
                <span className="metric-box-label">Confidence</span>
                <div className="metric-box-val">
                  <span className="metric-num">{threatAssessment.confidence}%</span>
                </div>
                <div className="meter-track">
                  <div 
                    className="meter-fill meter-info"
                    style={{ width: `${Math.min(100, Math.max(0, threatAssessment.confidence || 0))}%` }}
                  />
                </div>
              </div>
            </div>

            {/* Intent & Impact Box */}
            <div className="intent-impact-summary-card">
              <div className="intent-entry-box">
                <span className="data-field-label">Primary Attacker Intent</span>
                <p className="intent-primary-text">
                  {attackerIntent.primaryGoal || 'Not established from available evidence.'}
                </p>
                {attackerIntent.description && (
                  <p className="intent-sub-text">
                    Target Focus: {attackerIntent.description}
                  </p>
                )}
              </div>

              {resolvedPotentialImpact && (
                <div className="impact-entry-box">
                  <span className="data-field-label">Potential Impact</span>
                  <p className="impact-primary-text">
                    {resolvedPotentialImpact}
                  </p>
                </div>
              )}
            </div>
          </div>
        </div>

        {/* Collapsible Original Submitted Artifact Content */}
        {inputContent && (
          <div className="evidence-preview-container" style={{ marginTop: '1.25rem' }}>
            <button 
              className="evidence-preview-toggle" 
              onClick={() => setShowArtifactContent(!showArtifactContent)}
              type="button"
              aria-expanded={showArtifactContent}
            >
              <span>Submitted Artifact Source ({inputType.toUpperCase()})</span>
              <span>{showArtifactContent ? '▲ Hide Source' : '▼ Inspect Raw Source'}</span>
            </button>
            {showArtifactContent && (
              <div className="evidence-preview-content">
                {rawInput?.type === 'image' ? (
                  <img 
                    src={inputContent} 
                    alt="Submitted Evidence" 
                    style={{ maxWidth: '100%', maxHeight: '240px', borderRadius: '4px' }} 
                  />
                ) : (
                  inputContent
                )}
              </div>
            )}
          </div>
        )}
      </section>

      {/* ─── 2. "INVESTIGATE FURTHER" FEATURE AREA ───────────────────────── */}
      <section className="investigate-further-section" aria-label="Investigation Feature Selection">
        <div className="investigate-section-header">
          <div className="investigate-title-row">
            <span className="investigate-tag">DEEP DIVE FORENSICS</span>
            <h2 className="investigate-title">WHAT WOULD YOU LIKE TO INVESTIGATE?</h2>
          </div>
          <p className="investigate-subtitle">
            Select a specialized forensic module below to inspect underlying evidence, behavioral traits, MITRE techniques, or victim impact.
          </p>
        </div>

        <div className="feature-cards-grid" role="tablist" aria-label="Forensic Investigation Modules">
          
          {/* [ 🔎 EVIDENCE ] */}
          <button
            type="button"
            className={`feature-card-btn ${activePanel === 'evidence' ? 'feature-card-active' : ''}`}
            onClick={() => toggleFeaturePanel('evidence')}
            role="tab"
            aria-selected={activePanel === 'evidence'}
            aria-controls="active-feature-panel"
          >
            <div className="feature-card-top">
              <span className="feature-card-icon" aria-hidden="true">🔎</span>
              <span className="feature-card-name">
                {evidenceItems.length > 0 ? 'VIEW EVIDENCE' : 'EVIDENCE'}
                {activePanel === 'evidence' && <span className="feature-active-check"> ✓</span>}
              </span>
            </div>
            <p className="feature-card-desc">
              Inspect the indicators that influenced the analysis.
            </p>
            <div className="feature-card-footer">
              <span className="feature-card-chip">{evidenceItems.length} signal{evidenceItems.length === 1 ? '' : 's'}</span>
              <span className="feature-card-action-hint">
                {activePanel === 'evidence' ? 'Close [✕]' : 'Inspect →'}
              </span>
            </div>
          </button>

          {/* [ 🧬 ATTACK DNA ] */}
          <button
            type="button"
            className={`feature-card-btn ${activePanel === 'dna' ? 'feature-card-active' : ''}`}
            onClick={() => toggleFeaturePanel('dna')}
            role="tab"
            aria-selected={activePanel === 'dna'}
            aria-controls="active-feature-panel"
          >
            <div className="feature-card-top">
              <span className="feature-card-icon" aria-hidden="true">🧬</span>
              <span className="feature-card-name">
                ATTACK DNA
                {activePanel === 'dna' && <span className="feature-active-check"> ✓</span>}
              </span>
            </div>
            <p className="feature-card-desc">
              Explore behavioral heuristics, delivery vector, and traits.
            </p>
            <div className="feature-card-footer">
              <span className="feature-card-chip">
                {attackDNA?.traits?.filter((t: any) => t.present).length || 0} active traits
              </span>
              <span className="feature-card-action-hint">
                {activePanel === 'dna' ? 'Close [✕]' : 'Inspect →'}
              </span>
            </div>
          </button>

          {/* [ 🕵 ATTACKER FINGERPRINT ] */}
          <button
            type="button"
            className={`feature-card-btn ${activePanel === 'fingerprint' ? 'feature-card-active' : ''}`}
            onClick={() => toggleFeaturePanel('fingerprint')}
            role="tab"
            aria-selected={activePanel === 'fingerprint'}
            aria-controls="active-feature-panel"
          >
            <div className="feature-card-top">
              <span className="feature-card-icon" aria-hidden="true">🕵</span>
              <span className="feature-card-name">
                ATTACKER FINGERPRINT
                {activePanel === 'fingerprint' && <span className="feature-active-check"> ✓</span>}
              </span>
            </div>
            <p className="feature-card-desc">
              Review tactical persona, target focus, and adversary profile.
            </p>
            <div className="feature-card-footer">
              <span className="feature-card-chip">
                {attackerIntent.primaryGoal ? 'Profile available' : 'Standard'}
              </span>
              <span className="feature-card-action-hint">
                {activePanel === 'fingerprint' ? 'Close [✕]' : 'Inspect →'}
              </span>
            </div>
          </button>

          {/* [ 🧩 ATTACK RECONSTRUCTION ] */}
          <button
            type="button"
            className={`feature-card-btn ${activePanel === 'reconstruction' ? 'feature-card-active' : ''}`}
            onClick={() => toggleFeaturePanel('reconstruction')}
            role="tab"
            aria-selected={activePanel === 'reconstruction'}
            aria-controls="active-feature-panel"
          >
            <div className="feature-card-top">
              <span className="feature-card-icon" aria-hidden="true">🧩</span>
              <span className="feature-card-name">
                ATTACK RECONSTRUCTION
                {activePanel === 'reconstruction' && <span className="feature-active-check"> ✓</span>}
              </span>
            </div>
            <p className="feature-card-desc">
              Step through the multi-stage attack timeline and mechanisms.
            </p>
            <div className="feature-card-footer">
              <span className="feature-card-chip">
                {reconstructionStages.length} progression stage{reconstructionStages.length === 1 ? '' : 's'}
              </span>
              <span className="feature-card-action-hint">
                {activePanel === 'reconstruction' ? 'Close [✕]' : 'Inspect →'}
              </span>
            </div>
          </button>

          {/* [ 🎯 MITRE ATT&CK ] */}
          <button
            type="button"
            className={`feature-card-btn ${activePanel === 'mitre' ? 'feature-card-active' : ''}`}
            onClick={() => toggleFeaturePanel('mitre')}
            role="tab"
            aria-selected={activePanel === 'mitre'}
            aria-controls="active-feature-panel"
          >
            <div className="feature-card-top">
              <span className="feature-card-icon" aria-hidden="true">🎯</span>
              <span className="feature-card-name">
                MITRE ATT&CK
                {activePanel === 'mitre' && <span className="feature-active-check"> ✓</span>}
              </span>
            </div>
            <p className="feature-card-desc">
              See standardized techniques supported by the evidence.
            </p>
            <div className="feature-card-footer">
              <span className="feature-card-chip">
                {mitreAttack ? `Status: ${mitreAttack.status}` : 'Not evaluated'}
              </span>
              <span className="feature-card-action-hint">
                {activePanel === 'mitre' ? 'Close [✕]' : 'Inspect →'}
              </span>
            </div>
          </button>

          {/* [ 🌐 INDICATORS / IOCs ] */}
          <button
            type="button"
            className={`feature-card-btn ${activePanel === 'iocs' ? 'feature-card-active' : ''}`}
            onClick={() => toggleFeaturePanel('iocs')}
            role="tab"
            aria-selected={activePanel === 'iocs'}
            aria-controls="active-feature-panel"
          >
            <div className="feature-card-top">
              <span className="feature-card-icon" aria-hidden="true">🌐</span>
              <span className="feature-card-name">
                INDICATORS / IOCs
                {activePanel === 'iocs' && <span className="feature-active-check"> ✓</span>}
              </span>
            </div>
            <p className="feature-card-desc">
              Extract and copy defanged URLs, domains, and observables.
            </p>
            <div className="feature-card-footer">
              <span className="feature-card-chip">
                {extractedIOCs.length} defanged observable{extractedIOCs.length === 1 ? '' : 's'}
              </span>
              <span className="feature-card-action-hint">
                {activePanel === 'iocs' ? 'Close [✕]' : 'Inspect →'}
              </span>
            </div>
          </button>

          {/* [ ⚠ VICTIM IMPACT ] */}
          <button
            type="button"
            className={`feature-card-btn ${activePanel === 'impact' ? 'feature-card-active' : ''}`}
            onClick={() => toggleFeaturePanel('impact')}
            role="tab"
            aria-selected={activePanel === 'impact'}
            aria-controls="active-feature-panel"
          >
            <div className="feature-card-top">
              <span className="feature-card-icon" aria-hidden="true">⚠</span>
              <span className="feature-card-name">
                VICTIM IMPACT
                {activePanel === 'impact' && <span className="feature-active-check"> ✓</span>}
              </span>
            </div>
            <p className="feature-card-desc">
              Analyze potential credential, financial, and data fallout.
            </p>
            <div className="feature-card-footer">
              <span className="feature-card-chip">
                {victimImpacts.filter(v => v.isEstablished).length} established risk{victimImpacts.filter(v => v.isEstablished).length === 1 ? '' : 's'}
              </span>
              <span className="feature-card-action-hint">
                {activePanel === 'impact' ? 'Close [✕]' : 'Inspect →'}
              </span>
            </div>
          </button>

          {/* [ 🛡 SAFE SIMULATION ] */}
          <button
            type="button"
            className={`feature-card-btn ${activePanel === 'simulation' ? 'feature-card-active' : ''}`}
            onClick={() => toggleFeaturePanel('simulation')}
            role="tab"
            aria-selected={activePanel === 'simulation'}
            aria-controls="active-feature-panel"
          >
            <div className="feature-card-top">
              <span className="feature-card-icon" aria-hidden="true">🛡</span>
              <span className="feature-card-name">
                SAFE SIMULATION
                {activePanel === 'simulation' && <span className="feature-active-check"> ✓</span>}
              </span>
            </div>
            <p className="feature-card-desc">
              Walk through safe educational scenarios and defensive tips.
            </p>
            <div className="feature-card-footer">
              <span className="feature-card-chip">
                {simulationStages.length} stage{simulationStages.length === 1 ? '' : 's'}
              </span>
              <span className="feature-card-action-hint">
                {activePanel === 'simulation' ? 'Close [✕]' : 'Inspect →'}
              </span>
            </div>
          </button>

          {/* [ 🛡 DEFENSIVE GUIDANCE ] */}
          <button
            type="button"
            className={`feature-card-btn ${activePanel === 'guidance' ? 'feature-card-active' : ''}`}
            onClick={() => toggleFeaturePanel('guidance')}
            role="tab"
            aria-selected={activePanel === 'guidance'}
            aria-controls="active-feature-panel"
          >
            <div className="feature-card-top">
              <span className="feature-card-icon" aria-hidden="true">🛡️</span>
              <span className="feature-card-name">
                SAFETY GUIDANCE
                {activePanel === 'guidance' && <span className="feature-active-check"> ✓</span>}
              </span>
            </div>
            <p className="feature-card-desc">
              View actionable countermeasures and preventive actions.
            </p>
            <div className="feature-card-footer">
              <span className="feature-card-chip">Defensive playbook</span>
              <span className="feature-card-action-hint">
                {activePanel === 'guidance' ? 'Close [✕]' : 'Inspect →'}
              </span>
            </div>
          </button>

          {/* [ ⚖ COMPARE ATTACKS ] */}
          <button
            type="button"
            className="feature-card-btn"
            onClick={() => setShowCompareModal(true)}
            role="button"
            aria-label="Compare Investigations"
          >
            <div className="feature-card-top">
              <span className="feature-card-icon" aria-hidden="true">⚖</span>
              <span className="feature-card-name">COMPARE ATTACKS</span>
            </div>
            <p className="feature-card-desc">
              Benchmark this investigation against previous threat artifacts.
            </p>
            <div className="feature-card-footer">
              <span className="feature-card-chip">{investigationHistory.length} in history</span>
              <span className="feature-card-action-hint">Launch ⇄</span>
            </div>
          </button>

          {/* [ 📄 EXPORT REPORT ] */}
          <button
            type="button"
            className={`feature-card-btn ${activePanel === 'export' ? 'feature-card-active' : ''}`}
            onClick={() => toggleFeaturePanel('export')}
            role="tab"
            aria-selected={activePanel === 'export'}
            aria-controls="active-feature-panel"
          >
            <div className="feature-card-top">
              <span className="feature-card-icon" aria-hidden="true">📄</span>
              <span className="feature-card-name">
                EXPORT REPORT
                {activePanel === 'export' && <span className="feature-active-check"> ✓</span>}
              </span>
            </div>
            <p className="feature-card-desc">
              Download investigation reports in official PDF or JSON format.
            </p>
            <div className="feature-card-footer">
              <span className="feature-card-chip">PDF / JSON</span>
              <span className="feature-card-action-hint">
                {activePanel === 'export' ? 'Close [✕]' : 'Download ⤓'}
              </span>
            </div>
          </button>

        </div>
      </section>

      {/* ─── 3. ACTIVE FEATURE PANEL (APPEARS ONLY AFTER SELECTION) ────────── */}
      {activePanel && (
        <section 
          id="active-feature-panel" 
          className="active-feature-panel-wrapper"
          role="tabpanel"
          aria-label={getPanelTitle(activePanel)}
        >
          {/* Top Panel Control Bar */}
          <div className="feature-panel-top-bar">
            <div className="panel-title-area">
              <span className="panel-tag-code">{getPanelTag(activePanel)}</span>
              <h2 className="panel-main-title">{getPanelTitle(activePanel)}</h2>
            </div>
            <button
              type="button"
              className="btn-close-feature-panel"
              onClick={() => setActivePanel(null)}
              aria-label="Close detailed feature panel"
            >
              ✕ Close Panel
            </button>
          </div>

          {/* Detailed Content Container */}
          <div className="feature-panel-body">
            
            {/* ── PANEL: EVIDENCE ── */}
            {activePanel === 'evidence' && (
              <div className="panel-module-section">
                <div className="panel-sub-header">
                  <div className="evidence-filter-bar">
                    <button 
                      type="button"
                      className={`filter-btn ${evidenceFilter === 'all' ? 'active' : ''}`}
                      onClick={() => setEvidenceFilter('all')}
                    >
                      [ ALL ] ({evidenceItems.length})
                    </button>
                    <button 
                      type="button"
                      className={`filter-btn ${evidenceFilter === 'technical' ? 'active' : ''}`}
                      onClick={() => setEvidenceFilter('technical')}
                    >
                      [ TECHNICAL ] ({evidenceItems.filter(e => e.category === 'technical').length})
                    </button>
                    <button 
                      type="button"
                      className={`filter-btn ${evidenceFilter === 'psychological' ? 'active' : ''}`}
                      onClick={() => setEvidenceFilter('psychological')}
                    >
                      [ PSYCHOLOGICAL ] ({evidenceItems.filter(e => e.category === 'psychological').length})
                    </button>
                    <button 
                      type="button"
                      className={`filter-btn ${evidenceFilter === 'contextual' ? 'active' : ''}`}
                      onClick={() => setEvidenceFilter('contextual')}
                    >
                      [ CONTEXTUAL ] ({evidenceItems.filter(e => e.category === 'contextual').length})
                    </button>
                  </div>
                  <span className="meta-chip">
                    EVIDENCE COUNT: <strong>{evidenceItems.length}</strong>
                  </span>
                </div>

                {evidenceItems.length === 0 ? (
                  <div className="empty-state-box">
                    No specific forensic indicators were returned by the analysis engine.
                  </div>
                ) : filteredEvidence.length > 0 ? (
                  <div className="evidence-grid">
                    {filteredEvidence.map((ev: any) => {
                      const displayVal = ev.defangedValue || ev.value || '';
                      const hasConfidence = ev.confidence !== null && ev.confidence !== undefined;

                      return (
                        <div 
                          key={ev.id} 
                          id={`evidence-${ev.id}`}
                          className={`evidence-item-card ${highlightedEvId === ev.id ? 'evidence-highlight-active' : ''}`}
                        >
                          <div className="evidence-item-top">
                            <span className="evidence-id-mono">{ev.id}</span>
                            <span className={`pill-badge ${getEvidenceCategoryPillClass(ev.category)}`}>
                              {ev.category || 'contextual'}
                            </span>
                          </div>

                          <div className="evidence-val-row" title={displayVal}>
                            {displayVal}
                          </div>

                          {ev.description && ev.description !== displayVal && (
                            <div className="evidence-desc-row">
                              {ev.description}
                            </div>
                          )}

                          {/* Confidence meter */}
                          <div className="confidence-meter-row">
                            <div className="confidence-bar-track">
                              <div 
                                className="confidence-bar-fill" 
                                style={{ width: `${hasConfidence ? Math.min(100, Math.max(0, ev.confidence)) : 50}%` }}
                              />
                            </div>
                            <span className="confidence-percent-label">
                              {hasConfidence ? `${ev.confidence}% Confidence` : 'Confidence: Derived'}
                            </span>
                          </div>
                        </div>
                      );
                    })}
                  </div>
                ) : (
                  <div className="empty-state-box">
                    No evidence items found matching the selected filter ({evidenceFilter.toUpperCase()}).
                  </div>
                )}
              </div>
            )}

            {/* ── PANEL: ATTACK DNA ── */}
            {activePanel === 'dna' && (
              <div className="panel-module-section">
                <p style={{ fontSize: '0.85rem', color: 'var(--text-muted)', marginBottom: '1.25rem' }}>
                  Structured behavioral fingerprint capturing technical & psychological signatures evaluated by heuristic models.
                </p>

                {!attackDNA ? (
                  <div className="empty-state-box">
                    Attack DNA profile was not established for this artifact.
                  </div>
                ) : (
                  <div>
                    {attackDNA.complexity && (
                      <div style={{ marginBottom: '1rem' }}>
                        <span className="data-field-label">Evaluated Complexity</span>
                        <div style={{ marginTop: '0.35rem' }}>
                          <span className="pill-badge pill-neutral" style={{ fontSize: '0.8rem', padding: '0.3rem 0.75rem' }}>
                            {attackDNA.complexity} Complexity
                          </span>
                        </div>
                      </div>
                    )}

                    {attackDNA.profileSummary && (
                      <div className="callout-quote-box" style={{ marginBottom: '1.25rem' }}>
                        {attackDNA.profileSummary}
                      </div>
                    )}

                    {attackDNA.deliveryVector && (
                      <div className="data-field-group" style={{ marginBottom: '1.25rem' }}>
                        <span className="data-field-label">Delivery Vector</span>
                        <p className="data-field-value-text" style={{ fontWeight: 600 }}>{attackDNA.deliveryVector}</p>
                      </div>
                    )}

                    {/* Observed Traits Grid */}
                    {attackDNA.traits && attackDNA.traits.length > 0 && (
                      <div className="data-field-group">
                        <span className="data-field-label">Evaluated Behavioral Traits</span>
                        <div className="dna-traits-grid" style={{ marginTop: '0.5rem' }}>
                          {attackDNA.traits.map((tr: any) => (
                            <div 
                              key={tr.key} 
                              className={`dna-trait-pill ${tr.present ? 'trait-active' : ''}`}
                            >
                              <span className="dna-trait-name">{tr.label || tr.key}</span>
                              <span className="dna-trait-status">
                                {tr.present ? (tr.intensity ? tr.intensity.toUpperCase() : 'DETECTED') : 'NOT DETECTED'}
                              </span>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                )}
              </div>
            )}

            {/* ── PANEL: ATTACKER FINGERPRINT ── */}
            {activePanel === 'fingerprint' && (
              <div className="panel-module-section">
                <p style={{ fontSize: '0.85rem', color: 'var(--text-muted)', marginBottom: '1.25rem' }}>
                  Concise operational interpretation derived from Attack DNA and investigation signals.
                </p>

                <div className="fingerprint-meta-grid">
                  <div className="fingerprint-meta-item">
                    <div className="fingerprint-label">Delivery Vector</div>
                    <div className="fingerprint-value">
                      {attackDNA?.deliveryVector || inputType.toUpperCase() || 'Not established'}
                    </div>
                  </div>

                  <div className="fingerprint-meta-item">
                    <div className="fingerprint-label">Social Engineering Pattern</div>
                    <div className="fingerprint-value">
                      {evidenceItems.some(e => e.category === 'psychological')
                        ? 'Urgency & Pretext Manipulation'
                        : 'Direct Technical Delivery'}
                    </div>
                  </div>

                  <div className="fingerprint-meta-item">
                    <div className="fingerprint-label">Target Focus</div>
                    <div className="fingerprint-value">
                      {attackerIntent.description || 'Target Account Holder'}
                    </div>
                  </div>

                  <div className="fingerprint-meta-item">
                    <div className="fingerprint-label">Primary Objective</div>
                    <div className="fingerprint-value">
                      {attackerIntent.primaryGoal || 'Not established from available evidence.'}
                    </div>
                  </div>

                  <div className="fingerprint-meta-item">
                    <div className="fingerprint-label">Observed Complexity</div>
                    <div className="fingerprint-value">
                      {attackDNA?.complexity || 'Standard'}
                    </div>
                  </div>

                  <div className="fingerprint-meta-item">
                    <div className="fingerprint-label">Behavioral Signature</div>
                    <div className="fingerprint-value">
                      {threatAssessment.verdict === 'phishing' ? 'Credential Harvester' : threatAssessment.verdict}
                    </div>
                  </div>
                </div>

                <div className="fingerprint-disclaimer" style={{ marginTop: '1.5rem' }}>
                  <strong>Taxonomy Note:</strong> Attack DNA represents product-specific behavioral heuristics; MITRE ATT&CK provides standardized enterprise techniques. No nation-state or specific threat actor group attribution is claimed.
                </div>
              </div>
            )}

            {/* ── PANEL: ATTACK RECONSTRUCTION ── */}
            {activePanel === 'reconstruction' && (
              <div className="panel-module-section">
                {!reconstruction || reconstructionStages.length === 0 ? (
                  <div className="empty-state-box">
                    Attack reconstruction data is not available.
                  </div>
                ) : (
                  <div>
                    {reconstruction.attackFlowSummary && (
                      <p className="data-field-value-text" style={{ marginBottom: '1.5rem', fontSize: '0.92rem', lineHeight: '1.6' }}>
                        {reconstruction.attackFlowSummary}
                      </p>
                    )}

                    <div className="stepper-timeline">
                      {reconstructionStages.map((stg: any, idx: number) => (
                        <div key={stg.stageId || idx} className="stepper-node">
                          <div className="stepper-circle">{idx + 1}</div>
                          <div className="stepper-content">
                            <div className="stepper-title">
                              {stg.stageTitle || stg.stageName || stg.stage || `Stage ${idx + 1}`}
                            </div>
                            <div className="stepper-desc">
                              {stg.stageDescription || stg.description}
                            </div>
                            {stg.mechanism && (
                              <span className="stepper-mechanism-tag">
                                Mechanism: {stg.mechanism}
                              </span>
                            )}
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            )}

            {/* ── PANEL: MITRE ATT&CK ── */}
            {activePanel === 'mitre' && (
              <div className="panel-module-section">
                {!mitreAttack ? (
                  <div className="empty-state-box">
                    No verified MITRE ATT&CK techniques matched the available evidence.
                  </div>
                ) : mitreAttack.status === 'unmapped' ? (
                  <div>
                    <div className="empty-state-box">
                      No verified MITRE ATT&CK techniques matched the available evidence.
                    </div>
                    {mitreAttack.uncertaintyNotes && mitreAttack.uncertaintyNotes.length > 0 && (
                      <div className="uncertainty-note-box" style={{ marginTop: '1rem' }}>
                        <strong>Forensic Assessment Note:</strong> {mitreAttack.uncertaintyNotes.join(' ')}
                      </div>
                    )}
                  </div>
                ) : (
                  <div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', marginBottom: '1rem' }}>
                      <span className={`pill-badge ${getMitreStatusBadgeClass(mitreAttack.status)}`}>
                        Status: {mitreAttack.status}
                      </span>
                    </div>

                    {/* Primary Entry Technique Card */}
                    {mitreAttack.primaryTechnique && (
                      <div className="mitre-primary-card">
                        <div className="mitre-top-line">
                          <div>
                            <span className="data-field-label" style={{ color: 'var(--blue-primary)' }}>
                              Primary Entry Technique
                            </span>
                            <div className="mitre-tech-title">
                              {mitreAttack.primaryTechnique.techniqueId} — {mitreAttack.primaryTechnique.techniqueName}
                              {mitreAttack.primaryTechnique.subTechniqueId && (
                                <span className="mitre-subtech-badge">
                                  ({mitreAttack.primaryTechnique.subTechniqueId} {mitreAttack.primaryTechnique.subTechniqueName})
                                </span>
                              )}
                            </div>
                          </div>

                          <span className="mitre-tactic-pill">
                            Tactic: {mitreAttack.primaryTechnique.tactic?.name || 'Initial Access'} ({mitreAttack.primaryTechnique.tactic?.id})
                          </span>
                        </div>

                        <div className="mitre-rationale-text">
                          <strong>Why mapped:</strong> {mitreAttack.primaryTechnique.mappingRationale}
                        </div>

                        {mitreAttack.primaryTechnique.supportingEvidenceRefs && mitreAttack.primaryTechnique.supportingEvidenceRefs.length > 0 && (
                          <div className="mitre-refs-row">
                            <span>Supporting Evidence:</span>
                            {mitreAttack.primaryTechnique.supportingEvidenceRefs.map((ref: string) => (
                              <button
                                key={ref}
                                type="button"
                                className="clickable-evidence-ref"
                                title={`Click to view evidence ${ref}`}
                                onClick={() => scrollToEvidence(ref)}
                              >
                                [{ref}] ↗
                              </button>
                            ))}
                            {mitreAttack.primaryTechnique.confidence && (
                              <span style={{ marginLeft: 'auto' }}>
                                Confidence: <strong>{mitreAttack.primaryTechnique.confidence}%</strong>
                              </span>
                            )}
                          </div>
                        )}
                      </div>
                    )}

                    {/* Observed ATT&CK Tactics */}
                    {mitreAttack.observedTactics && mitreAttack.observedTactics.length > 0 && (
                      <div className="data-field-group" style={{ marginTop: '1.25rem' }}>
                        <span className="data-field-label">Observed ATT&CK Tactics</span>
                        <div className="tactics-badges-group" style={{ marginTop: '0.4rem' }}>
                          {mitreAttack.observedTactics.map((tac: any) => (
                            <a
                              key={tac.id}
                              href={tac.referenceUrl}
                              target="_blank"
                              rel="noopener noreferrer"
                              className="tactic-link-badge"
                            >
                              {tac.name} ({tac.id}) ↗
                            </a>
                          ))}
                        </div>
                      </div>
                    )}

                    {/* Evidence Qualification Notes */}
                    {mitreAttack.uncertaintyNotes && mitreAttack.uncertaintyNotes.length > 0 && (
                      <div className="uncertainty-note-box" style={{ marginTop: '1.25rem' }}>
                        <strong>Evidence Qualification Note:</strong> {mitreAttack.uncertaintyNotes.join(' ')}
                      </div>
                    )}
                  </div>
                )}
              </div>
            )}

            {/* ── PANEL: INDICATORS / IOCS ── */}
            {activePanel === 'iocs' && (
              <div className="panel-module-section">
                <div className="panel-sub-header">
                  <span className="data-field-label">Technical Observables & Indicators</span>
                  <span className="meta-chip">
                    TOTAL EXTRACTED: <strong>{extractedIOCs.length}</strong>
                  </span>
                </div>

                {extractedIOCs.length === 0 ? (
                  <div className="empty-state-box">
                    No technical indicators were extracted from this artifact.
                  </div>
                ) : (
                  <div className="ioc-grid">
                    {extractedIOCs.map((ioc) => (
                      <div key={ioc.id} className="ioc-item-card">
                        <div className="ioc-top-bar">
                          <span className="ioc-type-pill">{ioc.type}</span>
                          <span className="evidence-id-mono">{ioc.id}</span>
                        </div>

                        <div className="ioc-defanged-val" title="Defanged observable indicator">
                          {ioc.defangedValue}
                        </div>

                        <div className="ioc-actions-row">
                          <button 
                            type="button" 
                            className="btn-ioc-action"
                            onClick={() => {
                              navigator.clipboard.writeText(ioc.defangedValue);
                              setCopiedIoc(ioc.defangedValue);
                              setTimeout(() => setCopiedIoc(null), 2000);
                            }}
                          >
                            {copiedIoc === ioc.defangedValue ? '✓ Copied' : '[ COPY ]'}
                          </button>

                          {ioc.originEvidenceId && (
                            <button 
                              type="button" 
                              className="btn-ioc-action"
                              onClick={() => scrollToEvidence(ioc.originEvidenceId!)}
                            >
                              [ VIEW EVIDENCE ({ioc.originEvidenceId}) ] ↗
                            </button>
                          )}
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            )}

            {/* ── PANEL: VICTIM IMPACT ── */}
            {activePanel === 'impact' && (
              <div className="panel-module-section">
                <p style={{ fontSize: '0.85rem', color: 'var(--text-muted)', marginBottom: '1.25rem' }}>
                  Systematic evaluation of potential threat fallout across critical enterprise and identity dimensions.
                </p>

                <div className="impact-grid">
                  {victimImpacts.map((imp) => (
                    <div 
                      key={imp.category} 
                      className={`impact-card ${imp.isEstablished ? 'impact-established' : 'impact-unsupported'}`}
                    >
                      <div className="impact-top-line">
                        <span className="impact-title">{imp.category}</span>
                        {imp.isEstablished && imp.severity ? (
                          <span className={`pill-badge ${getSeverityPillClass(imp.severity)}`}>
                            {imp.severity}
                          </span>
                        ) : (
                          <span className="pill-badge pill-neutral">Not Established</span>
                        )}
                      </div>

                      <div className="impact-desc-text">
                        {imp.explanation}
                      </div>

                      {imp.isEstablished && imp.evidenceRefs.length > 0 && (
                        <div className="impact-refs-row">
                          <span>Evidence:</span>
                          {imp.evidenceRefs.map(ref => (
                            <button
                              key={ref}
                              type="button"
                              className="clickable-evidence-ref"
                              onClick={() => scrollToEvidence(ref)}
                              title={`Jump to ${ref}`}
                            >
                              [{ref}] ↗
                            </button>
                          ))}
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* ── PANEL: SAFE SIMULATION ── */}
            {activePanel === 'simulation' && (
              <div className="panel-module-section">
                {!safeSimulation ? (
                  <div className="empty-state-box">
                    Safe simulation scenario not generated for this analysis.
                  </div>
                ) : (
                  <div>
                    {safeSimulation.scenarioOverview && (
                      <p className="data-field-value-text" style={{ marginBottom: '1.25rem', lineHeight: '1.6' }}>
                        {safeSimulation.scenarioOverview}
                      </p>
                    )}

                    {simulationStages.length > 0 && (
                      <div>
                        {/* Stepper Tabs */}
                        <div className="sim-tabs-row">
                          {simulationStages.map((stage: any, idx: number) => (
                            <button
                              key={stage.stageId || stage.id || idx}
                              className={`sim-tab-btn ${idx === activeSimStage ? 'active' : ''}`}
                              onClick={() => setActiveSimStage(idx)}
                              type="button"
                            >
                              Stage {idx + 1}: {stage.stageTitle || stage.title || `Stage ${idx + 1}`}
                            </button>
                          ))}
                        </div>

                        {/* Active Stage Details Card */}
                        {simulationStages[activeSimStage] && (
                          <div className="sim-active-stage-card">
                            <div className="sim-active-stage-header">
                              {simulationStages[activeSimStage].stageTitle || simulationStages[activeSimStage].title || `Stage ${activeSimStage + 1}`}
                            </div>
                            <div className="sim-active-stage-narrative">
                              {simulationStages[activeSimStage].stageDescription || simulationStages[activeSimStage].description || simulationStages[activeSimStage].narrative}
                            </div>

                            {simulationStages[activeSimStage].mechanism && (
                              <div className="data-field-group" style={{ marginBottom: '0.6rem' }}>
                                <span className="data-field-label">Observed Delivery Mechanism</span>
                                <p className="data-field-value-text" style={{ fontSize: '0.85rem' }}>
                                  {simulationStages[activeSimStage].mechanism}
                                </p>
                              </div>
                            )}

                            {/* Safe Educational Consequence */}
                            {simulationStages[activeSimStage].possibleConsequence && (
                              <div className="sim-consequence-alert">
                                <strong>Hypothetical Consequence:</strong>{' '}
                                {simulationStages[activeSimStage].possibleConsequence.detailedConsequence || 
                                 simulationStages[activeSimStage].possibleConsequence.shortImpact || 
                                 simulationStages[activeSimStage].safeConsequence}
                              </div>
                            )}

                            {/* Educational Guidance */}
                            {simulationStages[activeSimStage].educationalGuidance && (
                              <div className="sim-guidance-box">
                                <strong>Educational Guidance:</strong>{' '}
                                {simulationStages[activeSimStage].educationalGuidance.headline && (
                                  <span>{simulationStages[activeSimStage].educationalGuidance.headline} — </span>
                                )}
                                {simulationStages[activeSimStage].educationalGuidance.keyTakeaway || 
                                 simulationStages[activeSimStage].educationalGuidance.practicalTip}
                              </div>
                            )}
                          </div>
                        )}

                        {/* Navigation Controls */}
                        <div className="sim-nav-controls">
                          <button
                            className="sim-control-btn"
                            disabled={activeSimStage === 0}
                            onClick={() => setActiveSimStage(Math.max(0, activeSimStage - 1))}
                            type="button"
                          >
                            ← Previous Stage
                          </button>
                          <span style={{ fontFamily: 'var(--font-mono)', fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                            Stage {activeSimStage + 1} of {simulationStages.length}
                          </span>
                          <button
                            className="sim-control-btn"
                            disabled={activeSimStage === simulationStages.length - 1}
                            onClick={() => setActiveSimStage(Math.min(simulationStages.length - 1, activeSimStage + 1))}
                            type="button"
                          >
                            Next Stage →
                          </button>
                        </div>
                      </div>
                    )}

                    {safeSimulation.safetyDisclaimer && (
                      <p style={{ marginTop: '1.25rem', fontSize: '0.75rem', color: 'var(--text-muted)', fontStyle: 'italic' }}>
                        ℹ {safeSimulation.safetyDisclaimer}
                      </p>
                    )}
                  </div>
                )}
              </div>
            )}

            {/* ── PANEL: SAFETY GUIDANCE ── */}
            {activePanel === 'guidance' && (
              <div className="panel-module-section">
                {safetyGuidance?.summary && (
                  <p className="data-field-value-text" style={{ marginBottom: '1.25rem', lineHeight: '1.6' }}>
                    {safetyGuidance.summary}
                  </p>
                )}

                {safetyGuidance?.immediateActions && safetyGuidance.immediateActions.length > 0 ? (
                  <div className="guidance-items-list">
                    {safetyGuidance.immediateActions.map((rec: any, idx: number) => {
                      const priority = rec.priority?.toLowerCase() || 'medium';
                      const priorityClass = priority === 'critical' || priority === 'high' 
                        ? 'pill-danger' 
                        : priority === 'medium' ? 'pill-warning' : 'pill-info';

                      return (
                        <div key={idx} className="guidance-item-card">
                          <div className="guidance-icon-check">✓</div>
                          <div className="guidance-text-content">
                            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.2rem' }}>
                              <span className={`pill-badge ${priorityClass}`} style={{ fontSize: '0.65rem', padding: '0.1rem 0.4rem' }}>
                                {priority.toUpperCase()}
                              </span>
                              <strong className="guidance-action-title">{rec.action}</strong>
                            </div>
                            {rec.reason && (
                              <p className="guidance-reason-desc">{rec.reason}</p>
                            )}
                          </div>
                        </div>
                      );
                    })}
                  </div>
                ) : result.recommendations && result.recommendations.length > 0 ? (
                  <div className="guidance-items-list">
                    {result.recommendations.map((rec: string, idx: number) => (
                      <div key={idx} className="guidance-item-card">
                        <div className="guidance-icon-check">✓</div>
                        <div className="guidance-text-content">
                          <p className="guidance-action-title">{rec}</p>
                        </div>
                      </div>
                    ))}
                  </div>
                ) : (
                  <div className="empty-state-box">
                    No specific countermeasures required for this artifact.
                  </div>
                )}
              </div>
            )}

            {/* ── PANEL: EXPORT REPORT ── */}
            {activePanel === 'export' && (
              <div className="panel-module-section">
                <p style={{ fontSize: '0.85rem', color: 'var(--text-muted)', marginBottom: '1.5rem' }}>
                  Generate and download forensic investigation reports containing full evidence trails, MITRE mappings, and intelligence matrices.
                </p>

                <div className="export-cards-row">
                  <div className="export-action-card">
                    <div className="export-card-icon">📄</div>
                    <div className="export-card-info">
                      <strong className="export-card-title">Export PDF Report</strong>
                      <p className="export-card-desc">
                        Print-ready document containing the complete Threat Analysis, evidence records, and ATT&CK matrix.
                      </p>
                    </div>
                    <button 
                      type="button" 
                      className="btn-primary-large" 
                      onClick={handleExportPdf}
                    >
                      [ EXPORT PDF ]
                    </button>
                  </div>

                  <div className="export-action-card">
                    <div className="export-card-icon">{ }</div>
                    <div className="export-card-info">
                      <strong className="export-card-title">Export JSON Intelligence</strong>
                      <p className="export-card-desc">
                        Standardized machine-readable JSON object matching the PhishForensics AI unified contract.
                      </p>
                    </div>
                    <button 
                      type="button" 
                      className="btn-primary-large" 
                      onClick={handleExportJson}
                    >
                      [ EXPORT JSON ]
                    </button>
                  </div>
                </div>

                <div className="export-breakdown-box" style={{ marginTop: '1.5rem' }}>
                  <span className="data-field-label">Included Intelligence Sections</span>
                  <div className="export-tags-list" style={{ display: 'flex', flexWrap: 'wrap', gap: '0.5rem', marginTop: '0.5rem' }}>
                    <span className="meta-chip">✓ Threat Verdict & Scores</span>
                    <span className="meta-chip">✓ Attacker Intent</span>
                    <span className="meta-chip">✓ {evidenceItems.length} Evidence Signals</span>
                    <span className="meta-chip">✓ {extractedIOCs.length} Defanged Observables</span>
                    <span className="meta-chip">✓ MITRE ATT&CK Mapping ({mitreAttack?.status || 'unmapped'})</span>
                    <span className="meta-chip">✓ Attack DNA & Heuristics</span>
                    <span className="meta-chip">✓ Victim Impact Matrix</span>
                  </div>
                </div>
              </div>
            )}

          </div>

          {/* Bottom Panel Control Bar */}
          <div className="feature-panel-footer-bar">
            <div className="panel-footer-meta">
              <span className="panel-footer-label">
                Active Module: <strong>{getPanelTitle(activePanel)}</strong>
              </span>
            </div>
            <button
              type="button"
              className="btn-close-feature-panel-bottom"
              onClick={() => {
                setActivePanel(null);
                window.scrollTo({ top: 300, behavior: 'smooth' });
              }}
            >
              ▲ Close Panel
            </button>
          </div>
        </section>
      )}

      {/* ─── ACTION FOOTER ─────────────────────────────────────────────────── */}
      <footer className="dashboard-footer-actions">
        <button className="btn-primary-large" onClick={() => navigate('/')}>
          ← Analyze Another Artifact
        </button>
      </footer>

      {/* ─── COMPARE TWO ATTACKS MODAL ─────────────────────────────────────── */}
      {showCompareModal && (
        <div className="modal-overlay" onClick={() => setShowCompareModal(false)}>
          <div className="modal-content-card" onClick={e => e.stopPropagation()}>
            <div className="modal-header-row">
              <div>
                <span className="section-tag">ANALYTICS // COMPARE</span>
                <h2 className="forensic-card-title" style={{ marginTop: '0.25rem' }}>Compare Investigations</h2>
              </div>
              <button 
                className="btn-header-action" 
                onClick={() => setShowCompareModal(false)}
                type="button"
              >
                ✕ Close
              </button>
            </div>

            <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', margin: 0 }}>
              Compare factual similarities and differences across completed investigation artifacts.
            </p>

            <div className="compare-selectors-bar">
              <div>
                <label className="data-field-label">Attack A (Investigation)</label>
                <select 
                  className="select-input-styled" 
                  value={compareAttackAId} 
                  onChange={e => setCompareAttackAId(e.target.value)}
                >
                  {investigationHistory.map((item, idx) => (
                    <option key={item.analysisId || idx} value={item.analysisId}>
                      {item.analysisId ? item.analysisId.substring(0, 12) + '...' : `Session ${idx + 1}`} ({item.threatAssessment?.verdict?.toUpperCase() || 'RESULT'})
                    </option>
                  ))}
                </select>
              </div>

              <div>
                <label className="data-field-label">Attack B (Investigation)</label>
                <select 
                  className="select-input-styled" 
                  value={compareAttackBId} 
                  onChange={e => setCompareAttackBId(e.target.value)}
                >
                  {investigationHistory.map((item, idx) => (
                    <option key={item.analysisId || idx} value={item.analysisId}>
                      {item.analysisId ? item.analysisId.substring(0, 12) + '...' : `Session ${idx + 1}`} ({item.threatAssessment?.verdict?.toUpperCase() || 'RESULT'})
                    </option>
                  ))}
                </select>
              </div>
            </div>

            {/* Comparison Table */}
            <table className="comparison-table">
              <thead>
                <tr>
                  <th style={{ width: '28%' }}>Dimension</th>
                  <th style={{ width: '36%' }}>Attack A ({attackA?.analysisId?.substring(0, 8) || 'Current'})</th>
                  <th style={{ width: '36%' }}>Attack B ({attackB?.analysisId?.substring(0, 8) || 'Current'})</th>
                </tr>
              </thead>
              <tbody>
                <tr>
                  <td>Threat Verdict</td>
                  <td>
                    <span className={`pill-badge ${getVerdictClass(attackA?.threatAssessment?.verdict)}`}>
                      {attackA?.threatAssessment?.verdict || 'Unknown'}
                    </span>
                  </td>
                  <td>
                    <span className={`pill-badge ${getVerdictClass(attackB?.threatAssessment?.verdict)}`}>
                      {attackB?.threatAssessment?.verdict || 'Unknown'}
                    </span>
                  </td>
                </tr>
                <tr>
                  <td>Severity Level</td>
                  <td>
                    <span className={`pill-badge ${getSeverityPillClass(attackA?.threatAssessment?.severity)}`}>
                      {attackA?.threatAssessment?.severity || 'Unknown'}
                    </span>
                  </td>
                  <td>
                    <span className={`pill-badge ${getSeverityPillClass(attackB?.threatAssessment?.severity)}`}>
                      {attackB?.threatAssessment?.severity || 'Unknown'}
                    </span>
                  </td>
                </tr>
                <tr>
                  <td>Risk Score</td>
                  <td>{attackA?.threatAssessment?.riskScore !== null && attackA?.threatAssessment?.riskScore !== undefined ? `${attackA.threatAssessment.riskScore} / 100` : 'N/A'}</td>
                  <td>{attackB?.threatAssessment?.riskScore !== null && attackB?.threatAssessment?.riskScore !== undefined ? `${attackB.threatAssessment.riskScore} / 100` : 'N/A'}</td>
                </tr>
                <tr>
                  <td>Confidence</td>
                  <td>{attackA?.threatAssessment?.confidence || 0}%</td>
                  <td>{attackB?.threatAssessment?.confidence || 0}%</td>
                </tr>
                <tr>
                  <td>Delivery Vector</td>
                  <td>{attackA?.attackDNA?.deliveryVector || attackA?.originalRequest?.sourceType || 'Not specified'}</td>
                  <td>{attackB?.attackDNA?.deliveryVector || attackB?.originalRequest?.sourceType || 'Not specified'}</td>
                </tr>
                <tr>
                  <td>Primary Objective</td>
                  <td>{attackA?.attackerIntent?.primaryGoal || 'Not established'}</td>
                  <td>{attackB?.attackerIntent?.primaryGoal || 'Not established'}</td>
                </tr>
                <tr>
                  <td>Evidence Count</td>
                  <td>{(attackA?.evidence || []).length} items</td>
                  <td>{(attackB?.evidence || []).length} items</td>
                </tr>
                <tr>
                  <td>MITRE Status</td>
                  <td>{attackA?.mitreAttack?.status || 'unmapped'}</td>
                  <td>{attackB?.mitreAttack?.status || 'unmapped'}</td>
                </tr>
              </tbody>
            </table>

            {/* Factual Similarities & Differences */}
            <div className="compare-insights-grid">
              <div className="insight-box box-shared">
                <strong style={{ display: 'block', marginBottom: '0.4rem', color: '#065F46' }}>
                  ✓ Shared Behavioral Attributes
                </strong>
                <ul style={{ margin: 0, paddingLeft: '1.2rem', fontSize: '0.82rem', color: '#047857' }}>
                  {attackA?.threatAssessment?.verdict === attackB?.threatAssessment?.verdict ? (
                    <li>Both artifacts yielded an identical verdict ({attackA?.threatAssessment?.verdict}).</li>
                  ) : null}
                  {attackA?.attackerIntent?.primaryGoal && attackA?.attackerIntent?.primaryGoal === attackB?.attackerIntent?.primaryGoal ? (
                    <li>Shared attacker intent objective: {attackA.attackerIntent.primaryGoal}.</li>
                  ) : null}
                  {attackA?.originalRequest?.sourceType === attackB?.originalRequest?.sourceType ? (
                    <li>Identical source modality ({attackA?.originalRequest?.sourceType || 'artifact'}).</li>
                  ) : null}
                  <li>Both investigations processed with deterministic forensic pipeline.</li>
                </ul>
              </div>

              <div className="insight-box box-diff">
                <strong style={{ display: 'block', marginBottom: '0.4rem', color: '#1E40AF' }}>
                  • Factual Variations
                </strong>
                <ul style={{ margin: 0, paddingLeft: '1.2rem', fontSize: '0.82rem', color: '#1D4ED8' }}>
                  {attackA?.threatAssessment?.riskScore !== attackB?.threatAssessment?.riskScore ? (
                    <li>Risk scores diverge: {attackA?.threatAssessment?.riskScore ?? 'N/A'} vs {attackB?.threatAssessment?.riskScore ?? 'N/A'}.</li>
                  ) : null}
                  {attackA?.threatAssessment?.verdict !== attackB?.threatAssessment?.verdict ? (
                    <li>Different threat verdicts: {attackA?.threatAssessment?.verdict} vs {attackB?.threatAssessment?.verdict}.</li>
                  ) : null}
                  <li>Evidence count comparison: {(attackA?.evidence || []).length} vs {(attackB?.evidence || []).length} items.</li>
                </ul>
              </div>
            </div>

            <div style={{ display: 'flex', justifyContent: 'flex-end', marginTop: '1rem' }}>
              <button 
                className="btn-primary-large" 
                onClick={() => setShowCompareModal(false)}
                type="button"
              >
                [ BACK TO INVESTIGATION ]
              </button>
            </div>
          </div>
        </div>
      )}

    </div>
  );
}
