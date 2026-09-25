import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { apiService } from '../services/api';
import type { AnalysisRequest, AnalysisResponse } from '../types';

export default function Home() {
  const navigate = useNavigate();
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [inputType, setInputType] = useState<'url' | 'text' | 'image'>('url');
  const [inputValue, setInputValue] = useState('');

  const handleAnalyze = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!inputValue) return;

    setIsAnalyzing(true);
    setError(null);

    const req: AnalysisRequest = {
      type: inputType,
      content: inputValue
    };

    try {
      const result: AnalysisResponse = await apiService.submitAnalysis(req);
      navigate('/dashboard', { state: { analysisResult: result } });
    } catch (err: any) {
      setError(err.message || 'An error occurred during analysis.');
      setIsAnalyzing(false);
    }
  };

  return (
    <div className="home-wrapper">
      
      {/* ─── 01 HERO ──────────────────────────────────────────────────────── */}
      <section className="section section-light" style={{ minHeight: '90vh', display: 'flex', flexDirection: 'column', justifyContent: 'center' }}>
        <div className="container">
          <div style={{ display: 'grid', gridTemplateColumns: '1.2fr 1fr', gap: '4rem', alignItems: 'center' }}>
            <div className="hero-content" style={{ opacity: 0 }} ref={el => { if (el) el.classList.add('animate-fade-up'); }}>
              <p className="mono-label" style={{ marginBottom: '1.5rem' }}>DIGITAL THREAT FORENSICS / 01</p>
              <h1 className="display-title" style={{ marginBottom: '1.5rem' }}>
                DON'T JUST<br/>
                DETECT THE<br/>
                PHISHING.
              </h1>
              <div style={{ width: '80px', height: '4px', backgroundColor: 'var(--text-primary)', marginBottom: '1.5rem' }}></div>
              <h1 className="display-title" style={{ marginBottom: '2rem', color: 'var(--blue-primary)' }}>
                RECONSTRUCT<br/>
                THE ATTACK.
              </h1>
              <p className="editorial-body" style={{ marginBottom: '3rem' }}>
                PhishForensics AI analyzes suspicious digital content,
                extracts forensic evidence, identifies attacker intent,
                builds an Attack DNA fingerprint, reconstructs the likely
                attack chain, and turns the investigation into an
                understandable security lesson.
              </p>
              
              <form onSubmit={handleAnalyze} style={{ display: 'flex', flexDirection: 'column', gap: '1rem', maxWidth: '500px', backgroundColor: 'var(--bg-white)', padding: '2rem', border: '1px solid var(--border-light)', borderRadius: 'var(--r-md)' }}>
                <p className="mono-label" style={{ color: 'var(--text-primary)' }}>START AN INVESTIGATION</p>
                <div style={{ display: 'flex', gap: '1rem', marginBottom: '0.5rem' }}>
                  {['url', 'text', 'image'].map((type) => (
                    <button 
                      key={type}
                      type="button" 
                      onClick={() => setInputType(type as any)}
                      style={{ 
                        padding: '0.5rem 1rem', 
                        border: `1px solid ${inputType === type ? 'var(--text-primary)' : 'var(--border-light)'}`,
                        backgroundColor: inputType === type ? 'var(--text-primary)' : 'transparent',
                        color: inputType === type ? 'var(--bg-pure-white)' : 'var(--text-secondary)',
                        fontFamily: 'var(--font-mono)',
                        fontSize: '0.75rem',
                        borderRadius: 'var(--r-sm)'
                      }}
                    >
                      {type.replace('_', ' ').toUpperCase()}
                    </button>
                  ))}
                </div>
                <textarea 
                  className="input-field" 
                  placeholder={`Enter suspicious ${inputType.replace('_', ' ')} here...`}
                  value={inputValue}
                  onChange={(e) => setInputValue(e.target.value)}
                  style={{ minHeight: '100px' }}
                />
                {error && <p style={{ color: 'var(--danger)', fontSize: '0.875rem' }}>{error}</p>}
                <button type="submit" className="btn-primary" disabled={isAnalyzing}>
                  {isAnalyzing ? 'ANALYZING...' : 'ANALYZE THREAT →'}
                </button>
              </form>
            </div>
            
            <div className="hero-visual" style={{ opacity: 0 }} ref={el => { if (el) el.classList.add('animate-fade-up', 'animate-delay-2'); }}>
              <div style={{ backgroundColor: 'var(--bg-pure-white)', border: '1px solid var(--border-strong)', padding: '2.5rem', borderRadius: 'var(--r-md)', boxShadow: '0 20px 40px rgba(0,0,0,0.05)' }}>
                <p className="mono-label" style={{ marginBottom: '2rem', borderBottom: '1px solid var(--border-light)', paddingBottom: '1rem' }}>FORENSIC ANALYSIS PREVIEW</p>
                
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '2rem', marginBottom: '2rem' }}>
                  <div>
                    <p className="mono-label" style={{ marginBottom: '0.5rem' }}>THREAT LEVEL</p>
                    <p style={{ fontSize: '2rem', fontWeight: 800, color: 'var(--danger)', lineHeight: 1 }}>HIGH</p>
                  </div>
                  <div>
                    <p className="mono-label" style={{ marginBottom: '0.5rem' }}>ATTACK TYPE</p>
                    <p style={{ fontSize: '1.25rem', fontWeight: 700, lineHeight: 1.2 }}>CREDENTIAL THEFT</p>
                  </div>
                  <div>
                    <p className="mono-label" style={{ marginBottom: '0.5rem' }}>SIGNALS</p>
                    <p style={{ fontSize: '2rem', fontWeight: 800, lineHeight: 1 }}>17</p>
                  </div>
                  <div>
                    <p className="mono-label" style={{ marginBottom: '0.5rem' }}>CONFIDENCE</p>
                    <p style={{ fontSize: '2rem', fontWeight: 800, lineHeight: 1, color: 'var(--blue-bright)' }}>94%</p>
                  </div>
                </div>
                
                <div style={{ borderTop: '1px solid var(--border-light)', paddingTop: '1.5rem' }}>
                  <p className="mono-label" style={{ marginBottom: '1rem' }}>ATTACK DNA FINGERPRINT</p>
                  {['Impersonation', 'Urgency', 'Credential Request'].map((trait, idx) => (
                    <div key={idx} style={{ marginBottom: '0.75rem' }}>
                      <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '0.25rem' }}>
                        <span className="mono-label" style={{ fontSize: '0.65rem' }}>{trait.toUpperCase()}</span>
                        <span className="mono-label" style={{ fontSize: '0.65rem' }}>HIGH</span>
                      </div>
                      <div style={{ width: '100%', height: '4px', backgroundColor: 'var(--bg-light)' }}>
                        <div style={{ width: `${80 - idx * 10}%`, height: '100%', backgroundColor: 'var(--danger)' }}></div>
                      </div>
                    </div>
                  ))}
                </div>
                <p className="mono-label" style={{ marginTop: '2rem', textAlign: 'center', fontSize: '0.65rem' }}>* Illustrative demo values only</p>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* ─── HERO TRUST STRIP ──────────────────────────────────────────────── */}
      <section className="section-light" style={{ borderTop: '1px solid var(--border-light)', borderBottom: '1px solid var(--border-light)', padding: '2rem 0' }}>
        <div className="container">
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '2rem' }}>
            {['AI THREAT ANALYSIS', 'ATTACK DNA', 'EMAIL FORENSICS', 'ATTACK RECONSTRUCTION', 'SAFE SIMULATION', 'SECURITY EDUCATION'].map((item, idx) => (
              <React.Fragment key={idx}>
                <span className="mono-label" style={{ color: 'var(--text-primary)' }}>{item}</span>
                {idx < 5 && <span style={{ color: 'var(--border-strong)' }}>|</span>}
              </React.Fragment>
            ))}
          </div>
        </div>
      </section>

      {/* ─── 01 / PROJECT INTRODUCTION ─────────────────────────────────────── */}
      <section className="section section-white">
        <div className="container">
          <p className="mono-label" style={{ marginBottom: '2rem' }}>01 / WHY PHISHFORENSICS?</p>
          <div className="grid-2">
            <div>
              <h2 className="section-title" style={{ maxWidth: '15ch' }}>
                PHISHING IS NO LONGER JUST A SUSPICIOUS LINK.
              </h2>
            </div>
            <div>
              <p className="editorial-body" style={{ marginBottom: '2rem' }}>
                Modern phishing attacks combine social engineering,
                impersonation, urgency, malicious infrastructure,
                credential harvesting, and psychological manipulation.
              </p>
              <p className="editorial-body" style={{ marginBottom: '3rem' }}>
                A simple "safe / malicious" verdict does not tell the
                whole story. PhishForensics AI is designed to investigate the attack
                behind the message.
              </p>
              
              <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
                {['DETECT', 'UNDERSTAND', 'RECONSTRUCT', 'EDUCATE'].map((word, idx) => (
                  <h3 key={idx} style={{ fontSize: 'clamp(2rem, 4vw, 3rem)', color: 'var(--text-primary)', borderBottom: '1px solid var(--border-light)', paddingBottom: '0.5rem', opacity: 0, animationDelay: `${idx * 100}ms` }} ref={el => { if (el) el.classList.add('animate-fade-up'); }}>
                    {word}
                  </h3>
                ))}
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* ─── 02 / THE DIFFERENCE ────────────────────────────────────────────── */}
      <section className="section section-light">
        <div className="container">
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1px 1fr', gap: '4rem', alignItems: 'start' }}>
            <div style={{ paddingRight: '2rem' }}>
              <p className="mono-label" style={{ marginBottom: '2rem' }}>TRADITIONAL DETECTION</p>
              <h3 style={{ fontSize: '2.5rem', marginBottom: '1.5rem', fontWeight: 700 }}>"IS THIS PHISHING?"</h3>
              <p className="editorial-body">
                Traditional detection can identify suspicious indicators
                and provide a binary verdict. It stops at telling you whether something is safe or malicious.
              </p>
            </div>
            <div className="divider" style={{ height: '100%' }}></div>
            <div style={{ paddingLeft: '2rem' }}>
              <p className="mono-label" style={{ marginBottom: '2rem' }}>PHISHFORENSICS AI</p>
              <h3 style={{ fontSize: '2.5rem', marginBottom: '1.5rem', fontWeight: 700, color: 'var(--blue-primary)' }}>"HOW DID THIS ATTACK WORK?"</h3>
              <p className="editorial-body" style={{ marginBottom: '1.5rem' }}>
                PhishForensics goes beyond detection by examining:
              </p>
              <ul style={{ listStyle: 'none', display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
                {['attacker intent', 'social engineering', 'evidence', 'behavioral signals', 'Attack DNA', 'attack sequence', 'likely consequences', 'user education'].map((item, idx) => (
                  <li key={idx} style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
                    <div style={{ width: '4px', height: '4px', backgroundColor: 'var(--text-primary)', borderRadius: '50%' }}></div>
                    <span style={{ fontSize: '1.125rem', color: 'var(--text-secondary)' }}>{item}</span>
                  </li>
                ))}
              </ul>
            </div>
          </div>
        </div>
      </section>

      {/* ─── 03 / THE FORENSIC PIPELINE ────────────────────────────────────── */}
      <section className="section section-white">
        <div className="container">
          <p className="mono-label" style={{ marginBottom: '2rem' }}>02 / THE FORENSIC PIPELINE</p>
          <h2 className="section-title" style={{ maxWidth: '20ch', marginBottom: '5rem' }}>
            FROM A SUSPICIOUS MESSAGE TO AN ATTACK STORY.
          </h2>
          
          <div style={{ display: 'flex', justifyContent: 'space-between', position: 'relative', flexWrap: 'wrap', gap: '2rem' }}>
            <div style={{ position: 'absolute', top: '24px', left: 0, right: 0, height: '1px', backgroundColor: 'var(--border-light)', zIndex: 0, display: 'none' }} className="desktop-line"></div>
            
            {[
              { num: '01', title: 'INPUT', desc: 'Suspicious email, URL, message, or artifact.' },
              { num: '02', title: 'ANALYSIS', desc: 'AI extracts indicators and behavioral signals.' },
              { num: '03', title: 'ATTACK DNA', desc: 'Signals become a structured attacker fingerprint.' },
              { num: '04', title: 'RECONSTRUCTION', desc: 'The likely attack sequence is reconstructed.' },
              { num: '05', title: 'EDUCATION', desc: 'The user learns what happened and what to look for next.' }
            ].map((step, idx) => (
              <div key={idx} style={{ flex: '1 1 200px', position: 'relative', zIndex: 1, backgroundColor: 'var(--bg-pure-white)', paddingRight: '1rem' }}>
                <p style={{ fontSize: '3rem', fontWeight: 800, color: 'var(--border-strong)', lineHeight: 1, marginBottom: '1rem' }}>{step.num}</p>
                <h4 style={{ fontSize: '1.25rem', marginBottom: '1rem' }}>{step.title}</h4>
                <p style={{ color: 'var(--text-secondary)', fontSize: '0.9rem', lineHeight: 1.5 }}>{step.desc}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* ─── 04 / ATTACK DNA ──────────────────────────────────────────────── */}
      <section className="section section-navy">
        <div className="container">
          <div className="grid-2" style={{ alignItems: 'center' }}>
            <div>
              <p className="mono-label" style={{ marginBottom: '2rem' }}>03 / ATTACK DNA</p>
              <h2 className="section-title">
                EVERY PHISH<br/>
                LEAVES A<br/>
                FINGERPRINT.
              </h2>
              <p className="editorial-body">
                Attack DNA turns individual phishing indicators into a
                structured behavioral fingerprint. By measuring social engineering 
                tactics, we reveal the human vulnerabilities being targeted.
              </p>
            </div>
            
            <div style={{ padding: '3rem', border: '1px solid rgba(255,255,255,0.1)', backgroundColor: 'rgba(255,255,255,0.03)' }}>
              {[
                { label: 'IMPERSONATION', val: 85 },
                { label: 'URGENCY', val: 92 },
                { label: 'AUTHORITY', val: 40 },
                { label: 'FEAR', val: 75 },
                { label: 'CREDENTIAL HARVESTING', val: 98 },
                { label: 'SOCIAL ENGINEERING', val: 88 }
              ].map((dna, idx) => (
                <div key={idx} style={{ marginBottom: '1.5rem' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '0.5rem' }}>
                    <span className="mono-label" style={{ color: 'rgba(255,255,255,0.7)' }}>{dna.label}</span>
                    <span className="mono-label" style={{ color: 'var(--cyan-accent)' }}>{dna.val}%</span>
                  </div>
                  <div style={{ width: '100%', height: '2px', backgroundColor: 'rgba(255,255,255,0.1)' }}>
                    <div style={{ width: `${dna.val}%`, height: '100%', backgroundColor: 'var(--cyan-accent)' }}></div>
                  </div>
                </div>
              ))}
              <p className="mono-label" style={{ marginTop: '2rem', textAlign: 'center', fontSize: '0.65rem' }}>* Illustrative demo values only</p>
            </div>
          </div>
        </div>
      </section>

      {/* ─── 05 / ATTACK RECONSTRUCTION ───────────────────────────────────── */}
      <section className="section section-white">
        <div className="container">
          <p className="mono-label" style={{ marginBottom: '2rem' }}>04 / ATTACK RECONSTRUCTION</p>
          <h2 className="section-title" style={{ marginBottom: '4rem' }}>
            DON'T STOP AT<br/>
            THE VERDICT.<br/>
            <span style={{ color: 'var(--blue-primary)' }}>RECONSTRUCT THE SEQUENCE.</span>
          </h2>
          
          <div style={{ maxWidth: '800px', position: 'relative', paddingLeft: '3rem' }}>
            <div style={{ position: 'absolute', left: '11px', top: 0, bottom: 0, width: '1px', backgroundColor: 'var(--border-strong)' }}></div>
            
            {[
              { num: '01', title: 'BUILD TRUST', desc: 'Attacker sends email appearing to be from IT Support.' },
              { num: '02', title: 'CREATE URGENCY', desc: 'Message claims account will be suspended in 24 hours.' },
              { num: '03', title: 'DRIVE ACTION', desc: 'Victim clicks link to "Verify Account".' },
              { num: '04', title: 'REQUEST INFORMATION', desc: 'Fake Microsoft 365 login page asks for credentials.' },
              { num: '05', title: 'POTENTIAL COMPROMISE', desc: 'Attacker harvests credentials and redirects victim.' }
            ].map((stage, idx) => (
              <div key={idx} style={{ position: 'relative', marginBottom: '3rem' }}>
                <div style={{ position: 'absolute', left: '-3.4rem', top: '0.5rem', width: '12px', height: '12px', borderRadius: '50%', border: '2px solid var(--blue-primary)', backgroundColor: 'var(--bg-pure-white)' }}></div>
                <p className="mono-label" style={{ color: 'var(--blue-primary)', marginBottom: '0.5rem' }}>STAGE {stage.num}</p>
                <h3 style={{ fontSize: '1.5rem', marginBottom: '0.5rem' }}>{stage.title}</h3>
                <p className="editorial-body" style={{ fontSize: '1rem' }}>{stage.desc}</p>
              </div>
            ))}
            <p className="mono-label" style={{ fontSize: '0.65rem' }}>* Illustrative marketing timeline</p>
          </div>
        </div>
      </section>

      {/* ─── 06 / EVIDENCE BENTO ──────────────────────────────────────────── */}
      <section className="section section-gray">
        <div className="container">
          <h2 className="section-title" style={{ textAlign: 'center', marginBottom: '4rem' }}>THE EVIDENCE BEHIND THE VERDICT.</h2>
          
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(12, 1fr)', gap: '1.5rem', gridAutoRows: 'minmax(150px, auto)' }}>
            
            <div style={{ gridColumn: 'span 8', backgroundColor: 'var(--bg-pure-white)', padding: '2rem', border: '1px solid var(--border-light)' }}>
              <p className="mono-label" style={{ marginBottom: '1rem' }}>EMAIL HEADERS</p>
              <h3 style={{ fontSize: '1.5rem', marginBottom: '1rem' }}>Deep Header Analysis</h3>
              <p style={{ color: 'var(--text-secondary)' }}>Identifying spoofing through Return-Path mismatches, suspicious X-Mailer fields, and unusual relay chains.</p>
            </div>
            
            <div style={{ gridColumn: 'span 4', backgroundColor: 'var(--bg-pure-white)', padding: '2rem', border: '1px solid var(--border-light)', display: 'flex', flexDirection: 'column', justifyContent: 'center' }}>
              <p className="mono-label" style={{ marginBottom: '1rem' }}>SPF / DKIM / DMARC</p>
              <p style={{ fontSize: '2rem', fontWeight: 800, color: 'var(--danger)' }}>FAIL</p>
            </div>
            
            <div style={{ gridColumn: 'span 4', backgroundColor: 'var(--bg-pure-white)', padding: '2rem', border: '1px solid var(--border-light)' }}>
              <p className="mono-label" style={{ marginBottom: '1rem' }}>LOOKALIKE DOMAINS</p>
              <p style={{ fontFamily: 'var(--font-mono)', fontSize: '0.9rem', color: 'var(--text-primary)', wordBreak: 'break-all' }}>
                rnicrosoft.com<br/>
                <span style={{ color: 'var(--text-muted)' }}>instead of microsoft.com</span>
              </p>
            </div>
            
            <div style={{ gridColumn: 'span 8', backgroundColor: 'var(--bg-pure-white)', padding: '2rem', border: '1px solid var(--border-light)' }}>
              <p className="mono-label" style={{ marginBottom: '1rem' }}>URL & ATTACHMENT ANALYSIS</p>
              <h3 style={{ fontSize: '1.5rem', marginBottom: '1rem' }}>Payload Extraction</h3>
              <p style={{ color: 'var(--text-secondary)' }}>Safe extraction of obfuscated URLs, shortened links, and suspicious file hashes without execution.</p>
            </div>
            
          </div>
        </div>
      </section>

      {/* ─── 07 / CAPABILITIES ────────────────────────────────────────────── */}
      <section className="section section-white">
        <div className="container">
          <h2 className="section-title" style={{ textAlign: 'center', marginBottom: '4rem' }}>
            ONE INVESTIGATION.<br/>
            A COMPLETE FORENSIC STORY.
          </h2>
          
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))', gap: '3rem 2rem' }}>
            {[
              { num: '01', title: 'THREAT VERDICT', desc: 'High-confidence binary classification of the threat level.' },
              { num: '02', title: 'EVIDENCE', desc: 'Transparent extraction of the technical indicators of compromise.' },
              { num: '03', title: 'ATTACK INTENT', desc: 'Determining what the attacker is ultimately trying to achieve.' },
              { num: '04', title: 'ATTACK DNA', desc: 'A dimensional analysis of the psychological manipulation.' },
              { num: '05', title: 'ATTACK RECONSTRUCTION', desc: 'A step-by-step timeline of the likely attack chain.' },
              { num: '06', title: 'SECURITY RECOMMENDATIONS', desc: 'Actionable steps to remediate and prevent similar attacks.' }
            ].map((cap, idx) => (
              <div key={idx}>
                <div style={{ display: 'flex', alignItems: 'baseline', gap: '1rem', borderBottom: '1px solid var(--border-light)', paddingBottom: '1rem', marginBottom: '1rem' }}>
                  <span className="mono-label" style={{ color: 'var(--text-primary)' }}>{cap.num}</span>
                  <h4 style={{ fontSize: '1.125rem', fontWeight: 700 }}>{cap.title}</h4>
                </div>
                <p style={{ color: 'var(--text-secondary)', fontSize: '0.95rem', lineHeight: 1.6 }}>{cap.desc}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* ─── 08 / SAFE SIMULATION ─────────────────────────────────────────── */}
      <section className="section section-soft-blue">
        <div className="container">
          <div className="grid-2">
            <div>
              <h2 className="section-title">
                SEE WHERE THE<br/>
                ATTACK COULD LEAD.
              </h2>
              <p className="editorial-body">
                PhishForensics can safely represent a potential attack
                consequence path without executing malicious activity. We map the attacker's expected outcome to show the true risk.
              </p>
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem', borderLeft: '1px solid var(--border-strong)', paddingLeft: '2rem' }}>
              <p className="mono-label" style={{ color: 'var(--blue-primary)' }}>SAFE SIMULATION PATH</p>
              <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}><span className="mono-label">MESSAGE</span> <span style={{ color: 'var(--border-strong)' }}>→</span></div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}><span className="mono-label">VICTIM ACTION</span> <span style={{ color: 'var(--border-strong)' }}>→</span></div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}><span className="mono-label">CREDENTIAL REQUEST</span> <span style={{ color: 'var(--border-strong)' }}>→</span></div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}><span className="mono-label" style={{ color: 'var(--warning)' }}>ACCOUNT RISK</span> <span style={{ color: 'var(--border-strong)' }}>→</span></div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}><span className="mono-label" style={{ color: 'var(--danger)' }}>DATA EXPOSURE</span></div>
            </div>
          </div>
        </div>
      </section>

      {/* ─── 09 / EDUCATION ───────────────────────────────────────────────── */}
      <section className="section section-white">
        <div className="container">
          <p className="mono-label" style={{ marginBottom: '2rem' }}>05 / TURN ANALYSIS INTO A LESSON.</p>
          <h2 className="section-title" style={{ marginBottom: '4rem' }}>
            EVERY INVESTIGATION<br/>
            SHOULD TEACH SOMETHING.
          </h2>
          
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '2rem' }}>
            {[
              'WHY IT LOOKED REAL',
              'WHAT SIGNALS WERE MISSED',
              'WHAT THE ATTACKER WANTED',
              'WHAT TO CHECK NEXT TIME'
            ].map((statement, idx) => (
              <div key={idx} style={{ padding: '3rem 2rem', border: '1px solid var(--border-light)', backgroundColor: 'var(--bg-warm-white)' }}>
                <h3 style={{ fontSize: '1.75rem', fontWeight: 700, color: 'var(--text-primary)' }}>{statement}</h3>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* ─── 10 / ARCHITECTURE ────────────────────────────────────────────── */}
      <section className="section section-light">
        <div className="container">
          <h2 className="section-title" style={{ textAlign: 'center', marginBottom: '4rem' }}>UNDER THE INTERFACE.</h2>
          
          <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '1.5rem', fontFamily: 'var(--font-mono)', fontSize: '0.875rem', letterSpacing: '0.05em' }}>
            <div style={{ padding: '1rem 2rem', border: '1px solid var(--border-strong)', backgroundColor: 'var(--bg-pure-white)' }}>USER INPUT</div>
            <div style={{ height: '20px', width: '1px', backgroundColor: 'var(--border-strong)' }}></div>
            <div style={{ padding: '1rem 2rem', border: '1px solid var(--border-strong)', backgroundColor: 'var(--bg-pure-white)' }}>FRONTEND (REACT)</div>
            <div style={{ height: '20px', width: '1px', backgroundColor: 'var(--border-strong)' }}></div>
            <div style={{ padding: '1rem 2rem', border: '1px solid var(--border-strong)', backgroundColor: 'var(--bg-pure-white)' }}>BACKEND API</div>
            <div style={{ height: '20px', width: '1px', backgroundColor: 'var(--border-strong)' }}></div>
            <div style={{ padding: '1rem 2rem', border: '1px solid var(--blue-primary)', backgroundColor: 'rgba(37,99,235,0.05)', color: 'var(--blue-primary)', fontWeight: 600 }}>AI ANALYSIS ENGINE</div>
            <div style={{ height: '20px', width: '1px', backgroundColor: 'var(--border-strong)' }}></div>
            <div style={{ display: 'flex', gap: '1rem', flexWrap: 'wrap', justifyContent: 'center' }}>
              <div style={{ padding: '0.75rem 1.5rem', border: '1px solid var(--border-light)', backgroundColor: 'var(--bg-pure-white)' }}>THREAT RESULT</div>
              <div style={{ padding: '0.75rem 1.5rem', border: '1px solid var(--border-light)', backgroundColor: 'var(--bg-pure-white)' }}>ATTACK DNA</div>
              <div style={{ padding: '0.75rem 1.5rem', border: '1px solid var(--border-light)', backgroundColor: 'var(--bg-pure-white)' }}>RECONSTRUCTION</div>
              <div style={{ padding: '0.75rem 1.5rem', border: '1px solid var(--border-light)', backgroundColor: 'var(--bg-pure-white)' }}>EDUCATION</div>
            </div>
          </div>
        </div>
      </section>

      {/* ─── 11 / UI PREVIEW ──────────────────────────────────────────────── */}
      <section className="section section-white">
        <div className="container">
          <div style={{ textAlign: 'center', marginBottom: '4rem' }}>
            <h2 className="section-title">FROM HOMEPAGE<br/>TO INVESTIGATION.</h2>
          </div>
          
          <div style={{ maxWidth: '900px', margin: '0 auto', border: '1px solid var(--border-light)', borderRadius: 'var(--r-md)', overflow: 'hidden', boxShadow: '0 25px 50px -12px rgba(0,0,0,0.1)' }}>
            <div style={{ backgroundColor: 'var(--bg-light)', padding: '1rem 2rem', borderBottom: '1px solid var(--border-light)', display: 'flex', alignItems: 'center', gap: '1rem' }}>
              <div style={{ display: 'flex', gap: '6px' }}>
                <div style={{ width: '10px', height: '10px', borderRadius: '50%', backgroundColor: 'var(--border-strong)' }}></div>
                <div style={{ width: '10px', height: '10px', borderRadius: '50%', backgroundColor: 'var(--border-strong)' }}></div>
                <div style={{ width: '10px', height: '10px', borderRadius: '50%', backgroundColor: 'var(--border-strong)' }}></div>
              </div>
              <p className="mono-label" style={{ fontSize: '0.65rem' }}>DASHBOARD PREVIEW</p>
            </div>
            
            <div style={{ padding: '3rem', backgroundColor: 'var(--bg-pure-white)' }}>
              <p className="mono-label" style={{ marginBottom: '1rem' }}>INVESTIGATION / PH-8924</p>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '3rem', borderBottom: '1px solid var(--border-light)', paddingBottom: '2rem' }}>
                <h3 style={{ fontSize: '2rem', fontWeight: 800 }}>FORENSIC REPORT</h3>
                <div style={{ textAlign: 'right' }}>
                  <p className="mono-label" style={{ marginBottom: '0.5rem' }}>RISK SCORE</p>
                  <p style={{ fontSize: '2.5rem', fontWeight: 800, color: 'var(--danger)', lineHeight: 1 }}>92</p>
                </div>
              </div>
              
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '3rem' }}>
                <div>
                  <p className="mono-label" style={{ marginBottom: '1rem' }}>VERDICT</p>
                  <p style={{ fontSize: '1.25rem', fontWeight: 700, color: 'var(--danger)', marginBottom: '2rem' }}>MALICIOUS</p>
                  
                  <p className="mono-label" style={{ marginBottom: '1rem' }}>ATTACK TYPE</p>
                  <p style={{ fontSize: '1.25rem', fontWeight: 700 }}>CREDENTIAL HARVESTING</p>
                </div>
                <div>
                  <p className="mono-label" style={{ marginBottom: '1rem' }}>EVIDENCE HIGHLIGHTS</p>
                  <ul style={{ listStyle: 'none', display: 'flex', flexDirection: 'column', gap: '0.5rem', fontFamily: 'var(--font-mono)', fontSize: '0.85rem' }}>
                    <li style={{ borderLeft: '2px solid var(--danger)', paddingLeft: '1rem' }}>SPF RECORD FAILURE</li>
                    <li style={{ borderLeft: '2px solid var(--danger)', paddingLeft: '1rem' }}>SPOOFED SENDER DOMAIN</li>
                    <li style={{ borderLeft: '2px solid var(--warning)', paddingLeft: '1rem' }}>OBFUSCATED URL DETECTED</li>
                  </ul>
                </div>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* ─── 12 / FINAL CTA ───────────────────────────────────────────────── */}
      <section className="section section-navy" style={{ textAlign: 'center', padding: '8rem 0' }}>
        <div className="container">
          <h2 className="section-title" style={{ marginBottom: '2rem' }}>
            A SUSPICIOUS MESSAGE<br/>
            IS ONLY THE BEGINNING.
          </h2>
          <p className="mono-label" style={{ marginBottom: '3rem', fontSize: '1rem', letterSpacing: '0.2em' }}>
            INVESTIGATE IT. UNDERSTAND IT. RECONSTRUCT IT.
          </p>
          <button className="btn-primary" onClick={() => window.scrollTo({ top: 0, behavior: 'smooth' })}>
            START INVESTIGATION →
          </button>
        </div>
      </section>

    </div>
  );
}
