import React, { useState, useEffect, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import { apiService } from '../services/api';
import type { AnalysisRequest, AnalysisResponse } from '../types';

function formatFileSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

export default function Home() {
  const navigate = useNavigate();
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Input Mode: 'text' or 'image'
  const [inputMode, setInputMode] = useState<'text' | 'image'>('text');
  const [textSubtype, setTextSubtype] = useState<'email' | 'url' | 'text'>('email');
  const [inputValue, setInputValue] = useState('');
  
  // File upload state
  const [uploadedFile, setUploadedFile] = useState<{
    file: File;
    name: string;
    size: number;
    dataUrl: string;
  } | null>(null);
  const [isDragging, setIsDragging] = useState(false);
  const fileInputRef = useRef<HTMLInputElement | null>(null);

  // Handle smooth scroll when navigating to hash sections
  useEffect(() => {
    const handleHashScroll = () => {
      if (window.location.hash) {
        const id = window.location.hash.replace('#', '');
        const el = document.getElementById(id);
        if (el) {
          setTimeout(() => {
            el.scrollIntoView({ behavior: 'smooth' });
          }, 100);
        }
      }
    };

    handleHashScroll();
    window.addEventListener('hashchange', handleHashScroll);
    return () => window.removeEventListener('hashchange', handleHashScroll);
  }, []);

  const validateAndProcessFile = (file: File) => {
    setError(null);
    const validExtensions = ['.png', '.jpg', '.jpeg', '.webp'];
    const validMimes = ['image/png', 'image/jpeg', 'image/webp'];

    const extension = '.' + file.name.split('.').pop()?.toLowerCase();
    const isValidType = validMimes.includes(file.type.toLowerCase()) || validExtensions.includes(extension);

    if (!isValidType) {
      setError('Unsupported file type. Please upload PNG, JPG, JPEG, or WEBP.');
      return;
    }

    const maxSize = 10 * 1024 * 1024; // 10MB limit
    if (file.size > maxSize) {
      setError('File size exceeds 10MB limit. Please upload a smaller image.');
      return;
    }

    const reader = new FileReader();
    reader.onload = (e) => {
      const dataUrl = e.target?.result as string;
      setUploadedFile({
        file,
        name: file.name,
        size: file.size,
        dataUrl
      });
    };
    reader.onerror = () => {
      setError('Failed to read file. Please select another image.');
    };
    reader.readAsDataURL(file);
  };

  const handleAnalyze = async (e: React.FormEvent) => {
    e.preventDefault();

    if (inputMode === 'text') {
      if (!inputValue.trim()) {
        setError('Please enter text, an email, or a URL to analyze.');
        return;
      }
    } else {
      if (!uploadedFile) {
        setError('Please upload an image artifact before analyzing.');
        return;
      }
    }

    setIsAnalyzing(true);
    setError(null);

    const req: AnalysisRequest = {
      type: inputMode === 'text' ? textSubtype : 'image',
      content: inputMode === 'text' ? inputValue.trim() : uploadedFile!.dataUrl
    };

    try {
      const result: AnalysisResponse = await apiService.submitAnalysis(req);
      navigate('/dashboard', { state: { analysisResult: result } });
    } catch (err: any) {
      setError(err.message || 'An error occurred during analysis.');
      setIsAnalyzing(false);
    }
  };

  const isSubmitDisabled = isAnalyzing || (inputMode === 'text' ? !inputValue.trim() : !uploadedFile);

  return (
    <div className="home-wrapper">
      
      {/* ─── 00 HERO / ANALYZE FORM ────────────────────────────────────────── */}
      <section id="analyze" className="section section-light" style={{ minHeight: '90vh', display: 'flex', flexDirection: 'column', justifyContent: 'center', scrollMarginTop: '80px' }}>
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
              
              <form onSubmit={handleAnalyze} style={{ display: 'flex', flexDirection: 'column', gap: '1rem', maxWidth: '520px', backgroundColor: 'var(--bg-white)', padding: '2rem', border: '1px solid var(--border-light)', borderRadius: 'var(--r-md)' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '0.5rem' }}>
                  <p className="mono-label" style={{ color: 'var(--text-primary)', margin: 0 }}>START AN INVESTIGATION</p>
                  <span style={{ fontFamily: 'var(--font-mono)', fontSize: '0.7rem', color: 'var(--text-muted)' }}>PASSIVE ONLY</span>
                </div>

                {/* Mode Selector: [ TEXT ] vs [ IMAGE / FILE ] */}
                <div className="mode-toggle-group" role="tablist" aria-label="Input Mode Selector">
                  <button
                    type="button"
                    className={`mode-toggle-btn ${inputMode === 'text' ? 'active' : ''}`}
                    onClick={() => { setInputMode('text'); setError(null); }}
                    role="tab"
                    aria-selected={inputMode === 'text'}
                  >
                    📝 TEXT
                  </button>
                  <button
                    type="button"
                    className={`mode-toggle-btn ${inputMode === 'image' ? 'active' : ''}`}
                    onClick={() => { setInputMode('image'); setError(null); }}
                    role="tab"
                    aria-selected={inputMode === 'image'}
                  >
                    🖼 IMAGE / FILE
                  </button>
                </div>

                {/* TEXT MODE */}
                {inputMode === 'text' && (
                  <div>
                    <div className="subtypes-group">
                      {(['email', 'url', 'text'] as const).map((sub) => (
                        <button 
                          key={sub}
                          type="button" 
                          className={`subtype-btn ${textSubtype === sub ? 'active' : ''}`}
                          onClick={() => setTextSubtype(sub)}
                        >
                          {sub.toUpperCase()}
                        </button>
                      ))}
                    </div>

                    <textarea 
                      className="input-field" 
                      placeholder={`Enter suspicious ${textSubtype} here...`}
                      value={inputValue}
                      onChange={(e) => setInputValue(e.target.value)}
                      style={{ minHeight: '120px' }}
                    />
                  </div>
                )}

                {/* IMAGE / FILE MODE */}
                {inputMode === 'image' && (
                  <div>
                    {!uploadedFile ? (
                      <div 
                        className={`upload-dropzone ${isDragging ? 'drag-active' : ''}`}
                        onDragOver={(e) => {
                          e.preventDefault();
                          setIsDragging(true);
                        }}
                        onDragLeave={() => setIsDragging(false)}
                        onDrop={(e) => {
                          e.preventDefault();
                          setIsDragging(false);
                          const files = e.dataTransfer.files;
                          if (files && files.length > 0) {
                            validateAndProcessFile(files[0]);
                          }
                        }}
                      >
                        <div className="upload-icon-circle">⤓</div>
                        <div>
                          <p className="upload-label-title">UPLOAD EVIDENCE</p>
                          <p className="upload-label-sub" style={{ marginTop: '0.25rem' }}>
                            {isDragging ? 'Drop file to upload' : 'Drag & drop an image here'}
                          </p>
                        </div>
                        
                        <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>or</span>

                        <button
                          type="button"
                          className="btn-add-file"
                          onClick={() => fileInputRef.current?.click()}
                          aria-label="Add file or image for forensic analysis"
                        >
                          + ADD FILE
                        </button>

                        <div className="upload-format-chips">
                          PNG • JPG • JPEG • WEBP (Max 10MB)
                        </div>
                      </div>
                    ) : (
                      <div className="upload-preview-container">
                        <div className="preview-media-box">
                          <img 
                            src={uploadedFile.dataUrl} 
                            alt={uploadedFile.name} 
                            className="preview-thumbnail" 
                          />
                        </div>

                        <div className="preview-info-row">
                          <div className="preview-meta">
                            <span className="preview-filename" title={uploadedFile.name}>
                              {uploadedFile.name}
                            </span>
                            <span className="preview-filesize">
                              {formatFileSize(uploadedFile.size)}
                            </span>
                          </div>

                          <div className="preview-actions-group">
                            <button
                              type="button"
                              className="btn-preview-action btn-replace"
                              onClick={() => fileInputRef.current?.click()}
                              aria-label="Replace selected file"
                            >
                              [ REPLACE ]
                            </button>
                            <button
                              type="button"
                              className="btn-preview-action btn-remove"
                              onClick={() => {
                                setUploadedFile(null);
                                if (fileInputRef.current) fileInputRef.current.value = '';
                              }}
                              aria-label="Remove selected file"
                            >
                              [ REMOVE ]
                            </button>
                          </div>
                        </div>
                      </div>
                    )}

                    {/* Native Hidden File Input */}
                    <input
                      ref={fileInputRef}
                      type="file"
                      accept=".png,.jpg,.jpeg,.webp,image/png,image/jpeg,image/webp"
                      style={{ display: 'none' }}
                      onChange={(e) => {
                        const files = e.target.files;
                        if (files && files.length > 0) {
                          validateAndProcessFile(files[0]);
                        }
                      }}
                    />
                  </div>
                )}

                {error && (
                  <div style={{ padding: '0.6rem 0.85rem', background: '#FFF1F2', border: '1px solid #FECDD3', borderRadius: 'var(--r-sm)', color: 'var(--danger)', fontSize: '0.82rem', fontFamily: 'var(--font-mono)' }}>
                    ⚠ {error}
                  </div>
                )}

                <button 
                  type="submit" 
                  className="btn-primary" 
                  disabled={isSubmitDisabled}
                >
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

      {/* ─── 01 / WHY US? ─────────────────────────────────────────────────── */}
      <section id="why-us" className="section section-white" style={{ scrollMarginTop: '80px' }}>
        <div className="container">
          <p className="mono-label" style={{ marginBottom: '1.5rem', color: 'var(--blue-primary)' }}>01 / WHY US?</p>
          <div className="grid-2">
            <div>
              <h2 className="section-title" style={{ maxWidth: '16ch' }}>
                BEYOND DETECTION.<br/>
                TRANSPARENT FORENSIC<br/>
                INTELLIGENCE.
              </h2>
              <p className="editorial-body" style={{ marginTop: '1.5rem' }}>
                Legacy security gateways provide opaque binary verdicts. PhishForensics AI was built on the principle that modern defense requires knowing <em>how</em> an attack works, <em>what</em> it targeted, and <em>why</em> the verdict was reached.
              </p>
            </div>
            <div>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr', gap: '1rem' }}>
                {[
                  {
                    title: 'Goes Beyond Simple Phishing Detection',
                    desc: 'Evaluates attacker intent, delivery vectors, and potential victim impact rather than returning a plain yes/no.'
                  },
                  {
                    title: 'Evidence-Driven Investigation',
                    desc: 'Every verdict is directly supported by isolated technical, psychological, and contextual observables.'
                  },
                  {
                    title: 'Attack DNA Behavioral Fingerprinting',
                    desc: 'Measures behavioral traits, urgency triggers, and social engineering patterns as a structured product-specific fingerprint.'
                  },
                  {
                    title: 'Attack Flow Reconstruction',
                    desc: 'Reconstructs the chronological progression of the adversary across discrete stages from trust-building to compromise.'
                  },
                  {
                    title: 'Safe Simulation Walkthrough',
                    desc: 'Demonstrates hypothetical attack consequences safely in a sandbox without executing real code or opening live URLs.'
                  },
                  {
                    title: 'Deterministic MITRE ATT&CK Mapping',
                    desc: 'Maps verified techniques strictly from extracted evidence, never guessing or fabricating external taxonomies.'
                  },
                  {
                    title: 'Explainable Investigation Results',
                    desc: 'Provides analyst-ready analytical justifications and genuine confidence metrics for full forensic auditability.'
                  }
                ].map((item, idx) => (
                  <div 
                    key={idx} 
                    className="hover-magnify-card" 
                    style={{ 
                      padding: '1.15rem 1.25rem', 
                      backgroundColor: 'var(--bg-primary)', 
                      border: '1px solid var(--border-light)', 
                      borderRadius: 'var(--r-sm)' 
                    }}
                  >
                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem', marginBottom: '0.35rem' }}>
                      <span style={{ color: 'var(--blue-primary)', fontWeight: 800 }}>✓</span>
                      <strong style={{ fontSize: '0.92rem', color: 'var(--text-primary)' }}>{item.title}</strong>
                    </div>
                    <p style={{ fontSize: '0.84rem', color: 'var(--text-secondary)', lineHeight: 1.5, margin: 0 }}>
                      {item.desc}
                    </p>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* ─── 02 / HOW IT WORKS ────────────────────────────────────────────── */}
      <section id="how-it-works" className="section section-light" style={{ scrollMarginTop: '80px' }}>
        <div className="container">
          <p className="mono-label" style={{ marginBottom: '1.5rem', color: 'var(--blue-primary)' }}>02 / HOW IT WORKS</p>
          <h2 className="section-title" style={{ maxWidth: '24ch', marginBottom: '4rem' }}>
            FROM A SUSPICIOUS MESSAGE TO AN ATTACK STORY.
          </h2>
          
          <div style={{ display: 'flex', justifyContent: 'space-between', position: 'relative', flexWrap: 'wrap', gap: '1.5rem' }}>
            <div style={{ position: 'absolute', top: '24px', left: 0, right: 0, height: '1px', backgroundColor: 'var(--border-light)', zIndex: 0, display: 'none' }} className="desktop-line"></div>
            
            {[
              { num: '01', title: 'INPUT ARTIFACT', desc: 'Submit suspicious email text, headers, URL, or image artifact for automated intake.' },
              { num: '02', title: 'AI & HEURISTIC ANALYSIS', desc: 'Extracts observable indicators, evaluates psychological pretexts, and scores risk.' },
              { num: '03', title: 'ATTACK DNA GENERATION', desc: 'Synthesizes observable traits into a structured, multi-dimensional behavioral fingerprint.' },
              { num: '04', title: 'ATTACK RECONSTRUCTION', desc: 'Reconstructs the adversary\'s staged mechanics from initial lure to credential collection.' },
              { num: '05', title: 'DEFENSIVE GUIDANCE', desc: 'Actionable countermeasures, MITRE mappings, and safe simulation educate the analyst.' }
            ].map((step, idx) => (
              <div 
                key={idx} 
                className="hover-magnify-card" 
                style={{ 
                  flex: '1 1 200px', 
                  position: 'relative', 
                  zIndex: 1, 
                  backgroundColor: 'var(--bg-pure-white)', 
                  padding: '1.5rem',
                  border: '1px solid var(--border-light)',
                  borderRadius: 'var(--r-sm)'
                }}
              >
                <p style={{ fontSize: '2.5rem', fontWeight: 800, color: 'var(--blue-primary)', lineHeight: 1, marginBottom: '0.85rem' }}>{step.num}</p>
                <h4 style={{ fontSize: '1.1rem', marginBottom: '0.75rem', fontWeight: 700 }}>{step.title}</h4>
                <p style={{ color: 'var(--text-secondary)', fontSize: '0.88rem', lineHeight: 1.55 }}>{step.desc}</p>
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

      {/* ─── 03 / PRODUCTS ────────────────────────────────────────────────── */}
      <section id="products" className="section section-white" style={{ scrollMarginTop: '80px' }}>
        <div className="container">
          <p className="mono-label" style={{ marginBottom: '1.5rem', color: 'var(--blue-primary)' }}>03 / PRODUCTS</p>
          <h2 className="section-title" style={{ maxWidth: '24ch', marginBottom: '1.5rem' }}>
            THE FORENSIC INVESTIGATION SUITE.
          </h2>
          <p className="editorial-body" style={{ marginBottom: '3.5rem' }}>
            Seven purpose-built analytical modules engineered into a single unified threat investigation pipeline.
          </p>
          
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: '1.5rem' }}>
            {[
              { 
                num: '01', 
                title: 'THREAT INVESTIGATION', 
                desc: 'Unified multi-signal classification engine delivering verified threat verdicts, severity classification, numerical risk scores, and analytical justifications.' 
              },
              { 
                num: '02', 
                title: 'ATTACK DNA FINGERPRINT', 
                desc: 'Structured behavioral fingerprint quantifying psychological manipulation tactics, urgency drivers, authority pretexts, and observed attacker complexity.' 
              },
              { 
                num: '03', 
                title: 'ATTACK RECONSTRUCTION', 
                desc: 'Chronological timeline sequencing the attack chain across discrete operational stages, from initial trust-building to credential collection.' 
              },
              { 
                num: '04', 
                title: 'SAFE SIMULATION', 
                desc: 'Sandboxed educational walkthrough demonstrating hypothetical consequences step-by-step without executing dangerous code or opening live links.' 
              },
              { 
                num: '05', 
                title: 'MITRE ATT&CK® MAPPING', 
                desc: 'Deterministic evidence-driven mapping to verified enterprise techniques (e.g., T1566 Spearphishing Link/Attachment) with clickable evidence cross-references.' 
              },
              { 
                num: '06', 
                title: 'FORENSIC EVIDENCE MATRIX', 
                desc: 'Granular isolation of technical, psychological, and contextual evidence signals accompanied by genuine confidence scoring and category filtering.' 
              },
              { 
                num: '07', 
                title: 'IOC EXTRACTION & DEFANGING', 
                desc: 'Automated extraction of observable indicators (URLs, domains, emails, IPs, file hashes) defanged for safe SOC handling and copy-to-clipboard workflows.' 
              }
            ].map((cap, idx) => (
              <div 
                key={idx} 
                className="hover-magnify-card" 
                style={{ 
                  backgroundColor: 'var(--bg-primary)', 
                  padding: '1.75rem', 
                  border: '1px solid var(--border-light)', 
                  borderRadius: 'var(--r-sm)' 
                }}
              >
                <div style={{ display: 'flex', alignItems: 'baseline', gap: '0.75rem', borderBottom: '1px solid var(--border-light)', paddingBottom: '0.85rem', marginBottom: '1rem' }}>
                  <span className="mono-label" style={{ color: 'var(--blue-primary)', fontWeight: 800 }}>{cap.num}</span>
                  <h4 style={{ fontSize: '1.1rem', fontWeight: 700 }}>{cap.title}</h4>
                </div>
                <p style={{ color: 'var(--text-secondary)', fontSize: '0.9rem', lineHeight: 1.6, margin: 0 }}>{cap.desc}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* ─── 04 / SOLUTIONS ───────────────────────────────────────────────── */}
      <section id="solutions" className="section section-light" style={{ scrollMarginTop: '80px' }}>
        <div className="container">
          <p className="mono-label" style={{ marginBottom: '1.5rem', color: 'var(--blue-primary)' }}>04 / SOLUTIONS</p>
          <h2 className="section-title" style={{ maxWidth: '24ch', marginBottom: '1.5rem' }}>
            ENGINEERED FOR MODERN SECURITY WORKFLOWS.
          </h2>
          <p className="editorial-body" style={{ marginBottom: '3.5rem' }}>
            Real-world forensic workflows supported by the PhishForensics AI unified analysis pipeline.
          </p>
          
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '1.75rem' }}>
            {[
              {
                badge: 'INCIDENT RESPONSE',
                title: 'Phishing Investigation',
                desc: 'Rapidly triage suspicious inbound emails, SMS messages, and URLs. Instead of opaque verdicts, analysts receive structured evidence, defanged observables, and verifiable risk assessments.'
              },
              {
                badge: 'SOC OPERATIONS',
                title: 'Security Analysis & IOC Triage',
                desc: 'Instantly isolate indicators of compromise, copy defanged values for threat hunting, and map observed attacker behaviors directly to MITRE ATT&CK enterprise techniques.'
              },
              {
                badge: 'THREAT INTELLIGENCE',
                title: 'Incident Understanding',
                desc: 'Gain deep visibility into deceptive campaigns by reconstructing the multi-stage attacker progression, understanding primary objectives, and modeling potential victim exposure.'
              },
              {
                badge: 'DEFENSIVE TRAINING',
                title: 'Security Awareness & Education',
                desc: 'Transform suspicious messages into safe educational walkthroughs. Interactive simulations illustrate why lures look legitimate and provide concrete guidance on what to check next time.'
              }
            ].map((sol, idx) => (
              <div 
                key={idx} 
                className="hover-magnify-card" 
                style={{ 
                  backgroundColor: 'var(--bg-pure-white)', 
                  padding: '2rem', 
                  border: '1px solid var(--border-light)', 
                  borderRadius: 'var(--r-sm)' 
                }}
              >
                <span className="mono-label" style={{ color: 'var(--blue-primary)', fontSize: '0.68rem', display: 'inline-block', marginBottom: '0.75rem' }}>
                  {sol.badge}
                </span>
                <h3 style={{ fontSize: '1.25rem', fontWeight: 700, marginBottom: '1rem', color: 'var(--text-primary)' }}>
                  {sol.title}
                </h3>
                <p style={{ color: 'var(--text-secondary)', fontSize: '0.9rem', lineHeight: 1.6, margin: 0 }}>
                  {sol.desc}
                </p>
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
