import React from 'react';
import { Outlet, Link, useLocation } from 'react-router-dom';

export default function MainLayout() {
  const location = useLocation();
  const isDashboard = location.pathname.includes('/dashboard');

  return (
    <div className="layout-wrapper" style={{ minHeight: '100vh', display: 'flex', flexDirection: 'column' }}>
      
      {/* ─── STICKY NAVIGATION ────────────────────────────────────────── */}
      <header 
        style={{ 
          position: 'sticky', 
          top: 0, 
          zIndex: 100, 
          backgroundColor: 'var(--bg-warm-white)', 
          borderBottom: '1px solid var(--border-light)',
          padding: '1rem 0'
        }}
      >
        <div className="container" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          
          {/* Logo */}
          <Link to="/" style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontWeight: 800, fontSize: '1.25rem', letterSpacing: '-0.02em' }}>
            <div style={{ width: '20px', height: '20px', backgroundColor: 'var(--text-primary)' }}></div>
            PHISHFORENSICS <span style={{ color: 'var(--blue-primary)' }}>AI</span>
          </Link>

          {/* Nav Links */}
          <nav style={{ display: 'flex', gap: '2rem', alignItems: 'center', display: 'none' }} className="desktop-nav">
            {['Product', 'How It Works', 'Attack DNA', 'Forensics', 'Dashboard'].map((link) => (
              <a href="#" key={link} className="mono-label" style={{ color: 'var(--text-primary)', transition: 'color 0.2s', fontWeight: 500 }}>
                {link.toUpperCase()}
              </a>
            ))}
          </nav>
          
          <nav style={{ display: 'flex', gap: '2rem', alignItems: 'center' }}>
             {['Product', 'How It Works'].map((link) => (
                <a href="#" key={link} className="mono-label" style={{ color: 'var(--text-primary)', transition: 'color 0.2s', fontWeight: 500 }}>
                  {link.toUpperCase()}
                </a>
              ))}
          </nav>

          {/* CTA */}
          <Link 
            to="/" 
            style={{ 
              padding: '0.5rem 1rem', 
              backgroundColor: 'transparent', 
              border: '1px solid var(--text-primary)', 
              color: 'var(--text-primary)', 
              fontFamily: 'var(--font-mono)', 
              fontSize: '0.75rem', 
              fontWeight: 600, 
              borderRadius: 'var(--r-sm)',
              textTransform: 'uppercase'
            }}
          >
            ANALYZE THREAT
          </Link>
        </div>
      </header>

      {/* ─── MAIN CONTENT ─────────────────────────────────────────────── */}
      <main style={{ flex: 1, display: 'flex', flexDirection: 'column' }}>
        <Outlet />
      </main>

      {/* ─── FOOTER ───────────────────────────────────────────────────── */}
      <footer style={{ borderTop: '1px solid var(--border-light)', padding: '4rem 0', backgroundColor: 'var(--bg-white)' }}>
        <div className="container">
          <div style={{ display: 'flex', justifyContent: 'space-between', flexWrap: 'wrap', gap: '2rem' }}>
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontWeight: 800, fontSize: '1rem', letterSpacing: '-0.02em', marginBottom: '1rem' }}>
                <div style={{ width: '16px', height: '16px', backgroundColor: 'var(--text-primary)' }}></div>
                PHISHFORENSICS <span style={{ color: 'var(--blue-primary)' }}>AI</span>
              </div>
              <p className="mono-label">DIGITAL THREAT FORENSICS</p>
            </div>
            
            <div style={{ display: 'flex', gap: '4rem' }}>
              <div>
                <p className="mono-label" style={{ marginBottom: '1rem', color: 'var(--text-primary)' }}>PLATFORM</p>
                <ul style={{ listStyle: 'none', display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
                  <li><a href="#" style={{ color: 'var(--text-secondary)', fontSize: '0.875rem' }}>Analysis Engine</a></li>
                  <li><a href="#" style={{ color: 'var(--text-secondary)', fontSize: '0.875rem' }}>Attack DNA</a></li>
                  <li><a href="#" style={{ color: 'var(--text-secondary)', fontSize: '0.875rem' }}>Reconstruction</a></li>
                </ul>
              </div>
              <div>
                <p className="mono-label" style={{ marginBottom: '1rem', color: 'var(--text-primary)' }}>RESOURCES</p>
                <ul style={{ listStyle: 'none', display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
                  <li><a href="#" style={{ color: 'var(--text-secondary)', fontSize: '0.875rem' }}>Documentation</a></li>
                  <li><a href="#" style={{ color: 'var(--text-secondary)', fontSize: '0.875rem' }}>API Reference</a></li>
                  <li><a href="#" style={{ color: 'var(--text-secondary)', fontSize: '0.875rem' }}>Case Studies</a></li>
                </ul>
              </div>
            </div>
          </div>
          
          <div style={{ borderTop: '1px solid var(--border-light)', marginTop: '4rem', paddingTop: '2rem', display: 'flex', justifyContent: 'space-between' }}>
            <p className="mono-label" style={{ fontSize: '0.65rem' }}>© 2026 PHISHFORENSICS AI. ALL RIGHTS RESERVED.</p>
            <p className="mono-label" style={{ fontSize: '0.65rem' }}>SECURE ANALYSIS ENVIRONMENT</p>
          </div>
        </div>
      </footer>
    </div>
  );
}
