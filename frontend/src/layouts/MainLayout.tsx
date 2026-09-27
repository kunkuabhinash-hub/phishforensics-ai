import { useState, useEffect } from 'react';
import { Outlet, Link, useLocation, useNavigate } from 'react-router-dom';
import ForensicCursor from '../components/ForensicCursor';
import InvestigationHistoryModal from '../components/InvestigationHistoryModal';

export default function MainLayout() {
  const location = useLocation();
  const navigate = useNavigate();
  const [showHistoryModal, setShowHistoryModal] = useState<boolean>(false);

  const [theme, setTheme] = useState<'dark' | 'light'>(() => {
    const saved = localStorage.getItem('theme');
    return (saved === 'light') ? 'light' : 'dark';
  });

  useEffect(() => {
    if (theme === 'light') {
      document.documentElement.setAttribute('data-theme', 'light');
    } else {
      document.documentElement.removeAttribute('data-theme');
    }
    localStorage.setItem('theme', theme);
  }, [theme]);

  const toggleTheme = () => {
    setTheme(prev => prev === 'dark' ? 'light' : 'dark');
  };

  const navItems = [
    { label: 'WHY US?', id: 'why-us' },
    { label: 'HOW IT WORKS', id: 'how-it-works' },
    { label: 'PRODUCTS', id: 'products' },
    { label: 'SOLUTIONS', id: 'solutions' },
  ];

  const handleNavClick = (e: React.MouseEvent<HTMLAnchorElement>, targetId: string) => {
    e.preventDefault();
    if (location.pathname === '/') {
      const el = document.getElementById(targetId);
      if (el) {
        el.scrollIntoView({ behavior: 'smooth' });
      }
    } else {
      navigate(`/#${targetId}`);
    }
  };

  const handleAnalyzeClick = (e: React.MouseEvent<HTMLAnchorElement>) => {
    e.preventDefault();
    if (location.pathname === '/') {
      window.scrollTo({ top: 0, behavior: 'smooth' });
      const textarea = document.querySelector('textarea.input-field') as HTMLTextAreaElement | null;
      if (textarea) textarea.focus();
    } else {
      navigate('/');
    }
  };

  return (
    <div className="layout-wrapper" style={{ minHeight: '100vh', display: 'flex', flexDirection: 'column' }}>
      <ForensicCursor />
      <InvestigationHistoryModal isOpen={showHistoryModal} onClose={() => setShowHistoryModal(false)} />
      
      {/* ─── STICKY NAVIGATION ────────────────────────────────────────── */}
      <header 
        style={{ 
          position: 'sticky', 
          top: 0, 
          zIndex: 100, 
          backgroundColor: 'var(--surface-elevated)', 
          borderBottom: '1px solid var(--border-divider)',
          padding: '0.85rem 0'
        }}
      >
        <div className="container header-nav-container" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          
          {/* Logo */}
          <Link to="/" style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontWeight: 800, fontSize: '1.25rem', letterSpacing: '-0.02em', flexShrink: 0 }}>
            <div style={{ width: '20px', height: '20px', backgroundColor: 'var(--text-primary)' }}></div>
            PHISHFORENSICS <span style={{ color: 'var(--blue-primary)' }}>AI</span>
          </Link>

          {/* Nav Links */}
          <nav className="main-nav-links" style={{ display: 'flex', gap: '2rem', alignItems: 'center' }}>
            {navItems.map((item) => (
              <a 
                href={`#${item.id}`} 
                key={item.label} 
                onClick={(e) => handleNavClick(e, item.id)}
                className="mono-label nav-link-item" 
                style={{ 
                  color: 'var(--text-primary)', 
                  transition: 'color 0.2s ease', 
                  fontWeight: 600,
                  fontSize: '0.75rem',
                  letterSpacing: '0.08em',
                  cursor: 'pointer'
                }}
              >
                {item.label}
              </a>
            ))}
          </nav>

          {/* Actions & CTA */}
          <div style={{ display: 'flex', gap: '0.75rem', alignItems: 'center' }}>
            <button
              onClick={() => setShowHistoryModal(true)}
              className="nav-link-item"
              style={{
                padding: '0.5rem 0.85rem',
                backgroundColor: 'transparent',
                border: '1px solid var(--border-divider)',
                color: 'var(--text-primary)',
                fontFamily: 'var(--font-mono)',
                fontSize: '0.75rem',
                fontWeight: 600,
                borderRadius: 'var(--r-sm)',
                textTransform: 'uppercase',
                cursor: 'pointer',
                display: 'flex',
                alignItems: 'center',
                gap: '0.35rem'
              }}
              type="button"
              title="View stored investigation history in SQLite"
            >
              📁 HISTORY
            </button>
            <a 
              href="#analyze" 
              onClick={handleAnalyzeClick}
              style={{ 
                padding: '0.5rem 1rem', 
                backgroundColor: 'transparent', 
                border: '1px solid var(--text-primary)', 
                color: 'var(--text-primary)', 
                fontFamily: 'var(--font-mono)', 
                fontSize: '0.75rem', 
                fontWeight: 600, 
                borderRadius: 'var(--r-sm)',
                textTransform: 'uppercase',
                flexShrink: 0,
                cursor: 'pointer'
              }}
            >
              ANALYZE THREAT
            </a>
            <button
              onClick={toggleTheme}
              aria-label="Toggle light/dark theme"
              className="nav-link-item"
              style={{
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                width: '34px',
                height: '34px',
                backgroundColor: 'transparent',
                border: '1px solid var(--border-divider)',
                color: 'var(--text-primary)',
                borderRadius: 'var(--r-sm)',
                cursor: 'pointer',
                transition: 'all 150ms ease',
                flexShrink: 0
              }}
            >
              {theme === 'dark' ? (
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><circle cx="12" cy="12" r="5"></circle><line x1="12" y1="1" x2="12" y2="3"></line><line x1="12" y1="21" x2="12" y2="23"></line><line x1="4.22" y1="4.22" x2="5.64" y2="5.64"></line><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"></line><line x1="1" y1="12" x2="3" y2="12"></line><line x1="21" y1="12" x2="23" y2="12"></line><line x1="4.22" y1="19.78" x2="5.64" y2="18.36"></line><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"></line></svg>
              ) : (
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"></path></svg>
              )}
            </button>
          </div>
        </div>
      </header>

      {/* ─── MAIN CONTENT ─────────────────────────────────────────────── */}
      <main style={{ flex: 1, display: 'flex', flexDirection: 'column' }}>
        <Outlet />
      </main>

      {/* ─── FOOTER ───────────────────────────────────────────────────── */}
      <footer style={{ borderTop: '1px solid var(--border-divider)', padding: '4rem 0', backgroundColor: 'var(--surface-card)' }}>
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
          
          <div style={{ borderTop: '1px solid var(--border-divider)', marginTop: '4rem', paddingTop: '2rem', display: 'flex', justifyContent: 'space-between' }}>
            <p className="mono-label" style={{ fontSize: '0.65rem' }}>© 2026 PHISHFORENSICS AI. ALL RIGHTS RESERVED.</p>
            <p className="mono-label" style={{ fontSize: '0.65rem' }}>SECURE ANALYSIS ENVIRONMENT</p>
          </div>
        </div>
      </footer>
    </div>
  );
}
