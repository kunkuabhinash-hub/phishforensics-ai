import { Outlet, NavLink, Link } from 'react-router-dom';
import { useState } from 'react';

export default function MainLayout() {
  const [mobileOpen, setMobileOpen] = useState(false);

  return (
    <div className="layout-container">
      {/* ── NAVIGATION ─────────────────────────────── */}
      <header className="main-header" role="banner">
        <div className="header-content">
          {/* Logo */}
          <Link to="/" className="logo" aria-label="PhishForensics AI — Home">
            <div className="logo-mark" aria-hidden="true" />
            <span className="logo-text">
              <span>Phish</span>Forensics AI
            </span>
          </Link>

          {/* Desktop Nav */}
          <nav aria-label="Primary navigation">
            <ul>
              <li>
                <NavLink to="/" end className={({ isActive }) => isActive ? 'nav-active' : ''}>
                  Analyze
                </NavLink>
              </li>
              <li>
                <a href="/#how-it-works">Pipeline</a>
              </li>
              <li>
                <a href="/#attack-dna">Attack DNA</a>
              </li>
              <li>
                <NavLink
                  to="/dashboard"
                  className={({ isActive }) => isActive ? 'nav-active' : ''}
                >
                  Forensics
                </NavLink>
              </li>
              <li>
                <NavLink
                  to="/"
                  end
                  className="nav-cta btn-arrow"
                >
                  Analyze Threat
                </NavLink>
              </li>
            </ul>
          </nav>

          {/* Mobile toggle */}
          <button
            className="nav-toggle"
            aria-label="Toggle navigation"
            aria-expanded={mobileOpen}
            onClick={() => setMobileOpen(!mobileOpen)}
          >
            <svg width="18" height="18" viewBox="0 0 18 18" fill="none">
              <rect x="1" y="4"  width="16" height="1.5" rx="1" fill="currentColor" />
              <rect x="1" y="8"  width="16" height="1.5" rx="1" fill="currentColor" />
              <rect x="1" y="12" width="16" height="1.5" rx="1" fill="currentColor" />
            </svg>
          </button>
        </div>

        {/* Mobile Menu */}
        {mobileOpen && (
          <div
            className="mobile-nav"
            role="navigation"
            aria-label="Mobile navigation"
            style={{
              position: 'absolute',
              top: '100%',
              left: 0,
              right: 0,
              background: 'rgba(8,12,18,0.98)',
              borderBottom: '1px solid var(--border-0)',
              padding: '12px 24px 20px',
              display: 'flex',
              flexDirection: 'column',
              gap: 4,
              backdropFilter: 'blur(20px)',
            }}
          >
            {[
              { to: '/', label: 'Analyze', end: true },
              { to: '/dashboard', label: 'Forensics', end: false },
            ].map(({ to, label, end }) => (
              <NavLink
                key={to}
                to={to}
                end={end}
                onClick={() => setMobileOpen(false)}
                style={{
                  padding: '12px 8px',
                  borderBottom: '1px solid var(--border-0)',
                  fontSize: '0.875rem',
                  fontWeight: 500,
                  color: 'var(--text-2)',
                  letterSpacing: '0.05em',
                }}
              >
                {label}
              </NavLink>
            ))}
          </div>
        )}
      </header>

      {/* ── MAIN ───────────────────────────────────── */}
      <main className="main-content" id="main-content">
        <Outlet />
      </main>

      {/* ── FOOTER ─────────────────────────────────── */}
      <footer className="main-footer" role="contentinfo">
        <div className="container">
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: 32, flexWrap: 'wrap', paddingBottom: 32, borderBottom: '1px solid var(--border-0)', marginBottom: 24 }}>
            {/* Brand */}
            <div style={{ maxWidth: 300 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 12 }}>
                <div className="logo-mark" aria-hidden="true" />
                <span style={{ fontWeight: 700, fontSize: '0.82rem', letterSpacing: '0.1em', textTransform: 'uppercase', color: 'var(--text-0)' }}>
                  <span style={{ color: 'var(--cyan)' }}>Phish</span>Forensics AI
                </span>
              </div>
              <p style={{ fontSize: '0.8rem', lineHeight: 1.6, color: 'var(--text-3)', fontStyle: 'italic' }}>
                Don't just detect the phishing.<br />Reconstruct the attack.
              </p>
            </div>

            {/* Links */}
            <nav aria-label="Footer navigation">
              <ul style={{ display: 'flex', gap: 20, flexWrap: 'wrap' }}>
                {[
                  { label: 'Analyze', href: '/' },
                  { label: 'Attack DNA', href: '/#attack-dna' },
                  { label: 'Pipeline', href: '/#how-it-works' },
                  { label: 'Forensics', href: '/dashboard' },
                ].map(({ label, href }) => (
                  <li key={label}>
                    <a
                      href={href}
                      style={{ fontSize: '0.78rem', fontWeight: 500, color: 'var(--text-3)', letterSpacing: '0.04em', transition: 'color 0.2s' }}
                      onMouseEnter={(e) => (e.currentTarget.style.color = 'var(--text-1)')}
                      onMouseLeave={(e) => (e.currentTarget.style.color = 'var(--text-3)')}
                    >
                      {label}
                    </a>
                  </li>
                ))}
              </ul>
            </nav>
          </div>

          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 12 }}>
            <p style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: '0.65rem', letterSpacing: '0.15em', textTransform: 'uppercase', color: 'var(--text-4)' }}>
              AI-Powered Digital Threat Forensics
            </p>
            <p style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: '0.65rem', color: 'var(--text-4)', letterSpacing: '0.08em' }}>
              &copy; {new Date().getFullYear()} PhishForensics AI
            </p>
          </div>
        </div>
      </footer>
    </div>
  );
}
