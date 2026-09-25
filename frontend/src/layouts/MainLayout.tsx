import { Outlet, Link } from 'react-router-dom';

export default function MainLayout() {
  return (
    <div className="layout-container">
      <header className="main-header">
        <div className="header-content">
          <Link to="/" className="logo">PhishForensics AI</Link>
          <nav>
            <ul>
              <li><Link to="/">Home</Link></li>
              <li><Link to="/dashboard">Dashboard</Link></li>
            </ul>
          </nav>
        </div>
      </header>

      <main className="main-content">
        <Outlet />
      </main>

      <footer className="main-footer">
        <p>&copy; {new Date().getFullYear()} PhishForensics AI Project</p>
      </footer>
    </div>
  );
}
