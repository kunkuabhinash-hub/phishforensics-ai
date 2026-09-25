export default function Home() {
  return (
    <div className="home-container">
      <h1>Welcome to PhishForensics AI</h1>
      <p>
        An explainable AI-based phishing investigation and awareness platform.
      </p>
      <div className="card">
        <h2>Start New Analysis</h2>
        <div className="form-group">
          <input 
            type="text" 
            placeholder="Enter suspicious URL..." 
          />
          <button>Analyze</button>
        </div>
      </div>
    </div>
  );
}
