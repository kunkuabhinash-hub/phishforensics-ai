import React, { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { apiService } from '../services/api';
import type { InvestigationHistoryItem } from '../types';
import './InvestigationHistoryModal.css';

interface Props {
  isOpen: boolean;
  onClose: () => void;
  onSelectInvestigation?: (investigation: any) => void;
}

export default function InvestigationHistoryModal({ isOpen, onClose, onSelectInvestigation }: Props) {
  const navigate = useNavigate();
  const [historyItems, setHistoryItems] = useState<InvestigationHistoryItem[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const [deletingId, setDeletingId] = useState<string | null>(null);
  const [loadingViewId, setLoadingViewId] = useState<string | null>(null);

  const fetchHistory = async () => {
    setLoading(true);
    setError(null);
    try {
      const items = await apiService.getInvestigations(50, 0);
      setHistoryItems(items);
    } catch (err: any) {
      setError(err?.message || 'Failed to load investigation history from SQLite database.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (isOpen) {
      fetchHistory();
    }
  }, [isOpen]);

  if (!isOpen) return null;

  const handleView = async (analysisId: string) => {
    setLoadingViewId(analysisId);
    try {
      const fullInvestigation = await apiService.getInvestigation(analysisId);
      if (onSelectInvestigation) {
        onSelectInvestigation(fullInvestigation);
      } else {
        navigate('/dashboard', { state: { analysisResult: fullInvestigation, result: fullInvestigation } });
      }
      onClose();
    } catch (err: any) {
      alert(`Error loading investigation: ${err?.message || 'Record not found.'}`);
    } finally {
      setLoadingViewId(null);
    }
  };

  const handleDelete = async (analysisId: string, e: React.MouseEvent) => {
    e.stopPropagation();
    const confirmed = window.confirm(
      `Are you sure you want to permanently delete investigation "${analysisId}" from the SQLite database?`
    );
    if (!confirmed) return;

    setDeletingId(analysisId);
    try {
      await apiService.deleteInvestigation(analysisId);
      setHistoryItems(prev => prev.filter(item => item.analysisId !== analysisId));
    } catch (err: any) {
      alert(`Delete failed: ${err?.message || 'Database error'}`);
    } finally {
      setDeletingId(null);
    }
  };

  // Helper: Group items by Date (Today, Yesterday, or formatted date)
  const groupItemsByDate = (items: InvestigationHistoryItem[]) => {
    const groups: { [key: string]: InvestigationHistoryItem[] } = {};
    const today = new Date().toDateString();
    const yesterdayDate = new Date();
    yesterdayDate.setDate(yesterdayDate.getDate() - 1);
    const yesterday = yesterdayDate.toDateString();

    items.forEach(item => {
      const itemDate = new Date(item.createdAt);
      const dateStr = itemDate.toDateString();
      let label = dateStr;
      if (dateStr === today) {
        label = 'Today';
      } else if (dateStr === yesterday) {
        label = 'Yesterday';
      } else {
        label = itemDate.toLocaleDateString(undefined, { month: 'short', day: 'numeric', year: 'numeric' });
      }

      if (!groups[label]) groups[label] = [];
      groups[label].push(item);
    });

    return groups;
  };

  const grouped = groupItemsByDate(historyItems);

  const getVerdictClass = (verdict: string) => {
    const v = verdict.toLowerCase();
    if (v === 'phishing' || v === 'malicious') return 'badge-phishing';
    if (v === 'suspicious') return 'badge-suspicious';
    if (v === 'safe' || v === 'benign') return 'badge-safe';
    return 'badge-unknown';
  };

  return (
    <div className="history-modal-backdrop" onClick={onClose} role="dialog" aria-modal="true">
      <div className="history-modal-card" onClick={e => e.stopPropagation()}>
        {/* Header */}
        <div className="history-modal-header">
          <div>
            <span className="history-header-tag">SQLITE PERSISTENCE</span>
            <h2 className="history-header-title">INVESTIGATION HISTORY</h2>
            <p className="history-header-subtitle">
              Previously conducted forensic investigations stored locally in SQLite database.
            </p>
          </div>
          <div className="history-header-actions">
            <button 
              className="history-refresh-btn" 
              onClick={fetchHistory} 
              title="Refresh investigations"
              disabled={loading}
              type="button"
            >
              🔄 Refresh
            </button>
            <button className="history-close-btn" onClick={onClose} aria-label="Close modal" type="button">
              ✕
            </button>
          </div>
        </div>

        {/* Content Body */}
        <div className="history-modal-body">
          {loading && (
            <div className="history-state-box">
              <span className="history-spinner"></span>
              <p>Querying SQLite database...</p>
            </div>
          )}

          {error && !loading && (
            <div className="history-state-box history-error-box">
              <p>⚠️ {error}</p>
              <button className="btn-secondary-sm" onClick={fetchHistory} type="button">
                Try Again
              </button>
            </div>
          )}

          {!loading && !error && historyItems.length === 0 && (
            <div className="history-state-box">
              <p style={{ fontSize: '1.1rem', color: 'var(--text-primary)', marginBottom: '0.5rem' }}>
                No Investigations Stored Yet
              </p>
              <p style={{ color: 'var(--text-muted)', fontSize: '0.85rem', maxWidth: '400px', margin: '0 auto 1.5rem' }}>
                When you submit a text, email, URL, or image artifact for analysis, its complete forensic report is automatically saved to SQLite.
              </p>
            </div>
          )}

          {!loading && !error && historyItems.length > 0 && (
            <div className="history-timeline-list">
              {Object.entries(grouped).map(([dateGroup, items]) => (
                <div key={dateGroup} className="history-date-group">
                  <div className="history-date-heading">{dateGroup}</div>
                  <div className="history-items-grid">
                    {items.map(item => {
                      const timeStr = new Date(item.createdAt).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
                      const isViewing = loadingViewId === item.analysisId;
                      const isDeleting = deletingId === item.analysisId;

                      return (
                        <div key={item.analysisId} className="history-item-card">
                          <div className="history-card-top">
                            <div className="history-badges-row">
                              <span className={`history-verdict-badge ${getVerdictClass(item.verdict)}`}>
                                {item.verdict.toUpperCase()}
                              </span>
                              <span className="history-type-badge">
                                {item.sourceType.toUpperCase()}
                              </span>
                              {item.severity && item.severity !== 'unknown' && (
                                <span className="history-severity-badge">
                                  {item.severity.toUpperCase()}
                                </span>
                              )}
                            </div>
                            <span className="history-time-stamp">{timeStr}</span>
                          </div>

                          <div className="history-card-metrics">
                            <div className="history-metric">
                              <span className="metric-label">RISK SCORE</span>
                              <span className="metric-val">
                                {item.riskScore !== null ? `${item.riskScore} / 100` : 'N/A'}
                              </span>
                            </div>
                            <div className="history-metric">
                              <span className="metric-label">CONFIDENCE</span>
                              <span className="metric-val">{item.confidence}%</span>
                            </div>
                            <div className="history-metric id-metric">
                              <span className="metric-label">INVESTIGATION ID</span>
                              <span className="metric-id-code" title={item.analysisId}>
                                {item.analysisId.substring(0, 14)}...
                              </span>
                            </div>
                          </div>

                          {item.inputContent && (
                            <p className="history-card-input-snippet">
                              {item.inputContent}
                            </p>
                          )}

                          <div className="history-card-actions">
                            <button
                              className="history-action-btn view-btn"
                              onClick={() => handleView(item.analysisId)}
                              disabled={isViewing || isDeleting}
                              type="button"
                            >
                              {isViewing ? 'Loading...' : '👁 [ VIEW ]'}
                            </button>
                            <button
                              className="history-action-btn delete-btn"
                              onClick={(e) => handleDelete(item.analysisId, e)}
                              disabled={isViewing || isDeleting}
                              type="button"
                              title="Delete from SQLite database"
                            >
                              {isDeleting ? 'Deleting...' : '🗑 [ DELETE ]'}
                            </button>
                          </div>
                        </div>
                      );
                    })}
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="history-modal-footer">
          <span className="history-footer-status">
            Total Stored: <strong>{historyItems.length}</strong> investigation records
          </span>
          <button className="history-footer-close-btn" onClick={onClose} type="button">
            Close
          </button>
        </div>
      </div>
    </div>
  );
}
