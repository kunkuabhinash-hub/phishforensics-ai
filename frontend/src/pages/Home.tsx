import React, { useState, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import { apiService } from '../services/api';
import type { AnalysisRequest, InputType } from '../types';

export default function Home() {
  const navigate = useNavigate();
  const [inputType, setInputType] = useState<InputType>('url');
  const [inputValue, setInputValue] = useState('');
  const [imagePreview, setImagePreview] = useState<string | null>(null);
  
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [isSuccess, setIsSuccess] = useState(false);
  const [validationError, setValidationError] = useState<string | null>(null);

  const fileInputRef = useRef<HTMLInputElement>(null);

  const handleTextChange = (e: React.ChangeEvent<HTMLTextAreaElement | HTMLInputElement>) => {
    setInputValue(e.target.value);
    setValidationError(null);
    setError(null);
  };

  const handleImageUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file) {
      if (!file.type.startsWith('image/')) {
        setValidationError('Please upload a valid image file.');
        return;
      }
      
      const reader = new FileReader();
      reader.onloadend = () => {
        const base64String = reader.result as string;
        setInputValue(base64String);
        setImagePreview(base64String);
        setValidationError(null);
        setError(null);
      };
      reader.readAsDataURL(file);
    }
  };

  const validate = (): boolean => {
    if (inputType === 'url') {
      if (!inputValue.trim()) {
        setValidationError('URL cannot be empty.');
        return false;
      }
      try {
        new URL(inputValue);
      } catch {
        setValidationError('Please enter a valid URL.');
        return false;
      }
    } else if (inputType === 'text') {
      if (!inputValue.trim()) {
        setValidationError('Text content cannot be empty.');
        return false;
      }
    } else if (inputType === 'image') {
      if (!inputValue) {
        setValidationError('Please select an image to analyze.');
        return false;
      }
    }
    return true;
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!validate() || isLoading) return;

    setIsLoading(true);
    setError(null);
    setIsSuccess(false);

    try {
      const request: AnalysisRequest = {
        type: inputType,
        content: inputValue
      };
      
      const response = await apiService.submitAnalysis(request);
      
      // Attach the original request so the dashboard can render the "Original Evidence" safely
      const responseWithEvidence = {
        ...response,
        originalRequest: request
      };
      
      setIsSuccess(true);
      
      // Navigate to dashboard and pass the result in state for Step 4
      navigate('/dashboard', { state: { analysisResult: responseWithEvidence } });
    } catch (err: any) {
      console.error(err);
      setError(err.message || 'Connection to analysis engine failed. The backend API is currently unavailable.');
    } finally {
      setIsLoading(false);
    }
  };

  const switchTab = (type: InputType) => {
    setInputType(type);
    setInputValue('');
    setImagePreview(null);
    setError(null);
    setValidationError(null);
    setIsSuccess(false);
  };

  return (
    <div className="home-container">
      <div className="investigation-header">
        <h1>Forensic Investigation Workspace</h1>
        <p>Submit suspicious artifacts for structural Attack DNA extraction and threat reconstruction.</p>
      </div>

      <div className="investigation-panel">
        <div className="panel-tabs" role="tablist">
          <button 
            role="tab"
            aria-selected={inputType === 'url'}
            className={`tab-btn ${inputType === 'url' ? 'active' : ''}`}
            onClick={() => switchTab('url')}
            type="button"
          >
            URL Evidence
          </button>
          <button 
            role="tab"
            aria-selected={inputType === 'text'}
            className={`tab-btn ${inputType === 'text' ? 'active' : ''}`}
            onClick={() => switchTab('text')}
            type="button"
          >
            Raw Text/Email
          </button>
          <button 
            role="tab"
            aria-selected={inputType === 'image'}
            className={`tab-btn ${inputType === 'image' ? 'active' : ''}`}
            onClick={() => switchTab('image')}
            type="button"
          >
            Image Capture
          </button>
        </div>

        <form onSubmit={handleSubmit} className="investigation-form" aria-label="Investigation Input Form">
          {inputType === 'url' && (
            <div className="form-group" role="tabpanel">
              <label htmlFor="url-input">Target URL for Analysis</label>
              <input 
                id="url-input"
                type="url" 
                placeholder="https://suspicious-site.example.com" 
                value={inputValue}
                onChange={handleTextChange}
                disabled={isLoading}
                aria-invalid={!!validationError}
              />
            </div>
          )}

          {inputType === 'text' && (
            <div className="form-group" role="tabpanel">
              <label htmlFor="text-input">Suspicious Content / Headers / Body</label>
              <textarea 
                id="text-input"
                placeholder="Paste email headers, raw HTML, or suspicious text messages here..." 
                value={inputValue}
                onChange={handleTextChange}
                rows={8}
                disabled={isLoading}
                aria-invalid={!!validationError}
              />
              <div className="char-count" aria-live="polite">
                {inputValue.length} characters
              </div>
            </div>
          )}

          {inputType === 'image' && (
            <div className="form-group" role="tabpanel">
              <label htmlFor="image-input">Upload Screenshot or Image Evidence</label>
              <input 
                id="image-input"
                type="file" 
                accept="image/*"
                onChange={handleImageUpload}
                ref={fileInputRef}
                disabled={isLoading}
                className="file-input"
                aria-invalid={!!validationError}
              />
              {imagePreview && (
                <div className="image-preview-container">
                  <p className="preview-label">Local Evidence Preview:</p>
                  <img src={imagePreview} alt="Evidence preview" className="image-preview" />
                </div>
              )}
            </div>
          )}

          {validationError && (
            <div className="error-message validation-error" role="alert">
              {validationError}
            </div>
          )}

          {error && (
            <div className="error-message api-error" role="alert">
              <strong>SYSTEM FAULT:</strong> {error}
            </div>
          )}

          {isSuccess && (
            <div className="success-message" role="alert">
              Artifact submitted to investigation queue. Awaiting analysis results...
            </div>
          )}

          <div className="action-bar">
            <button 
              type="submit" 
              className={`analyze-btn ${isLoading ? 'loading' : ''}`}
              disabled={isLoading}
              aria-busy={isLoading}
            >
              {isLoading ? 'Initiating Analysis...' : 'Analyze Artifact'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
