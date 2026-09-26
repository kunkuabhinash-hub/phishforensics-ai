// API Service layer for backend communication
import type { AnalysisRequest, AnalysisResponse } from '../types';

const API_BASE_URL = import.meta.env.VITE_API_URL || '/api';

export const apiService = {
  async submitAnalysis(request: AnalysisRequest): Promise<any> {
    try {
      const response = await fetch(`${API_BASE_URL}/analyze/unified`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(request),
      });

      if (!response.ok) {
        throw new Error(`API Error ${response.status}: Failed to submit analysis.`);
      }

      return await response.json();
    } catch (error: any) {
      if (error.name === 'TypeError' && error.message.includes('fetch')) {
        throw new Error('Network Error: Unable to connect to the backend API.');
      }
      throw error;
    }
  },
  
  async getAnalysisStatus(id: string): Promise<AnalysisResponse> {
    const response = await fetch(`${API_BASE_URL}/analyze/${id}`);
    
    if (!response.ok) {
      throw new Error('Failed to fetch analysis status');
    }

    return response.json();
  },

  async getInvestigations(limit: number = 50, offset: number = 0): Promise<import('../types').InvestigationHistoryItem[]> {
    try {
      const response = await fetch(`${API_BASE_URL}/investigations?limit=${limit}&offset=${offset}`);
      if (!response.ok) {
        throw new Error(`Failed to fetch investigations (${response.status})`);
      }
      const data = await response.json();
      return data.investigations || [];
    } catch (error) {
      console.error('[API] Error loading investigations:', error);
      throw error;
    }
  },

  async getInvestigation(analysisId: string): Promise<any> {
    try {
      const response = await fetch(`${API_BASE_URL}/investigations/${encodeURIComponent(analysisId)}`);
      if (!response.ok) {
        throw new Error(`Failed to load investigation ${analysisId} (${response.status})`);
      }
      return await response.json();
    } catch (error) {
      console.error(`[API] Error loading investigation ${analysisId}:`, error);
      throw error;
    }
  },

  async deleteInvestigation(analysisId: string): Promise<{ success: boolean; message: string }> {
    try {
      const response = await fetch(`${API_BASE_URL}/investigations/${encodeURIComponent(analysisId)}`, {
        method: 'DELETE'
      });
      if (!response.ok) {
        throw new Error(`Failed to delete investigation ${analysisId} (${response.status})`);
      }
      return await response.json();
    } catch (error) {
      console.error(`[API] Error deleting investigation ${analysisId}:`, error);
      throw error;
    }
  }
};
