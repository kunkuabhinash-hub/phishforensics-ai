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
  }
};
