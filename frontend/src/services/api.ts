// API Service layer for backend communication
import { AnalysisRequest, AnalysisResponse } from '../types';

const API_BASE_URL = import.meta.env.VITE_API_URL || '/api';

export const apiService = {
  async submitAnalysis(request: AnalysisRequest): Promise<AnalysisResponse> {
    const response = await fetch(`${API_BASE_URL}/analyze`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(request),
    });

    if (!response.ok) {
      throw new Error('Failed to submit analysis');
    }

    return response.json();
  },
  
  async getAnalysisStatus(id: string): Promise<AnalysisResponse> {
    const response = await fetch(`${API_BASE_URL}/analyze/${id}`);
    
    if (!response.ok) {
      throw new Error('Failed to fetch analysis status');
    }

    return response.json();
  }
};
