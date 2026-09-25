// Shared frontend types, aligned with future backend contracts

export interface AnalysisRequest {
  url: string;
}

export interface AnalysisResponse {
  // Temporary structure; to be updated when the API contract is finalized
  id: string;
  url: string;
  status: 'pending' | 'completed' | 'failed';
  // Add more fields here as the backend is developed
}
