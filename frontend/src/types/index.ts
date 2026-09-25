export type InputType = 'url' | 'text' | 'image';

export interface AnalysisRequest {
  type: InputType;
  content: string; // URL string, text content, or base64 image data
}

export interface AnalysisResponse {
  // Temporary structure; to be updated when the API contract is finalized
  id: string;
  status: 'pending' | 'completed' | 'failed';
}
