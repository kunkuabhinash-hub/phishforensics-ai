export type InputType = 'url' | 'text' | 'image';

export interface AnalysisRequest {
  type: InputType;
  content: string; // URL string, text content, or base64 image data
}

export interface AttackDna {
  [key: string]: number; // key: category (e.g. impersonation), value: score
}

export interface AttackTimelineStage {
  stage: string;
  description: string;
}

export interface AnalysisResponse {
  // Temporary structure; to be updated when the API contract is finalized
  id: string;
  status: 'pending' | 'completed' | 'failed';
  
  // Future fields expected from the backend
  riskScore?: number;
  riskLevel?: string;
  intent?: string;
  indicators?: string[];
  attackDna?: AttackDna;
  timeline?: AttackTimelineStage[];
  explanation?: string;
  recommendations?: string[];
  
  // To show original evidence
  originalRequest?: AnalysisRequest;
}
