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

export interface AttackReconstructionStage {
  id: string;
  title: string;
  description: string;
  attackerAction?: string;
  victimInteraction?: string;
  expectedConsequence?: string;
}

export interface SafeSimulationData {
  status: 'ready' | 'running' | 'completed' | 'failed' | 'unavailable';
  attackerObjective?: string;
  victimAction?: string;
  consequencePreview?: string;
  stages?: AttackReconstructionStage[];
}

export interface ForensicTakeaways {
  tactic?: string;
  manipulation?: string;
  target?: string;
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
  simulation?: SafeSimulationData;
  educationalLesson?: string;
  forensicTakeaways?: ForensicTakeaways;
  
  // To show original evidence
  originalRequest?: AnalysisRequest;
}
