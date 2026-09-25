// TEST ONLY - Verifies Yashu's orchestration pipeline mapping works with the Unified Contract
import { runSimulationPipeline } from '../src/services/simulationOrchestrator.ts';
import type { CanonicalThreatIntelligence } from '../../shared/types/threat-intelligence.ts';
import type { UnifiedPhishForensicsContract } from '../../shared/types/unified-contract.ts';

const mockCanonical: CanonicalThreatIntelligence = {
    investigation: {
        id: 'test-123',
        timestamp: '2026-09-25T00:00:00.000Z',
        schemaVersion: '1.0.0',
        analyzerVersion: '1.0.0',
        status: 'completed'
    },
    artifacts: [],
    threatAssessment: {
        verdict: 'phishing',
        severity: 'critical',
        riskScore: 99,
        confidenceScore: 95,
        summary: 'Test summary',
        verdictJustification: 'Test justification'
    },
    attackerIntent: {
        primaryObjective: 'Steal credentials',
        intendedVictimAction: 'Click link',
        potentialImpact: 'Account takeover'
    },
    evidence: [],
    technicalIndicators: [
        {
            id: 'ind-1',
            type: 'domain',
            value: 'evil.com',
            defangedValue: 'evil[.]com',
            suspicionLevel: 'high',
            context: 'Link in email'
        }
    ],
    socialEngineering: [
        {
            id: 'se-1',
            techniqueName: 'Urgency',
            explanation: 'Act now!'
        }
    ],
    attackDNASource: { attributes: [], signatures: [] },
    reconstructionTimeline: [],
    uncertaintyReport: { unverifiedClaims: [], logicalGaps: [], missingEvidence: [] },
    defensiveRecommendations: [],
    educationalExplanation: { psychologicalMechanism: '', technicalMechanism: '', redFlags: [] },
    crossArtifactCorrelations: [],
    metadata: {}
};

const mockPhase1: UnifiedPhishForensicsContract = {
    analysisId: 'test-123',
    timestamp: '2026-09-25T00:00:00.000Z',
    input: { sourceType: 'email', content: 'hello' },
    threatAssessment: {
        verdict: 'phishing',
        severity: 'critical',
        riskScore: 99,
        confidence: 95,
        justification: 'Test justification'
    },
    attackerIntent: {
        primaryGoal: 'Steal credentials',
        description: 'Click link',
        potentialImpact: 'Account takeover'
    },
    evidence: [
        {
            id: 'ind-1',
            category: 'technical',
            value: 'evil.com',
            defangedValue: 'evil[.]com',
            description: 'Link in email'
        },
        {
            id: 'se-1',
            category: 'psychological',
            value: 'Urgency',
            defangedValue: null,
            description: 'Act now!'
        }
    ]
};

console.log("Running simulation pipeline TEST ONLY...");
const result = runSimulationPipeline(mockCanonical, mockPhase1);

console.log("Attack DNA generated:", result.attackDNA ? "YES" : "NO");
console.log("Reconstruction generated:", result.reconstruction ? "YES" : "NO");
console.log("Safe Simulation generated:", result.safeSimulation ? "YES" : "NO");
console.log("Safety Guidance generated:", result.safetyGuidance ? "YES" : "NO");
console.log("Analysis ID preserved:", result.analysisId === 'test-123' ? "YES" : "NO");
console.log("Final Result Keys:", Object.keys(result));
