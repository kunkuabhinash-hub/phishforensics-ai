import type { CanonicalThreatIntelligence } from '../../../shared/types/threat-intelligence.ts';
import type { UnifiedPhishForensicsContract } from '../../../shared/types/unified-contract.ts';

/**
 * Maps Hemanth's CanonicalThreatIntelligence to the AI portion of the UnifiedPhishForensicsContract.
 * Does NOT generate fake Phase-2 (Reconstruction/Simulation) data.
 */
export function mapCanonicalToUnified(
    canonical: CanonicalThreatIntelligence, 
    analysisId: string, 
    originalInputType: string, 
    originalInputContent: string
): UnifiedPhishForensicsContract {
    
    // Normalize technical indicators
    const technicalEvidence = (canonical.technicalIndicators || []).map(ti => ({
        id: ti.id,
        category: 'technical' as const,
        value: ti.value || ti.defangedValue, // some IOCs might not be defanged
        defangedValue: ti.defangedValue || null,
        description: ti.context || 'Technical indicator extracted from artifact',
        confidence: ti.suspicionLevel === 'high' ? 95 : 90
    }));

    // Normalize social engineering
    const psychoEvidence = (canonical.socialEngineering || []).map(se => ({
        id: se.id,
        category: 'psychological' as const,
        value: se.techniqueName,
        defangedValue: null,
        description: se.explanation,
        confidence: se.confidence || 80
    }));

    // Normalize contextual evidence
    const contextualEvidence = (canonical.evidence || []).map(ev => ({
        id: ev.id,
        category: 'contextual' as const,
        value: ev.rawContent || ev.defangedContent || '',
        defangedValue: ev.defangedContent || null,
        description: ev.description,
        confidence: ev.confidence ?? 85
    }));

    return {
        analysisId: analysisId,
        timestamp: canonical.investigation?.timestamp || new Date().toISOString(),
        input: {
            sourceType: originalInputType,
            content: originalInputContent
        },
        threatAssessment: {
            verdict: canonical.threatAssessment?.verdict || 'unknown',
            severity: canonical.threatAssessment?.severity || 'unknown',
            riskScore: canonical.threatAssessment?.riskScore ?? null,
            confidence: canonical.threatAssessment?.confidenceScore || 0,
            justification: canonical.threatAssessment?.verdictJustification || 'No justification provided'
        },
        attackerIntent: {
            primaryGoal: canonical.attackerIntent?.primaryObjective || 'unknown',
            description: canonical.attackerIntent?.intendedVictimAction || '',
            potentialImpact: canonical.attackerIntent?.potentialImpact || null
        },
        evidence: [
            ...technicalEvidence,
            ...psychoEvidence,
            ...contextualEvidence
        ],
        // Phase-2 fields explicitly left null/undefined.
        attackDNA: null,
        reconstruction: null,
        safeSimulation: null,
        safetyGuidance: null
    };
}
