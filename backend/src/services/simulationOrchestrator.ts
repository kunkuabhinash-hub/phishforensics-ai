import { buildCompleteReconstruction } from '../../services/orchestration/index.ts';
import type { CanonicalThreatIntelligence } from '../../../shared/types/threat-intelligence.ts';
import type { ThreatAnalysisInput, ThreatIndicator, EvidenceItem, ManipulationTechnique, ExtractedEntity } from '../../../shared/types/threat-analysis.ts';
import type { UnifiedPhishForensicsContract } from '../../../shared/types/unified-contract.ts';

export function runSimulationPipeline(
    canonical: CanonicalThreatIntelligence,
    unifiedPhase1: UnifiedPhishForensicsContract
): UnifiedPhishForensicsContract {
    // If image processing failed, preserve clean null state for downstream reconstruction
    if (canonical.artifacts?.some(a => a.metadata?.imageProcessingFailure)) {
        return {
            ...unifiedPhase1,
            attackDNA: null,
            reconstruction: null,
            safeSimulation: null,
            safetyGuidance: null
        };
    }

    // 1. Map CanonicalThreatIntelligence to ThreatAnalysisInput
    const threatAnalysisInput: ThreatAnalysisInput = {
        analysisId: unifiedPhase1.analysisId,
        analyzedAt: unifiedPhase1.timestamp,
        sourceType: unifiedPhase1.input.sourceType,
        
        attackerIntent: {
            primaryGoal: canonical.attackerIntent?.primaryObjective || '',
            description: canonical.attackerIntent?.intendedVictimAction || '',
            confidence: canonical.threatAssessment?.confidenceScore?.toString() || undefined,
            secondaryGoals: undefined 
        },
        
        indicators: (canonical.technicalIndicators || []).map(ti => ({
            type: ti.type,
            value: ti.defangedValue || ti.value || '',
            context: ti.context,
            severity: ti.suspicionLevel
        } as ThreatIndicator)),
        
        manipulationTechniques: (canonical.socialEngineering || []).map(se => ({
            name: se.techniqueName,
            description: se.explanation
        } as ManipulationTechnique)),
        
        evidence: (canonical.evidence || []).map(ev => ({
            id: ev.id,
            type: ev.type,
            finding: ev.description,
            rawSnippet: ev.rawContent || ev.defangedContent
        } as EvidenceItem)),
        
        riskInformation: {
            level: canonical.threatAssessment?.severity || 'unknown',
            assessment: canonical.threatAssessment?.verdictJustification || '',
            potentialImpact: canonical.attackerIntent?.potentialImpact ? [canonical.attackerIntent.potentialImpact] : [],
        },
        
        entities: (canonical.technicalIndicators || [])
            .filter(ti => ti.type === 'domain' || ti.type === 'sender')
            .map(ti => ({
                entityType: ti.type,
                name: ti.value || ti.defangedValue || 'unknown',
                role: ti.type === 'domain' ? 'hosting_infrastructure' : 'sender'
            } as ExtractedEntity))
    };

    // 2. Execute Yashu's existing deterministic engines
    const simulationResult = buildCompleteReconstruction(threatAnalysisInput);

    // 3. Merge Phase-2 fields back into the Unified Contract
    return {
        ...unifiedPhase1,
        attackDNA: simulationResult.attackDNA,
        reconstruction: simulationResult.attackReconstruction,
        safeSimulation: simulationResult.safeSimulation,
        safetyGuidance: simulationResult.safetyGuidance
    };
}
