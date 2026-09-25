const { runFullInvestigation } = require('./ai-threat-analysis/integrationContract.ts');
const AppError = require('../utils/AppError');

/**
 * AI Integration Boundary
 * 
 * Adapts Hemanth's comprehensive CanonicalThreatIntelligence 
 * to the established PhishForensicsResult shared contract.
 */
class AIEngine {
    /**
     * Executes the AI analysis on the suspicious input.
     * 
     * @param {string} analysisId - The unique request ID for tracing.
     * @param {import('../../../shared/types').InputMetadata} normalizedInput 
     * @returns {Promise<import('../../../shared/types').PhishForensicsResult>}
     */
    static async analyze(analysisId, normalizedInput) {
        try {
            // 1. Map our internal normalized input to Hemanth's RawArtifactInput format
            let artifactType = 'text';
            if (normalizedInput.type === 'url') artifactType = 'url';
            if (normalizedInput.type === 'email') artifactType = 'email';
            if (normalizedInput.type === 'image') artifactType = 'screenshot';

            const rawInputs = {
                id: analysisId,
                type: artifactType,
                content: normalizedInput.content,
                metadata: {
                    source: normalizedInput.source
                }
            };

            const options = {
                investigationId: analysisId
            };

            // 2. Execute Hemanth's complete Threat Analysis Pipeline
            // This natively executes his TypeScript integration using Node's runtime capabilities
            const fullResult = await runFullInvestigation(rawInputs, options);
            
            // 3. Extract the Canonical truth
            const canonical = fullResult.canonical;

            // 4. Adapt CanonicalThreatIntelligence back to PhishForensicsResult
            // This maintains our strict data contract for frontend and downstream modules
            return {
                analysisId: analysisId,
                input: {
                    type: normalizedInput.type,
                    content: normalizedInput.content,
                    timestamp: canonical.investigation.timestamp || normalizedInput.timestamp
                },
                risk: {
                    score: canonical.threatAssessment.riskScore || 0,
                    severity: canonical.threatAssessment.severity || 'unknown',
                    confidence: canonical.threatAssessment.confidenceScore || 0
                },
                threatIntent: canonical.attackerIntent.primaryObjective || 'unknown',
                indicators: {
                    psychological: canonical.socialEngineering.map(se => se.techniqueName) || [],
                    technical: canonical.technicalIndicators.map(ti => ti.defangedValue) || []
                },
                dna: {
                    suspectedActor: "", // Preserved contract string without inventing intelligence
                    tactics: canonical.attackDNASource?.attributes.map(attr => attr.characteristic) || [],
                    signature: "" 
                },
                reconstruction: (canonical.reconstructionTimeline || []).map((stage) => ({
                    stageId: stage.stageId,
                    title: stage.stageName,
                    description: stage.description,
                    mechanism: stage.victimAction || ""
                })),
                simulation: {
                    potentialConsequences: [canonical.attackerIntent.potentialImpact],
                    simulatedOutcomeDescription: "" // Handled later by reconstruction module
                },
                education: {
                    recommendedActions: (canonical.defensiveRecommendations || []).map(rec => rec.action),
                    keyLearnings: [canonical.educationalExplanation.psychologicalMechanism]
                }
            };
        } catch (error) {
            // Convert Hemanth's specific ConfigurationError or runtime errors to AppError
            // This returns a safe backend error without leaking secrets.
            throw new AppError(`AI Engine Failure: ${error.message}`, 502, analysisId);
        }
    }

    /**
     * Executes the AI analysis and maps it to the new UnifiedPhishForensicsContract.
     * Does NOT map Phase-2 fields (Reconstruction/Simulation).
     */
    static async analyzeUnified(analysisId, normalizedInput) {
        try {
            const { mapCanonicalToUnified } = require('./unifiedAdapter.ts');

            let artifactType = 'text';
            if (normalizedInput.type === 'url') artifactType = 'url';
            if (normalizedInput.type === 'email') artifactType = 'email';
            if (normalizedInput.type === 'image') artifactType = 'screenshot';

            const rawInputs = {
                id: analysisId,
                type: artifactType,
                content: normalizedInput.content,
                metadata: {
                    source: normalizedInput.source
                }
            };

            const options = {
                investigationId: analysisId
            };

            const fullResult = await runFullInvestigation(rawInputs, options);
            const canonical = fullResult.canonical;

            const phase1 = mapCanonicalToUnified(canonical, analysisId, normalizedInput.type, normalizedInput.content);
            return { canonical, phase1 };
        } catch (error) {
            throw new AppError(`AI Engine Failure: ${error.message}`, 502, analysisId);
        }
    }
}

module.exports = AIEngine;
