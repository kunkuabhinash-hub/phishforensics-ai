import type { ThreatAnalysisInput } from "../../../shared/types/threat-analysis.ts";
import type { CompleteReconstructionResult } from "../../../shared/types/reconstruction-result.ts";

import { extractAttackDNA } from "../reconstruction/trait-extractor.ts";
import { reconstructAttack } from "../reconstruction/attack-reconstruction-engine.ts";
import { generateSimulation } from "../simulation/safe-simulation-engine.ts";
import { generateSafetyGuidance } from "./safety-guidance-engine.ts";

/**
 * Reusable orchestration pipeline that unifies Threat Analysis -> Attack DNA -> 
 * Attack Reconstruction -> Safe Simulation -> Safety Guidance.
 * 
 * Returns a strictly serializable CompleteReconstructionResult.
 * Does NOT perform side effects, network requests, or real exploits.
 */
export function buildCompleteReconstruction(threatAnalysis: ThreatAnalysisInput): CompleteReconstructionResult {
    // 1. Extract DNA
    const attackDNA = extractAttackDNA(threatAnalysis);
    
    // 2. Reconstruct Attack Stages
    const attackReconstruction = reconstructAttack(threatAnalysis);
    
    // 3. Map into Safe Simulation
    const safeSimulation = generateSimulation(attackReconstruction);
    
    // 4. Generate Grounded Guidance
    const safetyGuidance = generateSafetyGuidance(threatAnalysis, attackDNA, attackReconstruction);
    
    // 5. Assemble and Return Complete Serializable Contract
    return {
        version: "1.0.0",
        resultId: `result-${Math.random().toString(36).substring(2, 9)}`,
        generatedAt: new Date().toISOString(),
        threatAnalysis,
        attackDNA,
        attackReconstruction,
        safeSimulation,
        safetyGuidance
    };
}
