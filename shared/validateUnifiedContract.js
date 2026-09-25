/**
 * Validates the AI portion of the UnifiedPhishForensicsContract.
 * Phase-2 fields (attackDNA, reconstruction, safeSimulation, safetyGuidance) are allowed to be null.
 */
function validateUnifiedContract(result) {
    if (!result || typeof result !== 'object') {
        throw new Error("Contract Validation Error: Result must be an object.");
    }
    
    const requiredFields = [
        'analysisId', 'timestamp', 'input', 'threatAssessment', 
        'attackerIntent', 'evidence', 'attackDNA', 'reconstruction', 
        'safeSimulation', 'safetyGuidance'
    ];
    
    for (const field of requiredFields) {
        if (!(field in result)) {
            throw new Error(`Contract Validation Error: Missing required field '${field}'.`);
        }
    }

    if (typeof result.analysisId !== 'string') {
        throw new Error("Contract Validation Error: 'analysisId' must be a string.");
    }

    if (!Array.isArray(result.evidence)) {
        throw new Error("Contract Validation Error: 'evidence' must be an array.");
    }

    if (result.mitreAttack !== undefined && result.mitreAttack !== null) {
        if (typeof result.mitreAttack !== 'object') {
            throw new Error("Contract Validation Error: 'mitreAttack' must be an object when present.");
        }
        const validStatuses = ['mapped', 'partial', 'unmapped'];
        if (!validStatuses.includes(result.mitreAttack.status)) {
            throw new Error(`Contract Validation Error: 'mitreAttack.status' must be one of ${validStatuses.join(', ')}.`);
        }
        if (!Array.isArray(result.mitreAttack.techniques)) {
            throw new Error("Contract Validation Error: 'mitreAttack.techniques' must be an array.");
        }
        if (!Array.isArray(result.mitreAttack.observedTactics)) {
            throw new Error("Contract Validation Error: 'mitreAttack.observedTactics' must be an array.");
        }
        if (!Array.isArray(result.mitreAttack.uncertaintyNotes)) {
            throw new Error("Contract Validation Error: 'mitreAttack.uncertaintyNotes' must be an array.");
        }
        if (result.mitreAttack.primaryTechnique !== null) {
            if (typeof result.mitreAttack.primaryTechnique !== 'object') {
                throw new Error("Contract Validation Error: 'mitreAttack.primaryTechnique' must be an object or null.");
            }
            if (typeof result.mitreAttack.primaryTechnique.techniqueId !== 'string') {
                throw new Error("Contract Validation Error: 'primaryTechnique.techniqueId' must be a string.");
            }
            if (typeof result.mitreAttack.primaryTechnique.techniqueName !== 'string') {
                throw new Error("Contract Validation Error: 'primaryTechnique.techniqueName' must be a string.");
            }
            if (!result.mitreAttack.primaryTechnique.tactic || typeof result.mitreAttack.primaryTechnique.tactic.id !== 'string') {
                throw new Error("Contract Validation Error: 'primaryTechnique.tactic' must contain an 'id' string.");
            }
        }
    }

    return true;
}

module.exports = {
    validateUnifiedContract
};
