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

    return true;
}

module.exports = {
    validateUnifiedContract
};
