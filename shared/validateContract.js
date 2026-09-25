/**
 * Validates that the provided object conforms strictly to the 
 * PhishForensicsResult contract defined in types.js.
 * 
 * Used by the Backend to ensure the AI output is well-formed 
 * before it is passed down the pipeline or sent to the frontend.
 * 
 * @param {any} result - The object to validate.
 * @throws {Error} If the object does not conform to the contract.
 */
function validatePhishForensicsResult(result) {
    if (!result || typeof result !== 'object') {
        throw new Error("Contract Validation Error: Result must be an object.");
    }
    
    // 1. Check top-level required fields
    const requiredFields = [
        'analysisId', 'input', 'risk', 'threatIntent', 
        'indicators', 'dna', 'reconstruction', 'simulation', 'education'
    ];
    for (const field of requiredFields) {
        if (!(field in result)) {
            throw new Error(`Contract Validation Error: Missing required field '${field}'.`);
        }
    }

    if (typeof result.analysisId !== 'string') {
        throw new Error("Contract Validation Error: 'analysisId' must be a string.");
    }

    if (typeof result.threatIntent !== 'string') {
        throw new Error("Contract Validation Error: 'threatIntent' must be a string.");
    }

    // 2. Check input metadata
    if (!result.input || typeof result.input.type !== 'string' || typeof result.input.content !== 'string' || typeof result.input.timestamp !== 'string') {
        throw new Error("Contract Validation Error: 'input' must contain type, content, and timestamp as strings.");
    }

    // 3. Check risk
    if (!result.risk || typeof result.risk.score !== 'number' || typeof result.risk.severity !== 'string' || typeof result.risk.confidence !== 'number') {
        throw new Error("Contract Validation Error: 'risk' must contain numeric score/confidence and string severity.");
    }

    // 4. Check indicators
    if (!result.indicators || !Array.isArray(result.indicators.psychological) || !Array.isArray(result.indicators.technical)) {
        throw new Error("Contract Validation Error: 'indicators' must contain arrays for psychological and technical evidence.");
    }

    // 5. Check dna
    if (!result.dna || typeof result.dna.suspectedActor !== 'string' || !Array.isArray(result.dna.tactics) || typeof result.dna.signature !== 'string') {
        throw new Error("Contract Validation Error: 'dna' must contain suspectedActor (string), signature (string), and an array of tactics.");
    }

    // 6. Check reconstruction
    if (!Array.isArray(result.reconstruction)) {
        throw new Error("Contract Validation Error: 'reconstruction' must be an array of AttackStages.");
    }

    // 7. Check simulation
    if (!result.simulation || !Array.isArray(result.simulation.potentialConsequences) || typeof result.simulation.simulatedOutcomeDescription !== 'string') {
        throw new Error("Contract Validation Error: 'simulation' must contain potentialConsequences array and simulatedOutcomeDescription string.");
    }

    // 8. Check education
    if (!result.education || !Array.isArray(result.education.recommendedActions) || !Array.isArray(result.education.keyLearnings)) {
        throw new Error("Contract Validation Error: 'education' must contain arrays for recommendedActions and keyLearnings.");
    }

    return true; // Validation passed
}

module.exports = {
    validatePhishForensicsResult
};
