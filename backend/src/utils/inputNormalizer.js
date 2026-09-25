/**
 * Input Normalization Layer
 * 
 * Normalizes incoming suspicious content before it reaches the AI engine.
 * Ensures consistent data shapes regardless of the input type (text, url, email, image).
 * 
 * @param {string} analysisId - The unique tracing ID for this request.
 * @param {string} type - The format of the input ('text', 'url', 'email', 'image', 'other').
 * @param {string} content - The raw content or reference.
 * @param {string} [source] - Optional context about where this was found.
 * @returns {object} The normalized internal representation.
 */
function normalizeInput(analysisId, type, content, source) {
    // 1. Basic sanitization: Trim whitespace and handle empty sources safely
    const cleanContent = typeof content === 'string' ? content.trim() : content;
    const cleanSource = typeof source === 'string' && source.trim() !== '' ? source.trim() : 'unknown';

    // 2. Type-specific formatting contexts
    // Do NOT perform intelligence here (e.g., no OCR, no URL fetching). 
    // Simply annotate for the future AI analysis engine.
    let formatInfo = {};

    switch (type) {
        case 'url':
            formatInfo.isUrl = true;
            formatInfo.requiresFetching = false; // We do not fetch URLs in the normalizer
            break;
        case 'image':
            formatInfo.isImageReference = true;
            formatInfo.requiresVision = true; // Future AI flag indicating OCR/vision is needed
            break;
        case 'email':
            formatInfo.isRawEmail = true;
            break;
        case 'text':
        case 'other':
        default:
            formatInfo.isPlainText = true;
            break;
    }

    // 3. Return the consolidated, normalized representation
    // Remains fully compliant with shared/types.js `InputMetadata` but enriched
    return {
        analysisId,
        type,
        content: cleanContent,
        source: cleanSource,
        timestamp: new Date().toISOString(),
        formatInfo
    };
}

module.exports = {
    normalizeInput
};
