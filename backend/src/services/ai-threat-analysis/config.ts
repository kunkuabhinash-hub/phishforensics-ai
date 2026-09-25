/**
 * ============================================================================
 * PHISHFORENSICS AI — AI CONFIGURATION LAYER
 * ============================================================================
 *
 * Centralizes configuration for the AI Threat Analysis pipeline.
 * Extracts settings from the environment, sets safe defaults where applicable,
 * and validates configurations before network execution.
 */

export interface AIProviderConfig {
  provider: string;
  model: string;
  apiKey: string;
  timeoutMs: number;
  maxInputChars: number;
}

export class ConfigurationError extends Error {
  constructor(message: string) {
    super(`AI Configuration Blocked: ${message}`);
    this.name = 'ConfigurationError';
  }
}

/**
 * Resolves and validates the current AI provider configuration.
 * Must throw a safe configuration error (without leaking secrets) if invalid.
 */
export function getAIConfiguration(): AIProviderConfig {
  const provider = process.env.AI_PROVIDER || 'gemini';
  
  // Model cannot be hardcoded; must be dynamic with no predefined global constant fallback if unconfigured
  // However, we can use a safe default if the environment explicitly relies on sensible defaults.
  // The instruction: "If there is no safe default because provider/model availability can change, 
  // require explicit configuration and produce a clear configuration error."
  const model = process.env.AI_MODEL;
  if (!model) {
    throw new ConfigurationError('AI_MODEL is not configured. A specific model identifier must be explicitly provided in the environment.');
  }

  const apiKey = process.env.AI_API_KEY || process.env.GEMINI_API_KEY;
  if (!apiKey) {
    throw new ConfigurationError('AI_API_KEY or GEMINI_API_KEY is not configured.');
  }

  // Parse timeout (Default: 30000ms / 30s)
  const timeoutRaw = process.env.AI_TIMEOUT_MS;
  let timeoutMs = 30000;
  if (timeoutRaw) {
    const parsed = parseInt(timeoutRaw, 10);
    if (isNaN(parsed) || parsed <= 0) {
      throw new ConfigurationError('AI_TIMEOUT_MS must be a positive integer.');
    }
    timeoutMs = parsed;
  }

  // Parse max input chars (Default: 100000 chars)
  const maxCharsRaw = process.env.AI_MAX_INPUT_CHARS;
  let maxInputChars = 100000;
  if (maxCharsRaw) {
    const parsed = parseInt(maxCharsRaw, 10);
    if (isNaN(parsed) || parsed <= 0) {
      throw new ConfigurationError('AI_MAX_INPUT_CHARS must be a positive integer.');
    }
    maxInputChars = parsed;
  }

  return {
    provider,
    model,
    apiKey,
    timeoutMs,
    maxInputChars,
  };
}
