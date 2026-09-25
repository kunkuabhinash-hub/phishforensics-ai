import type { ThreatAnalysisProvider } from './types.ts';
import { getAIConfiguration, ConfigurationError } from './config.ts';
import { GeminiThreatAnalysisProvider } from './geminiProvider.ts';
import { FoundationPassThroughProvider } from './providerInterface.ts';

/**
 * ============================================================================
 * PHISHFORENSICS AI — PROVIDER FACTORY
 * ============================================================================
 *
 * Resolves the configured ThreatAnalysisProvider securely.
 */

export function resolveProvider(): ThreatAnalysisProvider {
  // We wrap config loading in try/catch to gracefully handle ConfigurationError if needed,
  // but by default, we let it propagate up so the pipeline fails clearly.
  const config = getAIConfiguration();

  switch (config.provider.toLowerCase()) {
    case 'gemini':
      return new GeminiThreatAnalysisProvider(config);
    case 'foundation':
    case 'passthrough':
      return new FoundationPassThroughProvider();
    default:
      throw new ConfigurationError(`Unsupported AI_PROVIDER: "${config.provider}". Supported values are "gemini", "foundation".`);
  }
}
