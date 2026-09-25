import type { RawArtifactInput, NormalizedArtifact, NormalizedAnalysisInput, AnalysisInputOptions } from './types.ts';
import { sanitizeContent, computeHash } from './safety.ts';

const URL_REGEX = /(https?:\/\/[^\s<>"]+|www\.[^\s<>"]+)/gi;
const EMAIL_REGEX = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g;

export function normalizeArtifact(raw: RawArtifactInput, index: number): NormalizedArtifact {
  const artifactId = raw.id || `ART-${(index + 1).toString().padStart(3, '0')}`;
  const rawContent = raw.content || '';
  const sanitizedContent = sanitizeContent(rawContent);
  const sha256 = computeHash(rawContent);

  const matchedUrls = Array.from(new Set(rawContent.match(URL_REGEX) || []));

  const extractedDomains = Array.from(
    new Set(
      matchedUrls
        .map((u) => {
          try {
            const host = u.replace(/^https?:\/\//i, '').split('/')[0].split(':')[0];
            return host.toLowerCase();
          } catch {
            return '';
          }
        })
        .filter(Boolean)
    )
  );

  const extractedSenders = Array.from(new Set(rawContent.match(EMAIL_REGEX) || []));

  const extractedHeaders: Record<string, string> = {};
  if (raw.type === 'email' || raw.type === 'header') {
    const lines = rawContent.split('\n');
    for (const line of lines) {
      const colonIndex = line.indexOf(':');
      if (colonIndex > 0) {
        const key = line.substring(0, colonIndex).trim().toLowerCase();
        const value = line.substring(colonIndex + 1).trim();
        if (key && value && ['from', 'to', 'subject', 'return-path', 'received', 'dkim-signature', 'authentication-results'].includes(key)) {
          extractedHeaders[key] = value;
        }
      }
    }
  }

  return {
    id: artifactId,
    type: raw.type || 'text',
    name: raw.name || `Artifact_${artifactId}`,
    format: raw.format || 'txt',
    sha256,
    sizeBytes: Buffer.byteLength(rawContent, 'utf-8'),
    rawContent,
    sanitizedContent,
    extractedHeaders: Object.keys(extractedHeaders).length > 0 ? extractedHeaders : undefined,
    extractedUrls: matchedUrls,
    extractedDomains,
    extractedSenders,
    metadata: raw.metadata || {},
  };
}

export function normalizeAnalysisInput(
  rawInputs: RawArtifactInput | RawArtifactInput[],
  options: AnalysisInputOptions = {}
): NormalizedAnalysisInput {
  const inputsArray = Array.isArray(rawInputs) ? rawInputs : [rawInputs];
  const investigationId = options.investigationId || `INV-${Date.now().toString(36).toUpperCase()}`;
  const timestamp = new Date().toISOString();

  const normalizedArtifacts = inputsArray.map((raw, idx) => normalizeArtifact(raw, idx));

  return {
    investigationId,
    timestamp,
    artifacts: normalizedArtifacts,
    options,
  };
}
