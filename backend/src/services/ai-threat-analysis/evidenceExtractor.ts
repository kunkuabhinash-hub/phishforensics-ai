import type { EvidenceItem, EvidenceType, ObservationStatus } from '../../../../shared/types/threat-intelligence.ts';
import type { NormalizedArtifact, NormalizedAnalysisInput } from './types.ts';
import { defangUrl, defangEmail } from './safety.ts';

const URGENCY_TRIGGERS = [
  'immediately',
  'urgent',
  '24 hours',
  'account suspended',
  'unauthorized access',
  'action required',
  'verify your account',
  'password expired',
  'wire transfer',
  'security alert',
  'final notice',
];

export function extractEvidenceFromArtifact(
  artifact: NormalizedArtifact,
  startIndex: number
): EvidenceItem[] {
  const evidenceList: EvidenceItem[] = [];
  let counter = startIndex;

  for (const sender of artifact.extractedSenders) {
    counter++;
    evidenceList.push({
      id: `EV-${counter.toString().padStart(3, '0')}`,
      type: 'sender',
      artifactId: artifact.id,
      rawContent: sender,
      defangedContent: defangEmail(sender),
      location: 'Email Header / Sender Field',
      status: 'observed',
      description: `Observed sender identifier: ${defangEmail(sender)}`,
      confidence: 100,
    });
  }

  for (const url of artifact.extractedUrls) {
    counter++;
    evidenceList.push({
      id: `EV-${counter.toString().padStart(3, '0')}`,
      type: 'url',
      artifactId: artifact.id,
      rawContent: url,
      defangedContent: defangUrl(url),
      location: 'Artifact Body Content',
      status: 'observed',
      description: `Observed extracted hyperlink: ${defangUrl(url)}`,
      confidence: 100,
    });
  }

  if (artifact.extractedHeaders) {
    for (const [headerKey, headerVal] of Object.entries(artifact.extractedHeaders)) {
      counter++;
      const isAuthHeader = ['dkim-signature', 'authentication-results', 'return-path'].includes(headerKey);
      evidenceList.push({
        id: `EV-${counter.toString().padStart(3, '0')}`,
        type: 'header',
        artifactId: artifact.id,
        rawContent: `${headerKey}: ${headerVal}`,
        defangedContent: `${headerKey}: ${defangEmail(headerVal)}`,
        location: `Email Header [${headerKey}]`,
        status: isAuthHeader ? 'observed' : 'observed',
        description: `Observed RFC header entry for ${headerKey}`,
        confidence: 90,
      });
    }
  }

  const lowerContent = artifact.sanitizedContent.toLowerCase();
  for (const trigger of URGENCY_TRIGGERS) {
    if (lowerContent.includes(trigger)) {
      counter++;
      evidenceList.push({
        id: `EV-${counter.toString().padStart(3, '0')}`,
        type: 'text_phrase',
        artifactId: artifact.id,
        rawContent: trigger,
        defangedContent: trigger,
        location: 'Body Text',
        status: 'observed',
        description: `Observed textual indicator matching: "${trigger}"`,
        confidence: 85,
      });
    }
  }

  return evidenceList;
}

export function extractCandidateEvidence(input: NormalizedAnalysisInput): EvidenceItem[] {
  const allEvidence: EvidenceItem[] = [];
  let globalCounter = 0;

  for (const artifact of input.artifacts) {
    const artifactEvidence = extractEvidenceFromArtifact(artifact, globalCounter);
    allEvidence.push(...artifactEvidence);
    globalCounter += artifactEvidence.length;
  }

  return allEvidence;
}
