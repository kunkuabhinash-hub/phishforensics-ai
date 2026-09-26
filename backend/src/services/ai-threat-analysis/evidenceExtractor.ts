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
        location: artifact.type === 'screenshot' ? 'Visible Screenshot Text' : 'Body Text',
        status: 'observed',
        description: `Observed textual indicator matching: "${trigger}"`,
        confidence: 85,
      });
    }
  }

  // Extract phone numbers from image metadata
  const phoneNumbers = Array.isArray(artifact.metadata?.extractedPhoneNumbers) ? artifact.metadata.extractedPhoneNumbers : [];
  for (const phone of phoneNumbers) {
    if (typeof phone === 'string' && phone.trim()) {
      counter++;
      evidenceList.push({
        id: `EV-${counter.toString().padStart(3, '0')}`,
        type: 'other',
        artifactId: artifact.id,
        rawContent: phone.trim(),
        defangedContent: phone.trim(),
        location: 'Visible Contact Information',
        status: 'observed',
        description: `Observed visible contact phone number: ${phone.trim()}`,
        confidence: 90,
      });
    }
  }

  // Extract suspicious phrases from image metadata
  const suspiciousPhrases = Array.isArray(artifact.metadata?.suspiciousPhrases) ? artifact.metadata.suspiciousPhrases : [];
  for (const phrase of suspiciousPhrases) {
    if (typeof phrase === 'string' && phrase.trim()) {
      const trimmedPhrase = phrase.trim();
      if (!evidenceList.some(e => e.rawContent.toLowerCase() === trimmedPhrase.toLowerCase())) {
        counter++;
        evidenceList.push({
          id: `EV-${counter.toString().padStart(3, '0')}`,
          type: 'text_phrase',
          artifactId: artifact.id,
          rawContent: trimmedPhrase,
          defangedContent: trimmedPhrase,
          location: 'Visible Screenshot Text',
          status: 'observed',
          description: `Observed suspicious textual cue: "${trimmedPhrase}"`,
          confidence: 90,
        });
      }
    }
  }

  // Extract visual forensic indicators
  const visualCues = Array.isArray(artifact.metadata?.visualForensicIndicators) ? artifact.metadata.visualForensicIndicators : [];
  for (const cue of visualCues) {
    if (typeof cue === 'string' && cue.trim()) {
      counter++;
      evidenceList.push({
        id: `EV-${counter.toString().padStart(3, '0')}`,
        type: 'visual_element',
        artifactId: artifact.id,
        rawContent: cue.trim(),
        defangedContent: cue.trim(),
        location: 'Visual Layout / Graphic Elements',
        status: 'observed',
        description: `Observed visual forensic indicator: "${cue.trim()}"`,
        confidence: 85,
      });
    }
  }

  // Extract visible logos and branding
  const branding = Array.isArray(artifact.metadata?.visibleLogosAndBranding) ? artifact.metadata.visibleLogosAndBranding : [];
  for (const brand of branding) {
    if (typeof brand === 'string' && brand.trim()) {
      counter++;
      evidenceList.push({
        id: `EV-${counter.toString().padStart(3, '0')}`,
        type: 'visual_element',
        artifactId: artifact.id,
        rawContent: brand.trim(),
        defangedContent: brand.trim(),
        location: 'Visual Branding / Logo',
        status: 'observed',
        description: `Observed visible brand or logo: "${brand.trim()}"`,
        confidence: 85,
      });
    }
  }

  // Extract image readability and quality metadata
  if (artifact.metadata?.readability) {
    const readability = artifact.metadata.readability;
    const qualityDesc = (artifact.metadata.imageQualityDescription as string) || '';
    if (readability === 'blurry_unreadable') {
      counter++;
      evidenceList.push({
        id: `EV-${counter.toString().padStart(3, '0')}`,
        type: 'metadata',
        artifactId: artifact.id,
        rawContent: `Image Readability: blurry_unreadable (${qualityDesc})`,
        defangedContent: `Image Readability: blurry_unreadable`,
        location: 'Visual Fidelity Assessment',
        status: 'observed',
        description: `Image visual fidelity is degraded or unreadable: ${qualityDesc}`,
        confidence: 95,
      });
    } else if (readability === 'blank_irrelevant') {
      counter++;
      evidenceList.push({
        id: `EV-${counter.toString().padStart(3, '0')}`,
        type: 'metadata',
        artifactId: artifact.id,
        rawContent: `Image Readability: blank_irrelevant (${qualityDesc})`,
        defangedContent: `Image Readability: blank_irrelevant`,
        location: 'Visual Content Assessment',
        status: 'observed',
        description: `Image contains no discernible security or forensic content: ${qualityDesc}`,
        confidence: 95,
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
