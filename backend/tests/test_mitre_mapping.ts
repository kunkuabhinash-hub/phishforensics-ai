import assert from 'node:assert';
import { mapToMitreAttack } from '../src/services/mitre/mitreMapper.ts';
import type { CanonicalThreatIntelligence } from '../../shared/types/threat-intelligence.ts';
import type { AttackReconstruction } from '../../shared/types/reconstruction.ts';
import type { AttackDNA } from '../../shared/types/attack-dna.ts';
import { validateUnifiedContract } from '../../shared/validateUnifiedContract.js';

function createMockCanonical(overrides: Partial<CanonicalThreatIntelligence> = {}): CanonicalThreatIntelligence {
  return {
    investigation: {
      id: 'test-inv-001',
      timestamp: new Date().toISOString(),
      schemaVersion: '1.0.0',
      analyzerVersion: '1.0.0',
      status: 'completed'
    },
    artifacts: [],
    threatAssessment: {
      verdict: 'phishing',
      severity: 'high',
      riskScore: 85,
      confidenceScore: 90,
      summary: 'Phishing detected',
      verdictJustification: 'Deceptive indicators observed'
    },
    attackerIntent: {
      primaryObjective: 'Credential Harvesting',
      intendedVictimAction: 'Submit credentials',
      potentialImpact: 'Account compromise'
    },
    evidence: [],
    technicalIndicators: [],
    socialEngineering: [],
    attackDNASource: { attributes: [] },
    reconstructionTimeline: [],
    uncertaintyReport: { unverifiedClaims: [], conflictingSignals: [], missingEvidence: [] },
    defensiveRecommendations: [],
    educationalExplanation: {
      whatHappened: '',
      knownFacts: [],
      inferredAssumptions: [],
      unknownFactors: [],
      whyThisWorks: '',
      keySignalsNoticed: [],
      psychologicalMechanism: '',
      saferAlternativeBehavior: ''
    },
    crossArtifactCorrelations: [],
    metadata: {},
    ...overrides
  };
}

console.log('--- RUNNING MITRE ATT&CK MAPPING TESTS ---');

// TEST A: Email containing an actual link indicator + phishing context
{
  console.log('\n[TEST A] Email containing an actual URL indicator + phishing context');
  const canonical = createMockCanonical({
    technicalIndicators: [
      {
        id: 'IOC-001',
        type: 'url',
        value: 'https://evil-auth-portal.com/login',
        defangedValue: 'hxxps://evil-auth-portal[.]com/login',
        suspicionLevel: 'critical',
        metadata: {}
      }
    ]
  });

  const originalInput = {
    sourceType: 'email',
    content: 'Please verify your account here: https://evil-auth-portal.com/login'
  };

  const mitre = mapToMitreAttack(canonical, null, null, undefined, originalInput);

  assert.strictEqual(mitre.status, 'mapped', 'Test A status should be mapped');
  assert.ok(mitre.primaryTechnique !== null, 'Test A should have a primary technique');
  assert.strictEqual(mitre.primaryTechnique?.techniqueId, 'T1566', 'Technique ID must be T1566');
  assert.strictEqual(mitre.primaryTechnique?.subTechniqueId, 'T1566.002', 'Sub-technique must be T1566.002');
  assert.strictEqual(mitre.primaryTechnique?.subTechniqueName, 'Spearphishing Link', 'Sub-technique name must match');
  assert.strictEqual(mitre.primaryTechnique?.tactic.id, 'TA0001', 'Tactic must be Initial Access (TA0001)');
  assert.ok(mitre.primaryTechnique?.supportingEvidenceRefs.includes('IOC-001'), 'Must cite IOC-001 reference');
  console.log('✔ TEST A PASSED: Correctly mapped to T1566.002 (Spearphishing Link)');
}

// TEST B: Email mentioning a link ("security link below") but containing NO actual URL artifact
{
  console.log('\n[TEST B] Email mentioning a link in text but containing NO actual URL artifact');
  const canonical = createMockCanonical({
    technicalIndicators: [], // ZERO URL artifacts
    evidence: [
      {
        id: 'EV-001',
        category: 'contextual',
        rawContent: 'immediately',
        description: 'Urgency indicator'
      },
      {
        id: 'EV-002',
        category: 'contextual',
        rawContent: 'verify your account',
        description: 'Action indicator'
      }
    ]
  });

  const originalInput = {
    sourceType: 'email',
    content: 'Your account has been temporarily suspended. Verify your account immediately using the security link below.'
  };

  const mitre = mapToMitreAttack(canonical, null, null, undefined, originalInput);

  assert.notStrictEqual(mitre.primaryTechnique?.subTechniqueId, 'T1566.002', 'CRITICAL: Must NOT map to T1566.002 without actual URL');
  assert.strictEqual(mitre.status, 'partial', 'Status should be partial');
  assert.strictEqual(mitre.primaryTechnique?.techniqueId, 'T1566', 'Should map to parent T1566');
  assert.strictEqual(mitre.primaryTechnique?.subTechniqueId, null, 'Sub-technique ID must be null');
  assert.ok(
    mitre.uncertaintyNotes.some(note => note.includes('T1566.002') && note.includes('actual URL')),
    'Must include uncertainty note explaining why T1566.002 was not asserted'
  );
  console.log('✔ TEST B PASSED: Textual mention of link was NOT falsely classified as T1566.002');
}

// TEST C: Email with attachment evidence
{
  console.log('\n[TEST C] Email with attachment evidence');
  const canonical = createMockCanonical({
    technicalIndicators: [
      {
        id: 'IOC-002',
        type: 'attachment',
        value: 'Invoice_Overdue.pdf',
        defangedValue: 'Invoice_Overdue.pdf',
        suspicionLevel: 'high',
        metadata: {}
      }
    ]
  });

  const originalInput = {
    sourceType: 'email',
    content: 'Attached is your overdue invoice. Please remit payment.'
  };

  const mitre = mapToMitreAttack(canonical, null, null, undefined, originalInput);

  assert.strictEqual(mitre.status, 'mapped', 'Test C status should be mapped');
  assert.strictEqual(mitre.primaryTechnique?.techniqueId, 'T1566');
  assert.strictEqual(mitre.primaryTechnique?.subTechniqueId, 'T1566.001', 'Must map to T1566.001');
  assert.strictEqual(mitre.primaryTechnique?.subTechniqueName, 'Spearphishing Attachment');
  assert.ok(
    mitre.techniques.some(t => t.techniqueId === 'T1204' && t.subTechniqueId === 'T1204.002'),
    'Should also identify T1204.002 (User Execution: Malicious File)'
  );
  console.log('✔ TEST C PASSED: Correctly mapped to T1566.001 (Spearphishing Attachment)');
}

// TEST D: Insufficient / unknown / safe evidence
{
  console.log('\n[TEST D] Insufficient / unknown / safe evidence');
  const canonical = createMockCanonical({
    threatAssessment: {
      verdict: 'safe',
      severity: 'unknown',
      riskScore: 0,
      confidenceScore: 90,
      summary: 'Normal email with no threat indicators',
      verdictJustification: 'Clean communication'
    },
    technicalIndicators: [],
    evidence: []
  });

  const originalInput = {
    sourceType: 'email',
    content: 'Hi Team, the weekly meeting has been moved to Thursday at 3 PM.'
  };

  const mitre = mapToMitreAttack(canonical, null, null, undefined, originalInput);

  assert.strictEqual(mitre.status, 'unmapped', 'Status must be unmapped');
  assert.strictEqual(mitre.primaryTechnique, null, 'Primary technique must be null');
  assert.strictEqual(mitre.techniques.length, 0, 'Techniques array must be empty');
  assert.ok(mitre.uncertaintyNotes.length > 0, 'Must include uncertainty notes');
  console.log('✔ TEST D PASSED: Insufficient/safe evidence correctly produced unmapped status without guessing');
}

// TEST E: Validate full contract with mitreAttack
{
  console.log('\n[TEST E] Contract structural validation with mitreAttack');
  const fullMockContract = {
    analysisId: 'test-uuid-456',
    timestamp: new Date().toISOString(),
    input: { sourceType: 'email', content: 'test' },
    threatAssessment: {
      verdict: 'phishing',
      severity: 'high',
      riskScore: 80,
      confidence: 85,
      justification: 'test'
    },
    attackerIntent: {
      primaryGoal: 'Theft',
      description: 'Test',
      potentialImpact: 'Test'
    },
    evidence: [],
    attackDNA: null,
    reconstruction: null,
    safeSimulation: null,
    safetyGuidance: null,
    mitreAttack: mapToMitreAttack(createMockCanonical(), null, null, [], { sourceType: 'email', content: 'test' })
  };

  const isValid = validateUnifiedContract(fullMockContract);
  assert.strictEqual(isValid, true, 'Contract must pass validateUnifiedContract');
  console.log('✔ TEST E PASSED: Unified contract validation passed with mitreAttack attached');
}

console.log('\n===========================================');
console.log('ALL FOCUSED MITRE ATT&CK TESTS PASSED (5/5)');
console.log('===========================================');
