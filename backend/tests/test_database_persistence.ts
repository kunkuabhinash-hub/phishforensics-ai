import fs from 'fs';
import path from 'path';
import assert from 'node:assert';
import Database from 'better-sqlite3';
import { initDatabase, closeDb } from '../src/db/database.ts';
import {
  saveInvestigation,
  getInvestigation,
  listInvestigations,
  deleteInvestigation
} from '../src/db/investigationRepository.ts';
import type { UnifiedPhishForensicsContract } from '../../shared/types/unified-contract.ts';

console.log('=== RUNNING SQLITE INVESTIGATION DATABASE TESTS ===\n');

const testDbPath = path.join(__dirname, 'fixtures', 'test_scratch.sqlite');
if (fs.existsSync(testDbPath)) {
  fs.unlinkSync(testDbPath);
}

// A. Fresh database initialization
console.log('[TEST A] Fresh database initialization');
const db = initDatabase(testDbPath);
assert.ok(db, 'Database instance should be initialized');
const tables = db.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='investigations';").get();
assert.ok(tables, 'investigations table must exist');
console.log('✔ TEST A PASSED: Fresh database created with investigations table');

// Mock data fixtures
const mockInvestigation1: UnifiedPhishForensicsContract = {
  analysisId: 'inv-test-001',
  timestamp: new Date('2026-09-26T10:00:00.000Z').toISOString(),
  input: {
    sourceType: 'email',
    content: 'Urgent notice: verify credentials at https://auth.bank-alert.com/login'
  },
  threatAssessment: {
    verdict: 'phishing',
    severity: 'high',
    riskScore: 88,
    confidence: 95,
    justification: 'Critical urgency language with spoofed authentication link.'
  },
  attackerIntent: {
    primaryGoal: 'Credential Harvesting',
    description: 'Steal bank portal credentials',
    potentialImpact: 'Financial loss and account takeover'
  },
  evidence: [
    {
      id: 'EV-001',
      category: 'technical',
      value: 'https://auth.bank-alert.com/login',
      defangedValue: 'hxxps://auth.bank-alert[.]com/login',
      description: 'Extracted credential link',
      confidence: 95
    },
    {
      id: 'EV-002',
      category: 'psychological',
      value: 'Urgent notice',
      defangedValue: null,
      description: 'Artificial urgency',
      confidence: 90
    }
  ],
  attackDNA: {
    traits: [
      { key: 'urgency', present: true, label: 'Urgency Pressure', confidence: 90 },
      { key: 'impersonation', present: true, label: 'Bank Impersonation', confidence: 95 }
    ],
    overallPattern: 'High-Pressure Credential Capture'
  } as any,
  reconstruction: {
    stages: [
      { stageId: 'STAGE-01', stageTitle: 'Pretext Delivery', phaseCategory: 'delivery', mechanism: 'Deceptive Email' },
      { stageId: 'STAGE-02', stageTitle: 'Credential Capture', phaseCategory: 'credential_harvesting', mechanism: 'Spoofed Form' }
    ]
  } as any,
  safeSimulation: null,
  safetyGuidance: null,
  mitreAttack: {
    status: 'mapped',
    primaryTechnique: {
      techniqueId: 'T1566',
      techniqueName: 'Phishing',
      subTechniqueId: 'T1566.002',
      subTechniqueName: 'Spearphishing Link',
      tactic: { id: 'TA0001', name: 'Initial Access' }
    },
    techniques: [],
    observedTactics: [],
    uncertaintyNotes: []
  }
};

const mockInvestigation2: UnifiedPhishForensicsContract = {
  analysisId: 'inv-test-002',
  timestamp: new Date('2026-09-26T10:15:00.000Z').toISOString(),
  input: {
    sourceType: 'image',
    content: 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg=='
  },
  threatAssessment: {
    verdict: 'safe',
    severity: 'info',
    riskScore: 0,
    confidence: 100,
    justification: 'Screenshot shows benign internal team sync agenda.'
  },
  attackerIntent: {
    primaryGoal: 'None',
    description: 'Benign communication',
    potentialImpact: null
  },
  evidence: [],
  attackDNA: null,
  reconstruction: null,
  safeSimulation: null,
  safetyGuidance: null,
  mitreAttack: {
    status: 'unmapped',
    primaryTechnique: null,
    techniques: [],
    observedTactics: [],
    uncertaintyNotes: ['No threat observed']
  }
};

// B. Save investigation
console.log('\n[TEST B] Save investigation');
const saved1 = saveInvestigation(mockInvestigation1, db);
assert.strictEqual(saved1.analysisId, 'inv-test-001');
assert.strictEqual(saved1.verdict, 'phishing');
assert.strictEqual(saved1.riskScore, 88);
console.log('✔ TEST B PASSED: Investigation saved successfully');

// C. Retrieve investigation
console.log('\n[TEST C] Retrieve investigation');
const retrieved1 = getInvestigation('inv-test-001', db);
assert.ok(retrieved1, 'Must retrieve investigation 1');
assert.strictEqual(retrieved1?.analysisId, 'inv-test-001');
assert.strictEqual(retrieved1?.threatAssessment?.verdict, 'phishing');
assert.strictEqual(retrieved1?.threatAssessment?.riskScore, 88);
console.log('✔ TEST C PASSED: Investigation retrieved accurately');

// D. List investigations
console.log('\n[TEST D] List investigations');
saveInvestigation(mockInvestigation2, db);
const list = listInvestigations(10, 0, db);
assert.strictEqual(list.length, 2, 'Should list 2 investigations');
assert.strictEqual(list[0].analysisId, 'inv-test-002', 'Newest investigation should be first');
console.log('✔ TEST D PASSED: Investigations listed in reverse chronological order');

// E. Retrieve nonexistent investigation
console.log('\n[TEST E] Retrieve nonexistent investigation');
const nonexistent = getInvestigation('nonexistent-id-999', db);
assert.strictEqual(nonexistent, null, 'Nonexistent investigation must return null');
console.log('✔ TEST E PASSED: Correctly returned null for missing investigation');

// F. Delete investigation
console.log('\n[TEST F] Delete investigation');
const deleteSuccess = deleteInvestigation('inv-test-002', db);
assert.strictEqual(deleteSuccess, true, 'Delete operation should return true');
const afterDelete = getInvestigation('inv-test-002', db);
assert.strictEqual(afterDelete, null, 'Deleted investigation must no longer exist');
const deleteAgain = deleteInvestigation('inv-test-002', db);
assert.strictEqual(deleteAgain, false, 'Deleting non-existent record should return false');
console.log('✔ TEST F PASSED: Investigation deleted properly');

// G. Duplicate analysis ID handling (Update on conflict)
console.log('\n[TEST G] Duplicate analysis ID handling (UPSERT)');
const updatedMock = {
  ...mockInvestigation1,
  threatAssessment: {
    ...mockInvestigation1.threatAssessment,
    riskScore: 92
  }
};
saveInvestigation(updatedMock, db);
const retrievedUpdated = getInvestigation('inv-test-001', db);
assert.strictEqual(retrievedUpdated?.threatAssessment?.riskScore, 92, 'Risk score must be updated');
console.log('✔ TEST G PASSED: Duplicate analysis ID updated cleanly without error');

// H. Complete result_json preservation
console.log('\n[TEST H] Complete result_json preservation');
assert.ok(retrievedUpdated?.threatAssessment, 'threatAssessment must be preserved');
assert.ok(retrievedUpdated?.attackerIntent, 'attackerIntent must be preserved');
assert.strictEqual(retrievedUpdated?.attackerIntent?.primaryGoal, 'Credential Harvesting');
console.log('✔ TEST H PASSED: Complete contract structure preserved');

// I. Image analysis result persistence (large base64 sanitized in input)
console.log('\n[TEST I] Image analysis result persistence');
saveInvestigation(mockInvestigation2, db);
const retrievedImg = getInvestigation('inv-test-002', db);
assert.ok(retrievedImg, 'Image investigation must be retrieved');
assert.strictEqual(retrievedImg?.input.sourceType, 'image');
assert.ok(!retrievedImg?.input.content.includes('iVBORw0KGgo'), 'Large base64 payload should not be bloated in DB');
assert.ok(retrievedImg?.input.content.includes('Image Artifact'), 'Lightweight image reference preserved');
console.log('✔ TEST I PASSED: Image investigation persisted with lightweight reference');

// J. MITRE data survives persistence
console.log('\n[TEST J] MITRE data survives persistence');
assert.strictEqual(retrievedUpdated?.mitreAttack?.status, 'mapped');
assert.strictEqual(retrievedUpdated?.mitreAttack?.primaryTechnique?.techniqueId, 'T1566');
assert.strictEqual(retrievedUpdated?.mitreAttack?.primaryTechnique?.subTechniqueId, 'T1566.002');
console.log('✔ TEST J PASSED: MITRE ATT&CK techniques survive persistence completely');

// K. Attack DNA survives persistence
console.log('\n[TEST K] Attack DNA survives persistence');
assert.ok(retrievedUpdated?.attackDNA?.traits, 'Attack DNA traits must exist');
assert.strictEqual(retrievedUpdated?.attackDNA?.traits.length, 2);
assert.strictEqual(retrievedUpdated?.attackDNA?.traits[0].key, 'urgency');
console.log('✔ TEST K PASSED: Attack DNA traits survive persistence');

// L. Evidence survives persistence
console.log('\n[TEST L] Evidence survives persistence');
assert.strictEqual(retrievedUpdated?.evidence.length, 2);
assert.strictEqual(retrievedUpdated?.evidence[0].id, 'EV-001');
assert.strictEqual(retrievedUpdated?.evidence[0].defangedValue, 'hxxps://auth.bank-alert[.]com/login');
console.log('✔ TEST L PASSED: Evidence array and defanged values survive persistence');

// M. Compare two stored investigations
console.log('\n[TEST M] Compare two stored investigations');
const invA = getInvestigation('inv-test-001', db);
const invB = getInvestigation('inv-test-002', db);
assert.ok(invA && invB, 'Both investigations must exist for comparison');
const comparison = {
  verdicts: [invA.threatAssessment.verdict, invB.threatAssessment.verdict],
  scores: [invA.threatAssessment.riskScore, invB.threatAssessment.riskScore],
  types: [invA.input.sourceType, invB.input.sourceType],
  mitreStatus: [invA.mitreAttack?.status, invB.mitreAttack?.status]
};
assert.deepStrictEqual(comparison.verdicts, ['phishing', 'safe']);
assert.deepStrictEqual(comparison.scores, [92, 0]);
assert.deepStrictEqual(comparison.types, ['email', 'image']);
assert.deepStrictEqual(comparison.mitreStatus, ['mapped', 'unmapped']);
console.log('✔ TEST M PASSED: Stored investigations compare cleanly on factual fields');

// N. Restart backend / Re-open database verification
console.log('\n[TEST N] Restart backend and verify stored investigation still exists');
db.close();

// Re-open brand new connection to the same file
const reOpenedDb = new Database(testDbPath);
const persistedAfterRestart = getInvestigation('inv-test-001', reOpenedDb);
assert.ok(persistedAfterRestart, 'Investigation must survive database close & re-open');
assert.strictEqual(persistedAfterRestart?.analysisId, 'inv-test-001');
assert.strictEqual(persistedAfterRestart?.threatAssessment.riskScore, 92);
reOpenedDb.close();

// Cleanup test file
if (fs.existsSync(testDbPath)) {
  fs.unlinkSync(testDbPath);
}
console.log('✔ TEST N PASSED: Persistence verified across database connection restarts');

console.log('\n===========================================');
console.log('ALL 14 DATABASE TESTS PASSED (A through N)!');
console.log('===========================================');
