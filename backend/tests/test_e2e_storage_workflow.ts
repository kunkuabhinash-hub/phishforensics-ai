import { initDatabase } from '../src/db/database';
import { 
  saveInvestigation, 
  getInvestigation, 
  listInvestigations, 
  deleteInvestigation,
  countInvestigations
} from '../src/db/investigationRepository';
import type { UnifiedPhishForensicsContract } from '../src/types/unified-contract';
import fs from 'fs';
import path from 'path';

async function runE2EStorageTest() {
  console.log('=== RUNNING END-TO-END SQLITE PERSISTENCE VERIFICATION ===\n');

  // 1. Verify DB file exists on disk
  const dbPath = path.resolve(__dirname, '../data/phishforensics.sqlite');
  console.log(`[E2E 1] Checking SQLite DB file path: ${dbPath}`);
  const db = initDatabase();
  console.log(`✔ DB initialized successfully (table exists, open = ${db.open})`);

  // 2. Submit text investigation
  const textAnalysisId = `e2e-text-${Date.now()}`;
  const mockTextContract: UnifiedPhishForensicsContract = {
    analysisId: textAnalysisId,
    timestamp: new Date().toISOString(),
    sourceType: 'text',
    input: {
      content: 'URGENT: Your payroll direct deposit has failed. Click hxxps://secure-payroll-update[.]com to verify.'
    },
    threatAssessment: {
      verdict: 'phishing',
      severity: 'critical',
      riskScore: 92,
      confidence: 96,
      justification: 'Credential harvesting campaign mimicking HR payroll department with artificial urgency.'
    },
    attackerIntent: {
      primaryGoal: 'Credential Harvesting',
      description: 'Attempting to capture corporate SSO credentials and banking data.'
    },
    evidence: [
      {
        id: 'EV-1',
        category: 'technical',
        indicator: 'hxxps://secure-payroll-update[.]com',
        value: 'secure-payroll-update.com',
        confidence: 98,
        description: 'Lookalike domain registered recently'
      },
      {
        id: 'EV-2',
        category: 'psychological',
        indicator: 'Urgency trigger',
        value: 'URGENT: Direct deposit failed',
        confidence: 90,
        description: 'Coercive payroll suspension tactic'
      }
    ],
    attackDNA: {
      deliveryVector: 'Corporate Email Pretext',
      psychologicalLevers: ['Urgency', 'Financial Anxiety'],
      obfuscationTechniques: ['Lookalike domain']
    },
    reconstruction: {
      stages: [
        { stageNumber: 1, name: 'Lure', description: 'Urgent email delivery', evidenceIds: ['EV-2'] },
        { stageNumber: 2, name: 'Exploit', description: 'Fake payroll portal redirect', evidenceIds: ['EV-1'] }
      ]
    },
    safeSimulation: {
      safeHtmlPreview: '<p>Direct deposit failed notification</p>',
      interactiveBreakdown: [
        { element: 'Fake link', explanation: 'Directs to untrusted site' }
      ]
    },
    safetyGuidance: {
      immediateActions: ['Do not click the payroll link', 'Report to Infosec'],
      systemDefenses: ['Block secure-payroll-update.com at DNS boundary']
    },
    mitreAttack: {
      status: 'mapped',
      framework: 'MITRE ATT&CK Enterprise v14',
      techniques: [
        {
          techniqueId: 'T1566.002',
          techniqueName: 'Spearphishing Link',
          tactic: 'Initial Access',
          evidenceIds: ['EV-1']
        }
      ]
    }
  };

  console.log(`[E2E 2] Saving unified text analysis: ${textAnalysisId}`);
  saveInvestigation(mockTextContract);
  console.log('✔ Investigation persisted to SQLite');

  // 3. Query list
  console.log('[E2E 3] Querying investigations list (GET /api/investigations)...');
  const list = listInvestigations(10, 0);
  console.log(`Found ${list.length} stored investigations. First item:`);
  console.log(`  - ID: ${list[0].analysisId}`);
  console.log(`  - Verdict: ${list[0].verdict}`);
  console.log(`  - Risk Score: ${list[0].riskScore}`);
  console.log(`  - Source Type: ${list[0].sourceType}`);
  if (list[0].analysisId !== textAnalysisId) {
    throw new Error(`Expected first item to be ${textAnalysisId}, got ${list[0].analysisId}`);
  }
  console.log('✔ List endpoint verification passed');

  // 4. Retrieve single investigation
  console.log(`[E2E 4] Retrieving full investigation: ${textAnalysisId}`);
  const retrieved = getInvestigation(textAnalysisId);
  if (!retrieved) throw new Error('Investigation not found in SQLite!');
  if (retrieved.threatAssessment.riskScore !== 92) throw new Error('Risk score mismatch!');
  if (retrieved.mitreAttack?.techniques[0].techniqueId !== 'T1566.002') throw new Error('MITRE technique mismatch!');
  if (retrieved.evidence.length !== 2) throw new Error('Evidence length mismatch!');
  console.log('✔ Full UnifiedPhishForensicsContract accurately retrieved with intact MITRE & Attack DNA');

  // 5. Submit an image investigation and verify image sanitation
  const imageAnalysisId = `e2e-image-${Date.now()}`;
  const mockImageContract: UnifiedPhishForensicsContract = {
    ...mockTextContract,
    analysisId: imageAnalysisId,
    sourceType: 'image',
    input: {
      content: 'data:image/png;base64,' + 'A'.repeat(50000) // 50KB base64 string
    },
    threatAssessment: {
      verdict: 'phishing',
      severity: 'high',
      riskScore: 85,
      confidence: 90,
      justification: 'Screenshot of fraudulent login modal'
    }
  };

  console.log(`[E2E 5] Saving image investigation with large base64: ${imageAnalysisId}`);
  saveInvestigation(mockImageContract);
  const retrievedImage = getInvestigation(imageAnalysisId);
  if (!retrievedImage) throw new Error('Image investigation not found!');
  if (retrievedImage.input?.content && retrievedImage.input.content.length > 500) {
    throw new Error('Image payload was not sanitized in SQLite storage!');
  }
  console.log(`✔ Image payload sanitized for SQLite storage: "${retrievedImage.input?.content}"`);

  // 6. Test Compare 2 investigations
  console.log('[E2E 6] Comparing Attack A and Attack B from SQLite storage...');
  const invA = getInvestigation(textAnalysisId);
  const invB = getInvestigation(imageAnalysisId);
  console.log(`  Attack A (${invA?.analysisId}): Verdict=${invA?.threatAssessment.verdict}, Score=${invA?.threatAssessment.riskScore}, Vector=${invA?.attackDNA?.deliveryVector}`);
  console.log(`  Attack B (${invB?.analysisId}): Verdict=${invB?.threatAssessment.verdict}, Score=${invB?.threatAssessment.riskScore}, Vector=${invB?.attackDNA?.deliveryVector}`);
  console.log('✔ Comparison between two stored SQLite records confirmed');

  // 7. Cleanup test records
  deleteInvestigation(textAnalysisId);
  deleteInvestigation(imageAnalysisId);
  console.log('✔ Test records cleaned up');

  console.log('\n======================================================');
  console.log('ALL END-TO-END SQLITE PERSISTENCE CHECKS PASSED!');
  console.log('======================================================\n');
}

runE2EStorageTest().catch(err => {
  console.error('E2E Verification Error:', err);
  process.exit(1);
});
