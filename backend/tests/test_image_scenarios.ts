import 'dotenv/config';
import fs from 'fs';
import assert from 'node:assert';
import AnalyzeService from '../src/services/analyzeService.js';

async function testScenario(name: string, filePathOrData: string, isRawDataUrl = false) {
  console.log(`\n==================================================`);
  console.log(`RUNNING ${name}`);
  console.log(`==================================================`);

  let dataUrl = filePathOrData;
  if (!isRawDataUrl) {
    const buffer = fs.readFileSync(filePathOrData);
    dataUrl = `data:image/png;base64,${buffer.toString('base64')}`;
  }

  const analysisId = `test-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`;
  const input = {
    analysisId,
    type: 'image',
    content: dataUrl,
    source: 'automated_test',
    timestamp: new Date().toISOString()
  };

  const result = await AnalyzeService.processUnifiedContent(analysisId, input);

  console.log(`Verdict: ${result.threatAssessment.verdict}`);
  console.log(`Severity: ${result.threatAssessment.severity}`);
  console.log(`Risk Score: ${result.threatAssessment.riskScore}`);
  console.log(`Confidence: ${result.threatAssessment.confidence}%`);
  console.log(`Justification: ${result.threatAssessment.justification}`);
  console.log(`Evidence count: ${result.evidence.length}`);
  console.log(`MITRE status: ${result.mitreAttack?.status}`);

  return result;
}

import path from 'path';

async function runAll() {
  const fixturesDir = path.join(__dirname, 'fixtures');
  const getFixture = (name: string) => fs.existsSync(path.join(fixturesDir, name)) ? path.join(fixturesDir, name) : name;

  // TEST A: Clearly readable phishing screenshot
  const resultA = await testScenario('TEST A: Readable Phishing Screenshot', getFixture('test_phish.png'));
  assert.ok(['phishing', 'suspicious'].includes(resultA.threatAssessment.verdict), 'Test A verdict should be phishing or suspicious');
  assert.ok(typeof resultA.threatAssessment.riskScore === 'number' && resultA.threatAssessment.riskScore >= 70, 'Test A risk score should be high numeric');
  assert.ok(resultA.threatAssessment.confidence >= 80, 'Test A confidence should be high');
  assert.ok(resultA.evidence.length >= 1, 'Test A should have extracted evidence');
  console.log('✔ TEST A PASSED');

  // TEST B: Benign screenshot
  const resultB = await testScenario('TEST B: Clearly Benign Screenshot', getFixture('test_benign.png'));
  assert.ok(['safe', 'unknown'].includes(resultB.threatAssessment.verdict), 'Test B verdict should be safe or unknown');
  if (resultB.threatAssessment.riskScore !== null) {
    assert.ok(resultB.threatAssessment.riskScore <= 30, 'Test B risk score should be low if numeric');
  }
  console.log('✔ TEST B PASSED');

  // TEST C: Blank / irrelevant image
  const resultC = await testScenario('TEST C: Blank / Irrelevant Image', getFixture('test_blank.png'));
  assert.ok(['safe', 'unknown'].includes(resultC.threatAssessment.verdict), 'Test C verdict should be unknown or safe');
  assert.ok(resultC.threatAssessment.riskScore === null || resultC.threatAssessment.riskScore <= 20, 'Test C risk score should be null or minimal');
  console.log('✔ TEST C PASSED');

  // TEST D: Corrupted / invalid image binary (Case B Fallback)
  const resultD = await testScenario('TEST D: Corrupted / Invalid Image (Case B Fallback)', 'data:image/png;base64,invalid_corrupt_binary_data', true);
  assert.strictEqual(resultD.threatAssessment.verdict, 'unknown', 'Test D verdict must be unknown for processing failure');
  assert.strictEqual(resultD.threatAssessment.riskScore, null, 'Test D riskScore must be null');
  assert.ok(resultD.threatAssessment.confidence <= 30, 'Test D confidence must be low');
  assert.ok(resultD.threatAssessment.justification.includes('Image processing failure') || resultD.threatAssessment.justification.includes('failure'), 'Test D must explicitly note image processing failure');
  assert.strictEqual(resultD.mitreAttack?.status, 'unmapped', 'Test D mitre must be unmapped');
  console.log('✔ TEST D PASSED');

  console.log('\n==================================================');
  console.log('ALL IMAGE PIPELINE SCENARIO TESTS PASSED!');
  console.log('==================================================');
}

runAll().catch(err => {
  console.error('Test Suite Failed:', err);
  process.exit(1);
});
