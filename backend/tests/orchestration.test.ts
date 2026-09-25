/**
 * PhishForensics AI - Orchestration Pipeline Tests
 * 
 * Verifies that the orchestration pipeline successfully connects ThreatAnalysis ->
 * DNA -> Reconstruction -> Simulation -> Guidance into a CompleteReconstructionResult.
 * 
 * Tests serialization, determinism, and correctness of outputs.
 */

import test from "node:test";
import assert from "node:assert";

import { buildCompleteReconstruction } from "../services/orchestration/index.ts";
import {
  credentialTargetingFixture,
  financialFraudFixture,
  impersonationSocialEngineeringFixture,
  lowInformationOrBenignFixture
} from "./fixtures/reconstruction-fixtures.ts";

test("Integration Pipeline: Serializability and Completeness (Credential Scenario)", () => {
    const result = buildCompleteReconstruction(credentialTargetingFixture);

    // Verify all components exist
    assert.ok(result.version);
    assert.ok(result.resultId);
    assert.ok(result.generatedAt);
    assert.ok(result.threatAnalysis);
    assert.ok(result.attackDNA);
    assert.ok(result.attackReconstruction);
    assert.ok(result.safeSimulation);
    assert.ok(result.safetyGuidance);

    // Verify serializability
    const stringified = JSON.stringify(result);
    const parsed = JSON.parse(stringified);

    assert.strictEqual(parsed.resultId, result.resultId, "Should survive JSON serialization");
    assert.strictEqual(parsed.attackReconstruction.totalStages, result.attackReconstruction.totalStages);
    assert.strictEqual(
        parsed.attackDNA.categorizedTraits.credentialTargeting.present, 
        true
    );
});

test("Integration Pipeline: Different Inputs Produce Meaningfully Different Outputs", () => {
    const credResult = buildCompleteReconstruction(credentialTargetingFixture);
    const becResult = buildCompleteReconstruction(financialFraudFixture);
    const smishResult = buildCompleteReconstruction(impersonationSocialEngineeringFixture);

    // Check DNA differs
    assert.notStrictEqual(
        credResult.attackDNA.deliveryVector,
        smishResult.attackDNA.deliveryVector,
        "Delivery vectors must differ"
    );

    // Check Reconstruction differs
    assert.notStrictEqual(
        credResult.attackReconstruction.attackerObjective.primaryObjective,
        becResult.attackReconstruction.attackerObjective.primaryObjective,
        "Objectives must differ"
    );

    // Check Guidance differs based on grounded traits
    const credGuidanceStrings = JSON.stringify(credResult.safetyGuidance);
    const becGuidanceStrings = JSON.stringify(becResult.safetyGuidance);
    assert.notStrictEqual(credGuidanceStrings, becGuidanceStrings, "Safety guidance must be tailored");
    
    assert.ok(credGuidanceStrings.includes("credential"), "Cred guidance should mention credentials");
    assert.ok(becGuidanceStrings.includes("wire") || becGuidanceStrings.includes("financial"), "BEC guidance should mention financial/wire");
});

test("Integration Pipeline: Benign Input Does Not Invent Attacks", () => {
    const result = buildCompleteReconstruction(lowInformationOrBenignFixture);

    // Verify DNA is mostly empty
    const traits = result.attackDNA.traits.filter(t => t.present);
    assert.strictEqual(traits.length, 0, "Benign input should not have active hostile traits");

    // Verify Reconstruction is single-stage inspection
    assert.strictEqual(result.attackReconstruction.totalStages, 1);
    assert.strictEqual(result.attackReconstruction.stages[0].phaseCategory, "inspection");

    // Verify Simulation is safe and zero-decision
    assert.strictEqual(result.safeSimulation.totalDecisionPoints, 0);

    // Verify Guidance is standard
    assert.strictEqual(result.safetyGuidance.immediateActions[0].priority, "standard");
    assert.ok(result.safetyGuidance.summary.includes("No malicious activity detected"));
});
