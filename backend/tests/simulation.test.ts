/**
 * PhishForensics AI - Safe Simulation Engine Tests
 * 
 * Verifies that the safe simulation engine correctly maps dynamically generated
 * attack reconstructions into safe, non-executable, deterministic educational state machines.
 */

import test from "node:test";
import assert from "node:assert";

import { reconstructAttack } from "../services/reconstruction/attack-reconstruction-engine.ts";
import { generateSimulation } from "../services/simulation/safe-simulation-engine.ts";
import {
  credentialTargetingFixture,
  financialFraudFixture,
  impersonationSocialEngineeringFixture,
  lowInformationOrBenignFixture
} from "./fixtures/reconstruction-fixtures.ts";

test("Category 1: Credential-Targeting Simulation Maps Stages to Interactive States", () => {
  const reconstruction = reconstructAttack(credentialTargetingFixture);
  const simulation = generateSimulation(reconstruction);

  // 1. Core simulation properties exist
  assert.ok(simulation.title.includes("Harvest Enterprise SSO Credentials"));
  assert.strictEqual(simulation.totalDecisionPoints, reconstruction.totalStages);
  assert.ok(simulation.safetyDisclaimer.length > 0);

  // 2. State machine covers all stages plus terminal states
  // We expect: stages.length (decision states) + 2 (safe terminal, compromise terminal)
  const expectedStateCount = reconstruction.totalStages + 2;
  const stateKeys = Object.keys(simulation.states);
  assert.strictEqual(stateKeys.length, expectedStateCount);

  // 3. Initial state links to the first stage correctly
  const initialStageId = reconstruction.stages[0].stageId;
  assert.strictEqual(simulation.initialStateId, `state_${initialStageId}`);

  // 4. Verify choices structure within a decision state
  const initialState = simulation.states[simulation.initialStateId];
  assert.strictEqual(initialState.isTerminal, false);
  assert.strictEqual(initialState.availableChoices.length, 2);

  const safeChoice = initialState.availableChoices.find(c => c.isRecommendedAction);
  const vulnChoice = initialState.availableChoices.find(c => !c.isRecommendedAction);
  
  assert.ok(safeChoice, "Must provide a recommended safe choice");
  assert.ok(vulnChoice, "Must provide a vulnerable choice for learning");
  assert.strictEqual(safeChoice.nextStateId, "state_safe_terminal");

  // 5. Verify transition to next stage
  const nextStageId = reconstruction.stages[1].stageId;
  assert.strictEqual(vulnChoice.nextStateId, `state_${nextStageId}`);
});

test("Category 2: Financial-Fraud BEC Simulation Adapts to Shorter Attack Path", () => {
  const reconstruction = reconstructAttack(financialFraudFixture);
  const simulation = generateSimulation(reconstruction);

  assert.strictEqual(simulation.totalDecisionPoints, reconstruction.totalStages);

  // Trace the vulnerable path to the end
  let currentState = simulation.states[simulation.initialStateId];
  let decisionCount = 0;
  
  while (!currentState.isTerminal && decisionCount < 10) {
      decisionCount++;
      const vulnChoice = currentState.availableChoices.find(c => !c.isRecommendedAction);
      assert.ok(vulnChoice, "Must find vulnerable choice");
      currentState = simulation.states[vulnChoice.nextStateId];
  }
  
  // Should end in compromise terminal state after tracing all stages
  assert.strictEqual(currentState.stateId, "state_compromise_terminal");
  assert.strictEqual(decisionCount, reconstruction.totalStages);
});

test("Category 3: Benign/Low-Info Analysis Creates Non-Interactive Safe Flow", () => {
  const reconstruction = reconstructAttack(lowInformationOrBenignFixture);
  const simulation = generateSimulation(reconstruction);

  assert.strictEqual(simulation.totalDecisionPoints, 0, "Benign simulation should have 0 decision points");
  assert.strictEqual(simulation.title, "Safe Interaction Simulation");
  
  const stateKeys = Object.keys(simulation.states);
  assert.strictEqual(stateKeys.length, 1, "Should only have one state for benign");
  
  const initialState = simulation.states[simulation.initialStateId];
  assert.strictEqual(initialState.isTerminal, true, "Benign state should be terminal immediately");
  assert.strictEqual(initialState.availableChoices.length, 0, "No choices needed for benign state");
});
