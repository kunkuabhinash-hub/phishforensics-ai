/**
 * PhishForensics AI - Attack Reconstruction Unit & Development Tests
 * 
 * Verifies that the dynamic reconstruction engine:
 * 1. Correctly handles Credential-targeting analysis
 * 2. Correctly handles Financial-fraud analysis
 * 3. Correctly handles Impersonation / Social-engineering analysis
 * 4. Correctly handles Low-information or benign analysis
 * 5. Changes stage count, titles, and evidence dynamically based strictly on input data
 * 6. Avoids inventing unsupported stages or fixed hardcoded attack paths
 */

import test from "node:test";
import assert from "node:assert";

import { reconstructAttack, AttackReconstructionEngine } from "../services/reconstruction/attack-reconstruction-engine.ts";
import { extractAttackDNA } from "../services/reconstruction/trait-extractor.ts";
import {
  credentialTargetingFixture,
  financialFraudFixture,
  impersonationSocialEngineeringFixture,
  lowInformationOrBenignFixture
} from "./fixtures/reconstruction-fixtures.ts";

test("Category 1: Credential-Targeting Analysis Reconstructs Multi-Stage Flow with Grounded Evidence", () => {
  const reconstruction = reconstructAttack(credentialTargetingFixture);
  const dna = extractAttackDNA(credentialTargetingFixture);

  // 1. Attacker objective derived from input intent
  assert.strictEqual(
    reconstruction.attackerObjective.primaryObjective,
    "Harvest Enterprise SSO Credentials",
    "Objective must come from supplied attackerIntent"
  );
  assert.strictEqual(
    reconstruction.attackerObjective.secondaryObjectives?.length,
    2,
    "Secondary objectives must be captured"
  );

  // 2. Dynamic multi-stage formation (Delivery -> Infrastructure -> Manipulation -> Objective)
  assert.ok(
    reconstruction.totalStages >= 3,
    `Credential attack with link must construct multi-stage kill chain, got ${reconstruction.totalStages}`
  );
  assert.strictEqual(reconstruction.stages.length, reconstruction.totalStages);

  // 3. Sequential ordering
  reconstruction.stages.forEach((stage, idx) => {
    assert.strictEqual(stage.sequenceOrder, idx + 1, "Stages must have continuous 1-based sequenceOrder");
    assert.ok(stage.stageTitle.length > 0, "Stage must have non-empty title");
    assert.ok(stage.stageDescription.length > 0, "Stage must have non-empty description");
    assert.ok(stage.possibleConsequence.shortImpact.length > 0, "Stage must have consequence impact");
  });

  // 4. Evidence grounding: Delivery stage must reference header evidence, Infrastructure stage must reference link
  const allAttachedEvidence = reconstruction.stages.flatMap(s => s.supportingEvidence);
  const evidenceIds = allAttachedEvidence.map(e => e.evidenceId).filter(Boolean);

  assert.ok(
    evidenceIds.includes("ev_hdr_01"),
    "Reconstruction must link header evidence 'ev_hdr_01'"
  );
  assert.ok(
    evidenceIds.includes("ev_lnk_01"),
    "Reconstruction must link destination URL evidence 'ev_lnk_01'"
  );

  // 5. DNA Traits correlated
  assert.ok(dna.categorizedTraits.credentialTargeting?.present, "Credential targeting trait must be present");
  assert.ok(dna.categorizedTraits.impersonation?.present, "Impersonation trait must be present");
  assert.ok(dna.categorizedTraits.urgency?.present, "Urgency trait must be present");
  assert.strictEqual(dna.deliveryVector, "email_link_phish", "Delivery vector must identify link phish");

  // Verify stage traits link back to DNA
  const allStageTraits = reconstruction.stages.flatMap(s => s.relevantTraits);
  assert.ok(allStageTraits.includes("credentialTargeting"), "Stage traits must include credentialTargeting");
});

test("Category 2: Financial-Fraud BEC Analysis OMITs Intermediate Infrastructure Stage", () => {
  const reconstruction = reconstructAttack(financialFraudFixture);
  const dna = extractAttackDNA(financialFraudFixture);

  // 1. Attacker objective derived from input intent
  assert.strictEqual(
    reconstruction.attackerObjective.primaryObjective,
    "Direct Financial Wire Fraud",
    "Objective must come from supplied attackerIntent"
  );

  // 2. BEC has NO links, NO domains, NO attachments -> Must NOT construct an infrastructure redirection stage!
  const hasInfrastructureStage = reconstruction.stages.some(s =>
    s.phaseCategory === "redirection" || s.phaseCategory === "infrastructure"
  );
  assert.strictEqual(
    hasInfrastructureStage,
    false,
    "BEC attack with zero links or attachments must NOT have an infrastructure redirection stage"
  );

  // 3. Stage count must differ dynamically from the credential phish
  assert.ok(
    reconstruction.totalStages > 0 && reconstruction.totalStages <= 3,
    `BEC flow should have compact stages (got ${reconstruction.totalStages})`
  );

  // 4. Evidence grounding: References BEC header and body snippets
  const allAttachedEvidence = reconstruction.stages.flatMap(s => s.supportingEvidence);
  const snippets = allAttachedEvidence.map(e => e.snippet).filter(Boolean);
  assert.ok(
    snippets.some(s => s?.includes("$95,000")),
    "Reconstruction must ground evidence in the actual wire amount snippet"
  );

  // 5. DNA Traits
  assert.ok(dna.categorizedTraits.financialTargeting?.present, "Financial targeting trait must be present");
  assert.ok(dna.categorizedTraits.authority?.present, "Authority coercion trait must be present");
  assert.strictEqual(
    dna.categorizedTraits.credentialTargeting?.present,
    undefined,
    "Credential targeting must NOT be present in pure financial wire fraud"
  );
});

test("Category 3: Impersonation / Social-Engineering Smishing Reconstructs SMS Vector", () => {
  const reconstruction = reconstructAttack(impersonationSocialEngineeringFixture);
  const dna = extractAttackDNA(impersonationSocialEngineeringFixture);

  // 1. Delivery vector reflects SMS medium
  assert.strictEqual(dna.deliveryVector, "sms_smishing", "Delivery vector must be sms_smishing");

  // 2. Stage title incorporates SMS context and brand
  const deliveryStage = reconstruction.stages[0];
  assert.ok(
    deliveryStage.stageTitle.toLowerCase().includes("sms") || deliveryStage.stageTitle.toLowerCase().includes("fedex"),
    `Stage title must reflect SMS/FedEx context: ${deliveryStage.stageTitle}`
  );

  // 3. Grounded evidence references SMS link
  const allAttachedEvidence = reconstruction.stages.flatMap(s => s.supportingEvidence);
  const evidenceIds = allAttachedEvidence.map(e => e.evidenceId).filter(Boolean);
  assert.ok(evidenceIds.includes("ev_sms_lnk"), "Must link SMS evidence ev_sms_lnk");

  // 4. Consequence severity matches medium risk
  const finalStage = reconstruction.stages[reconstruction.stages.length - 1];
  assert.strictEqual(
    finalStage.possibleConsequence.severity,
    "medium",
    "Consequence severity must match input risk level"
  );
});

test("Category 4: Low-Information / Benign Analysis Avoids Inventing Adversary Stages", () => {
  const reconstruction = reconstructAttack(lowInformationOrBenignFixture);
  const dna = extractAttackDNA(lowInformationOrBenignFixture);

  // 1. Does NOT invent multi-stage kill chains
  assert.strictEqual(
    reconstruction.totalStages,
    1,
    "Benign/low-information analysis must only produce 1 baseline inspection stage, not an artificial kill chain"
  );

  const stage = reconstruction.stages[0];
  assert.strictEqual(stage.phaseCategory, "inspection");
  assert.ok(
    stage.stageDescription.toLowerCase().includes("no active indicators") ||
    stage.stageDescription.toLowerCase().includes("authentic"),
    "Stage description must honestly communicate absence of attack indicators"
  );
  assert.strictEqual(
    stage.possibleConsequence.severity,
    "low",
    "Consequence must be low severity"
  );
  assert.strictEqual(
    stage.possibleConsequence.affectedAssets?.length,
    0,
    "No compromised assets should be reported"
  );

  // 2. DNA reflects absence of hostile traits
  assert.strictEqual(dna.traits.filter(t => t.present).length, 0, "No hostile traits should be flagged");
});

test("Category 5: Data-Driven Dynamism Proves Different Inputs Produce Structurally Distinct Reconstructions", () => {
  const credRec = reconstructAttack(credentialTargetingFixture);
  const becRec = reconstructAttack(financialFraudFixture);
  const smishRec = reconstructAttack(impersonationSocialEngineeringFixture);
  const benignRec = reconstructAttack(lowInformationOrBenignFixture);

  // 1. All produce different stage counts
  const stageCounts = new Set([
    credRec.totalStages,
    becRec.totalStages,
    smishRec.totalStages,
    benignRec.totalStages
  ]);
  assert.ok(
    stageCounts.size >= 3,
    `Expected at least 3 distinct stage counts across diverse inputs, got ${stageCounts.size} distinct counts`
  );

  // 2. Stage titles are distinct and derived from respective data
  const credTitles = credRec.stages.map(s => s.stageTitle).join(" | ");
  const becTitles = becRec.stages.map(s => s.stageTitle).join(" | ");
  assert.notStrictEqual(credTitles, becTitles, "Stage titles must differ fundamentally between attack types");

  // 3. Attacker objectives are distinct and not hardcoded
  assert.notStrictEqual(
    credRec.attackerObjective.primaryObjective,
    becRec.attackerObjective.primaryObjective,
    "Objectives must vary according to input"
  );

  // 4. Summaries are dynamically generated
  assert.ok(credRec.attackFlowSummary.includes(credRec.attackerObjective.primaryObjective));
  assert.ok(becRec.attackFlowSummary.includes(becRec.attackerObjective.primaryObjective));
});
