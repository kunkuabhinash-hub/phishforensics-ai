/**
 * PhishForensics AI - Dynamic Attack Reconstruction Engine
 * 
 * Reconstructs a grounded, variable-length attack sequence and kill-chain flow
 * based strictly on dynamic threat analysis findings.
 * 
 * Design Principles:
 * - Data-Driven: Consumes structured ThreatAnalysisInput without hardcoded rules.
 * - Dynamic Stages: Generates variable-length stages matching observed techniques.
 * - Evidence Grounded: Links every stage to real evidence items and indicators from input.
 * - DNA Aligned: Correlates relevant Attack DNA traits to each reconstructed phase.
 * - Safe & Non-Executable: Purely analytical reasoning with zero active execution.
 */

import type {
  ThreatAnalysisInput,
  AttackReconstruction,
  ReconstructionStage,
  StageEvidence,
  StageConsequence,
  AttackerObjective
} from "../../../shared/types/index.ts";

import { extractTraits } from "./trait-extractor.ts";

export class AttackReconstructionEngine {
  /**
   * Reconstructs the end-to-end attack progression from dynamic threat analysis findings.
   */
  public reconstruct(input: ThreatAnalysisInput): AttackReconstruction {
    // 1. Identify Attacker Objective from ThreatAnalysisInput
    const attackerObjective = this.deriveAttackerObjective(input);

    // 2. Identify Relevant Attack Characteristics (Traits)
    const { traits, categorized } = extractTraits(input);
    const activeTraitKeys = traits.filter(t => t.present).map(t => t.key);

    // 3. Evaluate whether input contains sufficient adversarial findings
    const isBenignOrMinimal = this.isLowInformationOrBenign(input);

    let stages: ReconstructionStage[] = [];

    if (isBenignOrMinimal) {
      // For benign/low-information findings, do not invent unsupported attack stages
      stages = this.buildBenignOrMinimalStages(input);
    } else {
      // Build variable-length attack stages dynamically from evidence & techniques
      stages = this.buildDynamicStages(input, activeTraitKeys, categorized);
    }

    // 4. Synthesize overall attack flow summary
    const attackFlowSummary = this.generateFlowSummary(stages, attackerObjective, isBenignOrMinimal);

    return {
      reconstructionId: `rec_${input.analysisId || Date.now().toString(36)}`,
      attackerObjective,
      stages,
      totalStages: stages.length,
      attackFlowSummary,
      metadata: {
        sourceAnalysisId: input.analysisId,
        sourceType: input.sourceType,
        riskLevel: input.riskInformation?.level,
        activeTraitsCount: activeTraitKeys.length,
        evidenceAttachedCount: stages.reduce((acc, s) => acc + s.supportingEvidence.length, 0)
      }
    };
  }

  /**
   * Extracts attacker objectives directly from supplied threat analysis intent.
   */
  private deriveAttackerObjective(input: ThreatAnalysisInput): AttackerObjective {
    const intent = input.attackerIntent;
    const primaryObjective = intent?.primaryGoal || "Undetermined Objective";
    const secondaryObjectives = intent?.secondaryGoals || [];
    const strategicGoal = intent?.description || undefined;

    return {
      primaryObjective,
      secondaryObjectives,
      strategicGoal
    };
  }

  /**
   * Checks whether the analysis reflects benign or low-information content.
   */
  private isLowInformationOrBenign(input: ThreatAnalysisInput): boolean {
    const riskLevel = (input.riskInformation?.level || "").toLowerCase();
    const hasLowRisk = riskLevel === "none" || riskLevel === "low" || riskLevel === "benign";
    const indicatorCount = input.indicators?.length || 0;
    const techniqueCount = input.manipulationTechniques?.length || 0;

    // If there are zero indicators and zero manipulation techniques with low risk
    if (indicatorCount === 0 && techniqueCount === 0 && hasLowRisk) {
      return true;
    }

    // If primary goal explicitly states benign or no threat
    const primaryGoal = (input.attackerIntent?.primaryGoal || "").toLowerCase();
    if (primaryGoal.includes("benign") || primaryGoal.includes("legitimate") || primaryGoal.includes("no threat")) {
      return true;
    }

    return false;
  }

  /**
   * Builds honest, single-stage representation for benign or low-information content.
   */
  private buildBenignOrMinimalStages(input: ThreatAnalysisInput): ReconstructionStage[] {
    const medium = input.sourceType ? input.sourceType.toUpperCase() : "Message";
    const evidence: StageEvidence[] = (input.evidence || []).map(ev => ({
      evidenceId: ev.id,
      summary: ev.finding,
      snippet: ev.rawSnippet,
      source: ev.type
    }));

    const stage: ReconstructionStage = {
      stageId: "stage_benign_evaluation",
      sequenceOrder: 1,
      stageTitle: `${medium} Verification & Baseline Inspection`,
      stageDescription: input.riskInformation?.assessment ||
        "Analysis of the content found no active indicators of deception, credential harvesting, or adversary kill-chain progression.",
      phaseCategory: "inspection",
      supportingEvidence: evidence,
      possibleConsequence: {
        shortImpact: "No adversarial compromise indicated",
        detailedConsequence: "The artifact exhibits standard communication patterns without substantiating an active attack flow.",
        severity: input.riskInformation?.level || "low",
        affectedAssets: []
      },
      relevantTraits: [],
      mechanism: "Standard communication / No exploit observed"
    };

    return [stage];
  }

  /**
   * Constructs variable-length stages dynamically from the supplied analysis.
   */
  private buildDynamicStages(
    input: ThreatAnalysisInput,
    activeTraitKeys: string[],
    categorizedTraits: Record<string, unknown>
  ): ReconstructionStage[] {
    const stages: ReconstructionStage[] = [];
    let sequenceCounter = 1;

    // Stage 1: Pretext & Delivery (Always exists if communication or lure is present)
    const deliveryStage = this.buildDeliveryStage(input, sequenceCounter++, activeTraitKeys);
    if (deliveryStage) {
      stages.push(deliveryStage);
    }

    // Stage 2: Intermediate Technical Mechanism / Infrastructure (Only if links/domains/attachments exist)
    const infrastructureStage = this.buildInfrastructureStage(input, sequenceCounter++, activeTraitKeys);
    if (infrastructureStage) {
      stages.push(infrastructureStage);
    }

    // Stage 3: Psychological Interaction & Manipulation (Only if active social engineering cues or body evidence exist)
    const manipulationStage = this.buildManipulationStage(input, sequenceCounter++, activeTraitKeys);
    if (manipulationStage) {
      stages.push(manipulationStage);
    }

    // Stage 4: Action on Objective (Final compromise stage derived from attacker intent)
    const objectiveStage = this.buildObjectiveStage(input, sequenceCounter++, activeTraitKeys);
    if (objectiveStage) {
      stages.push(objectiveStage);
    }

    return stages;
  }

  /**
   * Formulates Stage 1: Pretext Delivery.
   */
  private buildDeliveryStage(
    input: ThreatAnalysisInput,
    sequenceOrder: number,
    activeTraitKeys: string[]
  ): ReconstructionStage | null {
    const medium = input.sourceType || "message";
    const impersonatedEntity = (input.entities || []).find(e =>
      e.role?.toLowerCase().includes("impersonat") || e.role?.toLowerCase().includes("sender")
    );
    const senderIndicators = (input.indicators || []).filter(i =>
      i.type?.toLowerCase().includes("sender") ||
      i.type?.toLowerCase().includes("spoof") ||
      i.context?.toLowerCase().includes("header")
    );
    const headerEvidence = (input.evidence || []).filter(ev =>
      ev.type?.toLowerCase().includes("header") ||
      ev.finding?.toLowerCase().includes("spoof") ||
      ev.finding?.toLowerCase().includes("dmarc") ||
      ev.finding?.toLowerCase().includes("spf")
    );

    // Identify active traits relevant to delivery
    const deliveryTraits = activeTraitKeys.filter(k =>
      k === "impersonation" || k === "authority" || k === "urgency"
    );

    const stageTitle = impersonatedEntity
      ? `${impersonatedEntity.name} Pretext & Delivery via ${medium.toUpperCase()}`
      : `Pretext & Lure Delivery via ${medium.toUpperCase()}`;

    let stageDescription = `Adversary initiates contact using ${medium} vector`;
    if (impersonatedEntity) {
      stageDescription += `, masquerading as ${impersonatedEntity.name}`;
    }
    const urgencyTech = (input.manipulationTechniques || []).find(t =>
      t.name?.toLowerCase().includes("urgenc") || t.description?.toLowerCase().includes("urgenc")
    );
    if (urgencyTech) {
      stageDescription += ` while applying time-pressure pretext to compel rapid opening.`;
    } else {
      stageDescription += ` to establish initial deceptive rapport.`;
    }

    const supportingEvidence: StageEvidence[] = [
      ...headerEvidence.map(ev => ({
        evidenceId: ev.id,
        summary: ev.finding,
        snippet: ev.rawSnippet,
        source: ev.type
      })),
      ...senderIndicators.map(ind => ({
        summary: ind.explanation || `${ind.type}: ${ind.value}`,
        snippet: ind.value,
        source: ind.context || "indicator"
      }))
    ];

    const consequence: StageConsequence = {
      shortImpact: "Target is exposed to deceptive pretext",
      detailedConsequence: "Creates an initial illusion of authenticity or urgency, priming the recipient to bypass normal caution.",
      severity: input.riskInformation?.level === "critical" ? "high" : (input.riskInformation?.level || "medium"),
      affectedAssets: ["Employee Attention", "Initial Communication Channel"]
    };

    return {
      stageId: `stage_${sequenceOrder}_delivery`,
      sequenceOrder,
      stageTitle,
      stageDescription,
      phaseCategory: "delivery",
      supportingEvidence,
      possibleConsequence: consequence,
      relevantTraits: deliveryTraits,
      mechanism: impersonatedEntity ? `Identity Spoofing (${impersonatedEntity.name})` : "Direct Communication Lure"
    };
  }

  /**
   * Formulates Stage 2: Technical Mechanism / Intermediate Infrastructure.
   * OMITTED if no external links, domains, or attachments exist in findings.
   */
  private buildInfrastructureStage(
    input: ThreatAnalysisInput,
    sequenceOrder: number,
    activeTraitKeys: string[]
  ): ReconstructionStage | null {
    // Check if findings contain links, domains, or attachments
    const linkIndicators = (input.indicators || []).filter(i =>
      i.type?.toLowerCase().includes("url") ||
      i.type?.toLowerCase().includes("domain") ||
      i.type?.toLowerCase().includes("link") ||
      i.value?.startsWith("http")
    );
    const attachmentIndicators = (input.indicators || []).filter(i =>
      i.type?.toLowerCase().includes("attachment") ||
      i.type?.toLowerCase().includes("file")
    );
    const linkEvidence = (input.evidence || []).filter(ev =>
      ev.type?.toLowerCase().includes("link") ||
      ev.type?.toLowerCase().includes("url") ||
      ev.type?.toLowerCase().includes("attachment")
    );

    // If zero technical redirection/attachment cues exist (e.g. pure BEC wire fraud), return null!
    if (linkIndicators.length === 0 && attachmentIndicators.length === 0 && linkEvidence.length === 0) {
      return null;
    }

    const isAttachment = attachmentIndicators.length > 0;
    const stageTitle = isAttachment
      ? "Adversarial Attachment Delivery & Ingestion"
      : "Redirection to Untrusted External Infrastructure";

    const observedTargets = [
      ...linkIndicators.map(i => i.value),
      ...attachmentIndicators.map(i => i.value)
    ];

    const stageDescription = isAttachment
      ? `Lure prompts user to open an untrusted attachment containing malicious content: ${observedTargets.slice(0, 2).join(", ")}.`
      : `User is steered away from legitimate corporate services toward external adversary infrastructure: ${observedTargets.slice(0, 2).join(", ")}.`;

    const supportingEvidence: StageEvidence[] = [
      ...linkEvidence.map(ev => ({
        evidenceId: ev.id,
        summary: ev.finding,
        snippet: ev.rawSnippet,
        source: ev.type
      })),
      ...linkIndicators.map(ind => ({
        summary: ind.explanation || `Observed destination: ${ind.value}`,
        snippet: ind.value,
        source: ind.context || "link"
      })),
      ...attachmentIndicators.map(ind => ({
        summary: ind.explanation || `Attachment artifact: ${ind.value}`,
        snippet: ind.value,
        source: ind.context || "attachment"
      }))
    ];

    const consequence: StageConsequence = {
      shortImpact: isAttachment ? "Local payload download or execution" : "Navigation to adversary-controlled domain",
      detailedConsequence: isAttachment
        ? "Exposes local workstation to potential malware staging, macro execution, or malicious script execution."
        : "Browser connects to untrusted infrastructure enabling credential harvesting, session interception, or exploit delivery.",
      severity: "high",
      affectedAssets: isAttachment ? ["Endpoint Workstation"] : ["Web Browser Session", "Network Boundary"]
    };

    const infrastructureTraits = activeTraitKeys.filter(k =>
      k === "credentialTargeting" || k === "impersonation" || k === "fear"
    );

    return {
      stageId: `stage_${sequenceOrder}_infrastructure`,
      sequenceOrder,
      stageTitle,
      stageDescription,
      phaseCategory: isAttachment ? "exploitation" : "redirection",
      supportingEvidence,
      possibleConsequence: consequence,
      relevantTraits: infrastructureTraits,
      mechanism: isAttachment ? "File Attachment Download" : "Adversarial URL Redirection"
    };
  }

  /**
   * Formulates Stage 3: Psychological Manipulation & User Interaction.
   * Constructed when social engineering techniques or body content evidence exist.
   */
  private buildManipulationStage(
    input: ThreatAnalysisInput,
    sequenceOrder: number,
    activeTraitKeys: string[]
  ): ReconstructionStage | null {
    const techniques = input.manipulationTechniques || [];
    const bodyEvidence = (input.evidence || []).filter(ev =>
      ev.type?.toLowerCase().includes("body") ||
      ev.type?.toLowerCase().includes("content") ||
      ev.type?.toLowerCase().includes("text")
    );

    if (techniques.length === 0 && bodyEvidence.length === 0) {
      return null;
    }

    const techNames = techniques.length > 0
      ? techniques.map(t => t.name).join(" and ")
      : "Deceptive Body Content";
    const stageTitle = `Exploitation of ${techNames}`;

    let stageDescription = "";
    if (techniques.length > 0) {
      const techniqueDescriptions = techniques.map(t =>
        `${t.name}: ${t.description}${t.evidenceSnippet ? ` ("${t.evidenceSnippet}")` : ""}`
      ).join("; ");
      stageDescription = `Adversary actively exploits psychological pressure points (${techniqueDescriptions}) to induce victim compliance without independent verification.`;
    } else {
      stageDescription = `Content manipulation deployed in body to solicit recipient cooperation.`;
    }

    const supportingEvidence: StageEvidence[] = [
      ...bodyEvidence.map(ev => ({
        evidenceId: ev.id,
        summary: ev.finding,
        snippet: ev.rawSnippet,
        source: ev.type
      })),
      ...techniques
        .filter(t => t.evidenceSnippet)
        .map(t => ({
          summary: `${t.name} deployed in content`,
          snippet: t.evidenceSnippet,
          source: t.category || "manipulation_technique"
        }))
    ];

    const consequence: StageConsequence = {
      shortImpact: "Victim critical thinking and verification procedures overridden",
      detailedConsequence: "The user is psychologically compelled to follow instructions immediately (e.g. submit credentials, wire money, or ignore warning signs).",
      severity: "high",
      affectedAssets: ["Human Decision-Making"]
    };

    const manipulationTraits = activeTraitKeys.filter(k =>
      k === "socialEngineering" || k === "urgency" || k === "fear" || k === "authority"
    );

    return {
      stageId: `stage_${sequenceOrder}_manipulation`,
      sequenceOrder,
      stageTitle,
      stageDescription,
      phaseCategory: "social_engineering",
      supportingEvidence,
      possibleConsequence: consequence,
      relevantTraits: manipulationTraits,
      mechanism: techNames
    };
  }

  /**
   * Formulates Stage 4: Action on Objective (Final Compromise).
   */
  private buildObjectiveStage(
    input: ThreatAnalysisInput,
    sequenceOrder: number,
    activeTraitKeys: string[]
  ): ReconstructionStage {
    const goal = input.attackerIntent?.primaryGoal || "Compromise Objective";
    const stageTitle = `Realization of Objective: ${goal}`;
    const stageDescription = input.attackerIntent?.description ||
      `Attacker successfully accomplishes ${goal}, capitalizing on the prior stages.`;

    const objectiveEvidence: StageEvidence[] = [];
    if (input.riskInformation?.assessment) {
      objectiveEvidence.push({
        summary: input.riskInformation.assessment,
        source: "Risk Assessment"
      });
    }

    // Attach any specific evidence that directly reflects the primary goal
    const goalLower = goal.toLowerCase();
    const relevantEvidence = (input.evidence || []).filter(ev => {
      const findingLower = (ev.finding || "").toLowerCase();
      return (goalLower.includes("wire") && findingLower.includes("payment")) ||
        (goalLower.includes("credential") && findingLower.includes("login")) ||
        findingLower.includes(goalLower);
    });

    for (const ev of relevantEvidence) {
      objectiveEvidence.push({
        evidenceId: ev.id,
        summary: ev.finding,
        snippet: ev.rawSnippet,
        source: ev.type
      });
    }

    const consequence: StageConsequence = {
      shortImpact: `Attacker achieves ${goal}`,
      detailedConsequence: input.riskInformation?.assessment ||
        `Direct security compromise affecting ${(input.riskInformation?.potentialImpact || []).join(", ") || "targeted systems"}.`,
      severity: input.riskInformation?.level || "critical",
      affectedAssets: input.riskInformation?.potentialImpact || ["Corporate Systems"]
    };

    const objectiveTraits = activeTraitKeys.filter(k =>
      k === "credentialTargeting" || k === "financialTargeting"
    );

    return {
      stageId: `stage_${sequenceOrder}_objective`,
      sequenceOrder,
      stageTitle,
      stageDescription,
      phaseCategory: "action_on_objectives",
      supportingEvidence: objectiveEvidence,
      possibleConsequence: consequence,
      relevantTraits: objectiveTraits.length > 0 ? objectiveTraits : activeTraitKeys.slice(0, 2),
      mechanism: goal
    };
  }

  /**
   * Synthesizes narrative overview from reconstructed stages and objectives.
   */
  private generateFlowSummary(
    stages: ReconstructionStage[],
    objective: AttackerObjective,
    isBenign: boolean
  ): string {
    if (isBenign) {
      return "Evaluation completed. No multi-stage attack sequence identified based on supplied analytical findings.";
    }

    const stageFlow = stages.map(s => s.stageTitle).join("  ➔  ");
    return `Attack Flow Reconstructed (${stages.length} stages): ${stageFlow}. Ultimate Objective: ${objective.primaryObjective}.`;
  }
}

/**
 * Functional wrapper for direct execution.
 */
export function reconstructAttack(input: ThreatAnalysisInput): AttackReconstruction {
  const engine = new AttackReconstructionEngine();
  return engine.reconstruct(input);
}
