/**
 * PhishForensics AI - Attack DNA Trait Extractor
 * 
 * Data-driven analyzer that extracts attack characteristics and traits from ThreatAnalysisInput.
 * Connects dynamic AI threat findings into structured Attack DNA representation.
 * 
 * Strictly data-driven: consumes structured fields without hardcoded message rules.
 */

import type {
  ThreatAnalysisInput,
  AttackDNA,
  AttackTrait,
  CategorizedTraits
} from "../../../shared/types/index.ts";

/**
 * Derives Attack DNA traits dynamically from the supplied threat analysis.
 */
export function extractAttackDNA(input: ThreatAnalysisInput): AttackDNA {
  const { traits, categorized } = extractTraits(input);

  // Derive high-level summary dynamically from primary findings
  const activeTraitLabels = traits.filter(t => t.present).map(t => t.label);
  const primaryGoal = input.attackerIntent?.primaryGoal || "Unspecified Goal";
  const sourceMedium = input.sourceType || "message";

  let profileSummary = "";
  if (activeTraitLabels.length > 0) {
    profileSummary = `${activeTraitLabels.join(" + ")} profile targeting ${primaryGoal} via ${sourceMedium}.`;
  } else {
    profileSummary = `Minimal threat profile observed via ${sourceMedium} with no prominent hostile traits.`;
  }

  // Determine delivery vector dynamically from source medium and indicators
  const deliveryVector = determineDeliveryVector(input);

  // Complexity derived from diversity of techniques and entities
  const complexity = determineComplexity(input);

  return {
    dnaId: `dna_${input.analysisId || Date.now().toString(36)}`,
    profileSummary,
    traits,
    categorizedTraits: categorized,
    complexity,
    deliveryVector,
    targetProfile: extractTargetProfile(input),
    metadata: {
      sourceAnalysisId: input.analysisId,
      analyzedAt: input.analyzedAt,
      indicatorCount: input.indicators?.length || 0,
      evidenceCount: input.evidence?.length || 0
    }
  };
}

/**
 * Evaluates individual attack traits based purely on the provided analysis data.
 */
export function extractTraits(input: ThreatAnalysisInput): {
  traits: AttackTrait[];
  categorized: CategorizedTraits;
} {
  const traits: AttackTrait[] = [];
  const categorized: CategorizedTraits = {};

  // 1. Impersonation Trait
  const impersonationEvidence = findEvidenceForCategory(input, [
    "impersonation", "spoof", "mimicry", "lookalike", "pretext"
  ]);
  const impersonationEntities = (input.entities || []).filter(e =>
    e.role?.toLowerCase().includes("impersonat") ||
    e.role?.toLowerCase().includes("target")
  );
  const impersonationTech = (input.manipulationTechniques || []).filter(t =>
    t.name?.toLowerCase().includes("impersonat") ||
    t.category?.toLowerCase().includes("deception") ||
    t.description?.toLowerCase().includes("impersonat")
  );
  const hasImpersonation = impersonationEvidence.length > 0 || impersonationEntities.length > 0 || impersonationTech.length > 0;

  if (hasImpersonation) {
    const trait: AttackTrait = {
      key: "impersonation",
      label: "Brand / Identity Impersonation",
      present: true,
      intensity: determineIntensity(impersonationTech.map(t => t.description).join(" ")),
      description: impersonationTech[0]?.description ||
        (impersonationEntities.length > 0
          ? `Adversary adopts deceptive identity targeting ${impersonationEntities.map(e => e.name).join(", ")}.`
          : "Deceptive mimicry of trusted identities observed in analysis."),
      supportingEvidenceRefs: impersonationEvidence
    };
    traits.push(trait);
    categorized.impersonation = trait;
  }

  // 2. Urgency Trait
  const urgencyTech = (input.manipulationTechniques || []).filter(t =>
    t.name?.toLowerCase().includes("urgenc") ||
    t.category?.toLowerCase().includes("urgenc") ||
    t.description?.toLowerCase().includes("urgenc") ||
    t.description?.toLowerCase().includes("deadline") ||
    t.description?.toLowerCase().includes("time")
  );
  const urgencyIndicators = (input.indicators || []).filter(i =>
    i.type?.toLowerCase().includes("urgenc") ||
    i.explanation?.toLowerCase().includes("urgenc")
  );
  const hasUrgency = urgencyTech.length > 0 || urgencyIndicators.length > 0;

  if (hasUrgency) {
    const evidenceRefs = [
      ...findEvidenceForCategory(input, ["urgenc", "time", "deadline", "expire", "immediate"]),
      ...urgencyIndicators.map(i => i.value).filter(Boolean)
    ];
    const trait: AttackTrait = {
      key: "urgency",
      label: "Time-Pressure Urgency",
      present: true,
      intensity: determineIntensity(urgencyTech[0]?.description || ""),
      description: urgencyTech[0]?.description || "Artificial deadlines or time-sensitive constraints utilized to compel rapid response.",
      supportingEvidenceRefs: evidenceRefs
    };
    traits.push(trait);
    categorized.urgency = trait;
  }

  // 3. Fear / Negative Consequence Trait
  const fearTech = (input.manipulationTechniques || []).filter(t =>
    t.name?.toLowerCase().includes("fear") ||
    t.category?.toLowerCase().includes("fear") ||
    t.description?.toLowerCase().includes("suspens") ||
    t.description?.toLowerCase().includes("penalt") ||
    t.description?.toLowerCase().includes("legal") ||
    t.description?.toLowerCase().includes("lock")
  );
  if (fearTech.length > 0) {
    const trait: AttackTrait = {
      key: "fear",
      label: "Intimidation & Fear Appeal",
      present: true,
      intensity: determineIntensity(fearTech[0].description),
      description: fearTech[0].description,
      supportingEvidenceRefs: findEvidenceForCategory(input, ["fear", "suspens", "penalt", "terminat", "legal"])
    };
    traits.push(trait);
    categorized.fear = trait;
  }

  // 4. Authority Coercion Trait
  const authorityTech = (input.manipulationTechniques || []).filter(t =>
    t.name?.toLowerCase().includes("authorit") ||
    t.category?.toLowerCase().includes("authorit") ||
    t.description?.toLowerCase().includes("execut") ||
    t.description?.toLowerCase().includes("c-level") ||
    t.description?.toLowerCase().includes("director") ||
    t.description?.toLowerCase().includes("complianc")
  );
  if (authorityTech.length > 0) {
    const trait: AttackTrait = {
      key: "authority",
      label: "Authority Coercion",
      present: true,
      intensity: determineIntensity(authorityTech[0].description),
      description: authorityTech[0].description,
      supportingEvidenceRefs: findEvidenceForCategory(input, ["authorit", "ceo", "director", "execut", "complianc"])
    };
    traits.push(trait);
    categorized.authority = trait;
  }

  // 5. Credential Targeting Trait
  const goalStr = (input.attackerIntent?.primaryGoal || "") + " " + (input.attackerIntent?.secondaryGoals || []).join(" ");
  const credIndicators = (input.indicators || []).filter(i =>
    i.type?.toLowerCase().includes("credential") ||
    i.type?.toLowerCase().includes("login") ||
    i.explanation?.toLowerCase().includes("credential")
  );
  const isCredentialGoal = goalStr.toLowerCase().includes("credential") ||
    goalStr.toLowerCase().includes("login") ||
    goalStr.toLowerCase().includes("password") ||
    goalStr.toLowerCase().includes("sso") ||
    goalStr.toLowerCase().includes("mfa") ||
    credIndicators.length > 0;

  if (isCredentialGoal) {
    const trait: AttackTrait = {
      key: "credentialTargeting",
      label: "Credential Harvesting",
      present: true,
      intensity: "dominant",
      description: input.attackerIntent?.description || "Explicit focus on capturing user authentication secrets or session tokens.",
      supportingEvidenceRefs: [
        ...findEvidenceForCategory(input, ["credential", "login", "password", "sso", "auth"]),
        ...credIndicators.map(i => i.value)
      ]
    };
    traits.push(trait);
    categorized.credentialTargeting = trait;
  }

  // 6. Financial Targeting Trait
  const isFinancialGoal = goalStr.toLowerCase().includes("financ") ||
    goalStr.toLowerCase().includes("wire") ||
    goalStr.toLowerCase().includes("invoice") ||
    goalStr.toLowerCase().includes("payment") ||
    goalStr.toLowerCase().includes("fraud") ||
    (input.riskInformation?.potentialImpact || []).some(impact =>
      impact.toLowerCase().includes("financ") || impact.toLowerCase().includes("wire") || impact.toLowerCase().includes("fund")
    );

  if (isFinancialGoal) {
    const trait: AttackTrait = {
      key: "financialTargeting",
      label: "Financial Fraud",
      present: true,
      intensity: "dominant",
      description: input.attackerIntent?.description || "Aims at illicit capital redirection, invoice diversion, or fraudulent wire transfers.",
      supportingEvidenceRefs: findEvidenceForCategory(input, ["wire", "invoice", "payment", "bank", "financ"])
    };
    traits.push(trait);
    categorized.financialTargeting = trait;
  }

  // 7. Social Engineering Trait
  const hasSocialEng = (input.manipulationTechniques && input.manipulationTechniques.length > 0);
  if (hasSocialEng) {
    const techNames = input.manipulationTechniques.map(t => t.name).join(", ");
    const trait: AttackTrait = {
      key: "socialEngineering",
      label: "Social Engineering Manipulation",
      present: true,
      intensity: input.manipulationTechniques.length > 1 ? "pronounced" : "moderate",
      description: `Employs deliberate psychological tactics: ${techNames}.`,
      supportingEvidenceRefs: input.manipulationTechniques.map(t => t.name)
    };
    traits.push(trait);
    categorized.socialEngineering = trait;
  }

  // 8. Capture Any Other AI-Identified Manipulation Techniques as Custom Traits
  for (const tech of input.manipulationTechniques || []) {
    const standardKeys = ["impersonation", "urgency", "fear", "authority", "socialEngineering", "credentialTargeting", "financialTargeting"];
    const normalizedKey = tech.name.toLowerCase().replace(/[^a-z0-9]/g, "_");
    if (!standardKeys.includes(normalizedKey) && !categorized[normalizedKey]) {
      const customTrait: AttackTrait = {
        key: normalizedKey,
        label: tech.name,
        present: true,
        intensity: "moderate",
        description: tech.description,
        supportingEvidenceRefs: findEvidenceForCategory(input, [tech.name.toLowerCase()])
      };
      traits.push(customTrait);
      categorized[normalizedKey] = customTrait;
    }
  }

  return { traits, categorized };
}

/**
 * Searches input evidence for terms relevant to a trait category.
 */
function findEvidenceForCategory(input: ThreatAnalysisInput, keywords: string[]): string[] {
  const matches: string[] = [];

  for (const ev of input.evidence || []) {
    const searchTarget = `${ev.type} ${ev.finding} ${ev.rawSnippet || ""}`.toLowerCase();
    if (keywords.some(k => searchTarget.includes(k))) {
      matches.push(ev.id);
    }
  }

  return matches;
}

/**
 * Evaluates qualitative intensity from descriptive language.
 */
function determineIntensity(description: string): string {
  const lower = description.toLowerCase();
  if (lower.includes("extreme") || lower.includes("immediate") || lower.includes("critical") || lower.includes("dominant")) {
    return "dominant";
  }
  if (lower.includes("strong") || lower.includes("high") || lower.includes("severe") || lower.includes("aggressive")) {
    return "pronounced";
  }
  if (lower.includes("subtle") || lower.includes("mild") || lower.includes("covert")) {
    return "subtle";
  }
  return "moderate";
}

/**
 * Determines delivery vector dynamically from input source type and indicators.
 */
function determineDeliveryVector(input: ThreatAnalysisInput): string {
  const source = input.sourceType?.toLowerCase() || "unknown";
  const hasUrlIndicator = (input.indicators || []).some(i =>
    i.type.includes("url") || i.type.includes("domain") || i.value.startsWith("http")
  );
  const hasAttachment = (input.indicators || []).some(i =>
    i.type.includes("attachment") || i.type.includes("file")
  );

  if (source === "email") {
    if (hasUrlIndicator) return "email_link_phish";
    if (hasAttachment) return "email_malware_attachment";
    return "email_direct_lure";
  }
  if (source === "sms") return "sms_smishing";
  if (source === "qr_code") return "qr_code_quishing";
  if (source === "url") return "direct_web_landing";

  return source;
}

/**
 * Evaluates complexity qualitatively based on analytical findings diversity.
 */
function determineComplexity(input: ThreatAnalysisInput): string {
  const techCount = input.manipulationTechniques?.length || 0;
  const indCount = input.indicators?.length || 0;
  const entityCount = input.entities?.length || 0;

  if (techCount >= 2 && indCount >= 2 && entityCount >= 2) {
    return "targeted_spear_phish";
  }
  if (techCount >= 1 || indCount >= 2) {
    return "moderate";
  }
  return "basic";
}

/**
 * Extracts target profile description from entities or analysis metadata.
 */
function extractTargetProfile(input: ThreatAnalysisInput): string | undefined {
  const victimEntity = (input.entities || []).find(e =>
    e.role?.toLowerCase().includes("victim") ||
    e.role?.toLowerCase().includes("target_recipient") ||
    e.role?.toLowerCase().includes("recipient")
  );
  if (victimEntity) {
    return `${victimEntity.name} (${victimEntity.role})`;
  }
  return undefined;
}
