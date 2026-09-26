import type { MitreAttackAnalysis, MitreTactic } from '../../../../shared/types/mitre.ts';
import type { CanonicalThreatIntelligence } from '../../../../shared/types/threat-intelligence.ts';
import type { AttackReconstruction } from '../../../../shared/types/reconstruction.ts';
import type { AttackDNA } from '../../../../shared/types/attack-dna.ts';
import { evaluateMitreRules, type EvaluatorContext } from './rules.ts';

/**
 * Maps pipeline findings deterministically to MITRE ATT&CK Enterprise TTPs.
 * Strictly adheres to verified evidence; does NOT guess or allow AI hallucinations.
 */
export function mapToMitreAttack(
  canonical: CanonicalThreatIntelligence,
  reconstruction?: AttackReconstruction | null,
  attackDNA?: AttackDNA | null,
  normalizedEvidence?: Array<{ id: string; category: string; value: string; defangedValue?: string | null; description?: string }>,
  originalInput?: { sourceType: string; content: string }
): MitreAttackAnalysis {
  const sourceType = originalInput?.sourceType || canonical.artifacts?.[0]?.type || 'text';
  const rawContent = (sourceType === 'image' || sourceType === 'screenshot')
    ? (canonical.artifacts?.[0]?.sanitizedContent || '')
    : (originalInput?.content || canonical.artifacts?.[0]?.sanitizedContent || '');

  // Consolidate technical indicators
  const technicalIndicators = (canonical.technicalIndicators || []).map(ti => ({
    id: ti.id,
    type: ti.type,
    value: ti.value,
    defangedValue: ti.defangedValue
  }));

  // Consolidate normalized evidence
  const evidence = normalizedEvidence || (canonical.evidence || []).map(ev => ({
    id: ev.id,
    category: 'contextual',
    value: ev.rawContent || '',
    defangedValue: ev.defangedContent || null,
    description: ev.description
  }));

  // Consolidate traits from Attack DNA
  const traits = (attackDNA?.traits || []).map(tr => ({
    key: tr.key,
    present: tr.present,
    label: tr.label
  }));

  // Consolidate stages from Reconstruction
  const stages = (reconstruction?.stages || []).map(st => ({
    stageId: st.stageId,
    phaseCategory: st.phaseCategory,
    mechanism: st.mechanism,
    stageTitle: st.stageTitle
  }));

  const threatVerdict = canonical.threatAssessment?.verdict || 'unknown';
  const threatSeverity = canonical.threatAssessment?.severity || 'unknown';

  const ctx: EvaluatorContext = {
    sourceType,
    rawContent,
    technicalIndicators,
    evidence,
    traits,
    stages,
    threatVerdict,
    threatSeverity
  };

  const { mappings, uncertaintyNotes } = evaluateMitreRules(ctx);

  if (mappings.length === 0) {
    return {
      status: 'unmapped',
      primaryTechnique: null,
      techniques: [],
      observedTactics: [],
      uncertaintyNotes: uncertaintyNotes.length > 0 
        ? uncertaintyNotes 
        : ['Insufficient forensic indicators to ground artifacts in MITRE ATT&CK techniques.'],
      evaluatedAt: new Date().toISOString()
    };
  }

  // Deduplicate tactics
  const tacticMap = new Map<string, MitreTactic>();
  for (const m of mappings) {
    if (!tacticMap.has(m.tactic.id)) {
      tacticMap.set(m.tactic.id, m.tactic);
    }
  }

  // Sort mappings by confidence descending
  mappings.sort((a, b) => b.confidence - a.confidence);

  const hasSpecificSubTechnique = mappings.some(m => !!m.subTechniqueId);
  const status: 'mapped' | 'partial' = hasSpecificSubTechnique ? 'mapped' : 'partial';

  return {
    status,
    primaryTechnique: mappings[0] || null,
    techniques: mappings,
    observedTactics: Array.from(tacticMap.values()),
    uncertaintyNotes,
    evaluatedAt: new Date().toISOString()
  };
}
