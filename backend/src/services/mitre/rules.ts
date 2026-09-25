import type { MitreTechniqueMapping } from '../../../../shared/types/mitre.ts';
import { MITRE_CATALOG } from './catalog.ts';

export interface EvaluatorContext {
  sourceType: string;
  rawContent: string;
  technicalIndicators: Array<{ id?: string; type: string; value: string; defangedValue?: string }>;
  evidence: Array<{ id: string; category: string; value: string; defangedValue?: string | null; description?: string }>;
  traits: Array<{ key: string; present: boolean; label?: string }>;
  stages: Array<{ stageId: string; phaseCategory?: string; mechanism?: string; stageTitle?: string }>;
  threatVerdict: string;
  threatSeverity: string;
}

/**
 * Deterministic helper to detect whether an actual technical URL/domain artifact exists.
 * Textual phrases alone (e.g. "click here", "link below") do NOT qualify as an extracted URL.
 */
export function hasActualUrlIndicator(ctx: EvaluatorContext): { hasUrl: boolean; refs: string[]; values: string[] } {
  const refs: string[] = [];
  const values: string[] = [];

  // Check technical indicators
  for (const ti of ctx.technicalIndicators || []) {
    if (ti.type === 'url' || ti.type === 'domain') {
      if (ti.id) refs.push(ti.id);
      values.push(ti.value);
    }
  }

  // Check technical category in normalized evidence
  for (const ev of ctx.evidence || []) {
    if (ev.category === 'technical') {
      const val = (ev.value || ev.defangedValue || '').trim();
      if (/^(https?|hxxps?):\/\/[^\s]+$/i.test(val) || /^www\.[^\s]+$/i.test(val)) {
        refs.push(ev.id);
        values.push(val);
      }
    }
  }

  return {
    hasUrl: refs.length > 0,
    refs,
    values
  };
}

/**
 * Deterministic helper to detect whether an actual attachment artifact exists.
 */
export function hasActualAttachmentIndicator(ctx: EvaluatorContext): { hasAttachment: boolean; refs: string[]; values: string[] } {
  const refs: string[] = [];
  const values: string[] = [];

  for (const ti of ctx.technicalIndicators || []) {
    if (ti.type === 'attachment') {
      if (ti.id) refs.push(ti.id);
      values.push(ti.value);
    }
  }

  for (const ev of ctx.evidence || []) {
    if (ev.category === 'technical') {
      const val = (ev.value || '').toLowerCase();
      if (/\.(pdf|docx?|xlsx?|pptx?|zip|rar|7z|tar|gz|exe|scr|iso|img|vbs|js|html|htm)$/i.test(val)) {
        refs.push(ev.id);
        values.push(ev.value);
      }
    }
  }

  return {
    hasAttachment: refs.length > 0,
    refs,
    values
  };
}

/**
 * Evaluates candidates against verified MITRE ATT&CK rules.
 */
export function evaluateMitreRules(ctx: EvaluatorContext): {
  mappings: MitreTechniqueMapping[];
  uncertaintyNotes: string[];
} {
  const mappings: MitreTechniqueMapping[] = [];
  const uncertaintyNotes: string[] = [];

  const isPhishingOrSuspicious = 
    ctx.threatVerdict === 'phishing' || 
    ctx.threatVerdict === 'suspicious' || 
    ctx.traits.some(t => t.present && ['urgency', 'impersonation', 'credentialTargeting', 'fear', 'authority'].includes(t.key)) ||
    ctx.stages.some(s => s.phaseCategory === 'delivery' || s.phaseCategory === 'social_engineering');

  // If artifact is deemed safe or completely devoid of suspicious indicators
  if (!isPhishingOrSuspicious && ctx.threatVerdict === 'safe') {
    return {
      mappings: [],
      uncertaintyNotes: ['Artifact does not display hostile or deceptive indicators sufficient to support MITRE ATT&CK mapping.']
    };
  }

  const urlCheck = hasActualUrlIndicator(ctx);
  const attachCheck = hasActualAttachmentIndicator(ctx);

  // Check for textual mention of links without actual URL IOC
  const textMentionsLink = /(?:link|url|click|portal|verify|log\s*in|sign\s*in)/i.test(ctx.rawContent);

  // RULE 1: T1566.002 - Spearphishing Link
  // STRICT REQUIREMENT: Must have an actual extracted URL artifact in an email/lure context
  if (ctx.sourceType === 'email' && urlCheck.hasUrl && isPhishingOrSuspicious) {
    mappings.push({
      techniqueId: MITRE_CATALOG.SPEARPHISHING_LINK.techniqueId,
      techniqueName: MITRE_CATALOG.SPEARPHISHING_LINK.techniqueName,
      subTechniqueId: MITRE_CATALOG.SPEARPHISHING_LINK.subTechniqueId,
      subTechniqueName: MITRE_CATALOG.SPEARPHISHING_LINK.subTechniqueName,
      tactic: MITRE_CATALOG.SPEARPHISHING_LINK.tactic,
      confidence: 85,
      supportingEvidenceRefs: urlCheck.refs,
      mappingRationale: `Inbound email contains verified technical link artifact (${urlCheck.values.join(', ')}) deployed as an initial access vector.`
    });

    // RULE 1B: T1204.001 - User Execution: Malicious Link
    if (ctx.stages.some(s => s.phaseCategory === 'social_engineering' || s.phaseCategory === 'redirection')) {
      mappings.push({
        techniqueId: MITRE_CATALOG.USER_EXEC_LINK.techniqueId,
        techniqueName: MITRE_CATALOG.USER_EXEC_LINK.techniqueName,
        subTechniqueId: MITRE_CATALOG.USER_EXEC_LINK.subTechniqueId,
        subTechniqueName: MITRE_CATALOG.USER_EXEC_LINK.subTechniqueName,
        tactic: MITRE_CATALOG.USER_EXEC_LINK.tactic,
        confidence: 75,
        supportingEvidenceRefs: urlCheck.refs,
        mappingRationale: 'Adversary relies on the recipient clicking the extracted link artifact to advance the attack sequence.'
      });
    }
  }

  // RULE 2: T1566.001 - Spearphishing Attachment
  // STRICT REQUIREMENT: Must have an actual extracted attachment artifact
  if (ctx.sourceType === 'email' && attachCheck.hasAttachment && isPhishingOrSuspicious) {
    mappings.push({
      techniqueId: MITRE_CATALOG.SPEARPHISHING_ATTACHMENT.techniqueId,
      techniqueName: MITRE_CATALOG.SPEARPHISHING_ATTACHMENT.techniqueName,
      subTechniqueId: MITRE_CATALOG.SPEARPHISHING_ATTACHMENT.subTechniqueId,
      subTechniqueName: MITRE_CATALOG.SPEARPHISHING_ATTACHMENT.subTechniqueName,
      tactic: MITRE_CATALOG.SPEARPHISHING_ATTACHMENT.tactic,
      confidence: 90,
      supportingEvidenceRefs: attachCheck.refs,
      mappingRationale: `Inbound email contains verified file attachment artifact (${attachCheck.values.join(', ')}) intended for victim delivery.`
    });

    // RULE 2B: T1204.002 - User Execution: Malicious File
    mappings.push({
      techniqueId: MITRE_CATALOG.USER_EXEC_FILE.techniqueId,
      techniqueName: MITRE_CATALOG.USER_EXEC_FILE.techniqueName,
      subTechniqueId: MITRE_CATALOG.USER_EXEC_FILE.subTechniqueId,
      subTechniqueName: MITRE_CATALOG.USER_EXEC_FILE.subTechniqueName,
      tactic: MITRE_CATALOG.USER_EXEC_FILE.tactic,
      confidence: 80,
      supportingEvidenceRefs: attachCheck.refs,
      mappingRationale: 'Attack chain relies on the recipient opening or executing the delivered file artifact.'
    });
  }

  // RULE 3: T1566 (Parent Only) - Inbound Phishing Lure Without Concrete URL or Attachment Artifact
  // TRIGGER: Email source with suspicious pretext/manipulation, but NO extracted URL or attachment IOC
  if (ctx.sourceType === 'email' && !urlCheck.hasUrl && !attachCheck.hasAttachment && isPhishingOrSuspicious) {
    const contextualRefs = ctx.evidence.filter(e => e.category === 'contextual' || e.category === 'psychological').map(e => e.id);
    
    mappings.push({
      techniqueId: MITRE_CATALOG.PHISHING_PARENT.techniqueId,
      techniqueName: MITRE_CATALOG.PHISHING_PARENT.techniqueName,
      subTechniqueId: null,
      subTechniqueName: null,
      tactic: MITRE_CATALOG.PHISHING_PARENT.tactic,
      confidence: 60,
      supportingEvidenceRefs: contextualRefs.length > 0 ? contextualRefs : ['input_email_lure'],
      mappingRationale: 'Inbound email presents deceptive social engineering characteristics, but lacks an extracted URL or attachment artifact to substantiate a specific sub-technique.'
    });

    if (textMentionsLink) {
      uncertaintyNotes.push(
        'Artifact text makes rhetorical reference to a link or verification action, but no concrete URL or domain indicator was extracted. Sub-technique T1566.002 (Spearphishing Link) cannot be asserted without an actual URL artifact.'
      );
    } else {
      uncertaintyNotes.push(
        'Inbound email exhibits deceptive lure characteristics, but contains neither an extracted URL nor an attachment indicator. Classified under parent technique T1566.'
      );
    }
  }

  // RULE 4: T1566.003 - Spearphishing via Service (SMS / Messaging)
  if ((ctx.sourceType === 'sms' || ctx.sourceType === 'message') && isPhishingOrSuspicious) {
    mappings.push({
      techniqueId: MITRE_CATALOG.SPEARPHISHING_SERVICE.techniqueId,
      techniqueName: MITRE_CATALOG.SPEARPHISHING_SERVICE.techniqueName,
      subTechniqueId: MITRE_CATALOG.SPEARPHISHING_SERVICE.subTechniqueId,
      subTechniqueName: MITRE_CATALOG.SPEARPHISHING_SERVICE.subTechniqueName,
      tactic: MITRE_CATALOG.SPEARPHISHING_SERVICE.tactic,
      confidence: 80,
      supportingEvidenceRefs: ctx.evidence.map(e => e.id),
      mappingRationale: 'Deceptive communication received via short messaging service (SMS) or communication platform.'
    });
  }

  // RULE 5: T1056.003 - Web Portal Capture
  // TRIGGER: Credential targeting trait or action on objectives aiming at login/credentials WITH an actual URL or web portal artifact
  const hasCredentialTarget = ctx.traits.some(t => t.present && (t.key === 'credentialTargeting' || t.key === 'credential_targeting'));
  if (hasCredentialTarget && urlCheck.hasUrl) {
    mappings.push({
      techniqueId: MITRE_CATALOG.WEB_PORTAL_CAPTURE.techniqueId,
      techniqueName: MITRE_CATALOG.WEB_PORTAL_CAPTURE.techniqueName,
      subTechniqueId: MITRE_CATALOG.WEB_PORTAL_CAPTURE.subTechniqueId,
      subTechniqueName: MITRE_CATALOG.WEB_PORTAL_CAPTURE.subTechniqueName,
      tactic: MITRE_CATALOG.WEB_PORTAL_CAPTURE.tactic,
      confidence: 75,
      supportingEvidenceRefs: urlCheck.refs,
      mappingRationale: 'Adversary deploys or directs victims to a web interface designed to capture entered authentication credentials.'
    });
  }

  return {
    mappings,
    uncertaintyNotes
  };
}
