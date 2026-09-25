import type { ThreatAnalysisInput } from "../../../shared/types/threat-analysis.ts";
import type { AttackDNA } from "../../../shared/types/attack-dna.ts";
import type { AttackReconstruction } from "../../../shared/types/reconstruction.ts";
import type { SafetyGuidance, DefensiveAction, PreventionRecommendation, IdentifiedRedFlag } from "../../../shared/types/guidance.ts";

/**
 * Dynamically generates grounded safety guidance and recommendations based on the
 * analyzed threat traits and reconstructed attack flow.
 */
export function generateSafetyGuidance(
    analysis: ThreatAnalysisInput,
    dna: AttackDNA,
    reconstruction: AttackReconstruction
): SafetyGuidance {
    const immediateActions: DefensiveAction[] = [];
    const preventionRecommendations: PreventionRecommendation[] = [];
    const redFlagsIdentified: IdentifiedRedFlag[] = [];
    
    // Check if benign
    const isBenign = reconstruction.totalStages === 1 && reconstruction.stages[0].phaseCategory === "inspection" && reconstruction.stages[0].possibleConsequence.severity === "low";

    if (isBenign) {
        return {
            guidanceId: "guidance-benign",
            summary: "No malicious activity detected. Standard security practices apply.",
            immediateActions: [
                {
                    priority: "standard",
                    action: "Proceed with normal operations",
                    reason: "Analysis identified no actionable threats."
                }
            ],
            preventionRecommendations: [],
            redFlagsIdentified: []
        };
    }

    // Grounded Red Flags & Actions
    if (dna.categorizedTraits.urgency?.present) {
        redFlagsIdentified.push({
            cue: "Artificial Time Pressure",
            explanation: "Attackers use urgency to force mistakes and bypass logical scrutiny.",
            locationFound: dna.categorizedTraits.urgency.supportingEvidenceRefs[0]
        });
        preventionRecommendations.push({
            category: "training",
            recommendation: "Train employees to pause and verify when faced with urgent requests.",
            rationale: "Urgency is a primary manipulation tactic in this attack."
        });
    }

    if (dna.categorizedTraits.impersonation?.present) {
        redFlagsIdentified.push({
            cue: "Brand or Authority Impersonation",
            explanation: "The communication attempts to visually or textually mimic a trusted entity.",
            locationFound: dna.categorizedTraits.impersonation.supportingEvidenceRefs[0]
        });
        immediateActions.push({
            priority: "high",
            action: "Verify the sender via an out-of-band communication channel.",
            reason: "The sender's identity cannot be trusted based on the provided metadata."
        });
    }

    if (dna.categorizedTraits.credentialTargeting?.present) {
        immediateActions.push({
            priority: "critical",
            action: "Do not interact with the login portal and rotate credentials if exposed.",
            reason: "The primary objective is harvesting authentication secrets."
        });
        preventionRecommendations.push({
            category: "technical_control",
            recommendation: "Implement phishing-resistant MFA (e.g., FIDO2 keys).",
            rationale: "This attack specifically targets credentials which MFA can protect against."
        });
    }
    
    if (dna.categorizedTraits.financialTargeting?.present) {
        immediateActions.push({
            priority: "critical",
            action: "Halt all wire transfers or financial transactions related to this request.",
            reason: "The objective is direct financial theft via invoice or wire fraud."
        });
        preventionRecommendations.push({
            category: "policy",
            recommendation: "Require verbal authorization for all unexpected financial requests.",
            rationale: "Bypasses technical filters by relying on social engineering for financial gain."
        });
    }
    
    // Add any specific observable indicators
    analysis.indicators.forEach(ind => {
        if (ind.type === "url" && ind.value) {
            redFlagsIdentified.push({
                cue: "Suspicious Link",
                explanation: `The destination URL (${ind.value}) does not align with the claimed sender.`,
                locationFound: ind.id
            });
        }
    });
    
    // Default fallback action if none matched
    if (immediateActions.length === 0) {
        immediateActions.push({
            priority: "medium",
            action: "Report the artifact to the security operations center.",
            reason: "Suspicious characteristics warrant further investigation."
        });
    }

    return {
        guidanceId: `guidance-${Math.random().toString(36).substring(2, 9)}`,
        summary: `Guidance tailored against: ${reconstruction.attackerObjective.primaryObjective}`,
        immediateActions,
        preventionRecommendations,
        redFlagsIdentified
    };
}
