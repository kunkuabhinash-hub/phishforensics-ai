import type { AttackReconstruction, ReconstructionStage } from "../../../shared/types/reconstruction.ts";
import type { SafeSimulation, SimulationState, SimulationChoice, SafeConsequence } from "../../../shared/types/simulation.ts";

/**
 * Generates an interactive, safe educational simulation based on an attack reconstruction.
 * 
 * Maps dynamically generated stages into a state machine representing choices the user
 * could make, what consequences would occur, and why.
 * 
 * Never performs real actions, purely returns a state machine representation.
 */
export function generateSimulation(reconstruction: AttackReconstruction): SafeSimulation {
  const states: Record<string, SimulationState> = {};
  
  const simulationId = "sim-" + Math.random().toString(36).substring(2, 9);
  
  // Check if this is a benign / low-info analysis (no real attack)
  const isBenign = reconstruction.totalStages === 1 && reconstruction.stages[0].phaseCategory === "inspection" && reconstruction.stages[0].possibleConsequence.severity === "low";
  
  if (isBenign) {
      const benignStage = reconstruction.stages[0];
      const stateId = `state_${benignStage.stageId}`;
      const state: SimulationState = {
          stateId: stateId,
          title: benignStage.stageTitle,
          narrative: benignStage.stageDescription,
          isTerminal: true,
          availableChoices: [],
          educationalGuidance: {
              headline: "Safe Interaction",
              keyTakeaway: "No malicious indicators were found in this analysis.",
              practicalTip: "Continue normal operations with standard vigilance."
          }
      };
      states[state.stateId] = state;
      return {
        simulationId,
        title: "Safe Interaction Simulation",
        scenarioOverview: reconstruction.attackFlowSummary,
        initialStateId: stateId,
        states,
        safetyDisclaimer: "This is a safe educational simulation.",
        totalDecisionPoints: 0
      };
  }

  // 1. Create a terminal "safe" state for successful defense
  const safeState: SimulationState = {
    stateId: "state_safe_terminal",
    title: "Threat Neutralized",
    narrative: "You successfully identified the threat and took defensive action.",
    isTerminal: true,
    availableChoices: [],
    educationalGuidance: {
      headline: "Good Catch!",
      keyTakeaway: "Identifying deceptive traits early prevents the attack chain from progressing.",
      practicalTip: "Always use official channels or report buttons for suspected attacks."
    }
  };
  states[safeState.stateId] = safeState;

  // 2. Create a terminal "compromise" state for the worst-case scenario
  const compromiseState: SimulationState = {
    stateId: "state_compromise_terminal",
    title: "Security Compromised",
    narrative: "The attacker successfully completed their objective.",
    isTerminal: true,
    availableChoices: [],
    educationalGuidance: {
      headline: "Attack Successful",
      keyTakeaway: "Attackers rely on victims completing their required steps.",
      practicalTip: "If you realize you made a mistake, disconnect and report to IT immediately."
    }
  };
  states[compromiseState.stateId] = compromiseState;

  // 3. Map dynamic stages to decision states
  reconstruction.stages.forEach((stage, idx) => {
    const isLastStage = idx === reconstruction.stages.length - 1;
    const stateId = `state_${stage.stageId}`;
    const nextStateId = isLastStage ? "state_compromise_terminal" : `state_${reconstruction.stages[idx + 1].stageId}`;
    
    const safeChoice: SimulationChoice = {
      choiceId: `choice_safe_${stage.stageId}`,
      label: "Inspect and Report",
      actionDescription: "Carefully review the indicators and report the threat.",
      isRecommendedAction: true,
      nextStateId: "state_safe_terminal",
      safeConsequence: {
        outcomeType: "safe_defense",
        explanation: "By stopping to inspect the evidence, the attack chain is broken.",
        wouldLeadToCompromise: false
      }
    };
    
    const vulnerableChoice: SimulationChoice = {
      choiceId: `choice_vuln_${stage.stageId}`,
      label: `Proceed with action (${stage.phaseCategory || 'interaction'})`,
      actionDescription: `Proceed with the mechanism: ${stage.mechanism || 'Interact with the lure'}.`,
      isRecommendedAction: false,
      nextStateId: nextStateId,
      safeConsequence: {
        outcomeType: isLastStage ? "compromise" : "progression",
        explanation: stage.possibleConsequence.detailedConsequence,
        wouldLeadToCompromise: isLastStage,
        revealedIndicators: stage.supportingEvidence.map(e => e.summary)
      }
    };
    
    const state: SimulationState = {
      stateId,
      title: stage.stageTitle,
      narrative: stage.stageDescription,
      isTerminal: false,
      availableChoices: [safeChoice, vulnerableChoice],
      educationalGuidance: {
        headline: `Beware of ${stage.relevantTraits.join(", ") || 'Deception'}`,
        keyTakeaway: stage.possibleConsequence.shortImpact,
        practicalTip: "Verify out-of-band before taking action."
      },
      simulatedEnvironment: {
        contextType: stage.phaseCategory || "unknown",
        viewTitle: `Simulated: ${stage.stageTitle}`,
      }
    };
    
    states[stateId] = state;
  });

  const sim: SafeSimulation = {
    simulationId,
    title: `Simulation: ${reconstruction.attackerObjective.primaryObjective}`,
    scenarioOverview: reconstruction.attackFlowSummary,
    initialStateId: `state_${reconstruction.stages[0].stageId}`,
    states,
    safetyDisclaimer: "This is a safe educational sandbox. No real exploits or attacks are performed.",
    totalDecisionPoints: reconstruction.stages.length
  };

  return sim;
}
