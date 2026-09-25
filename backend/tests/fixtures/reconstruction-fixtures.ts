/**
 * PhishForensics AI - Test Fixtures for Attack Reconstruction
 * 
 * Isolated test data for verifying reconstruction behavior across distinct threat classes.
 * These fixtures remain strictly test data and are never imported into production logic.
 */

import type { ThreatAnalysisInput } from "../../../shared/types/index.ts";

/**
 * 1. Credential-Targeting Analysis Fixture
 * Technical multi-stage phishing lure targeting corporate SSO authentication.
 */
export const credentialTargetingFixture: ThreatAnalysisInput = {
  analysisId: "threat_cred_test_001",
  analyzedAt: "2026-09-25T10:00:00Z",
  sourceType: "email",
  attackerIntent: {
    primaryGoal: "Harvest Enterprise SSO Credentials",
    description: "Capture corporate single sign-on passwords and MFA session tokens through a counterfeit login portal.",
    confidence: "high",
    secondaryGoals: ["Gain unauthorized access to corporate SharePoint", "Exfiltrate internal communication"]
  },
  indicators: [
    {
      type: "sender_spoof",
      value: "security-noreply@microsoft-compliance-portal.com",
      context: "Header:From",
      severity: "high",
      explanation: "Lookalike domain mimicking Microsoft Security operations"
    },
    {
      type: "suspicious_domain",
      value: "https://auth-renew-session.azure-verify.workers.dev/login",
      context: "Body:Anchor",
      severity: "critical",
      explanation: "Cloudflare worker hosting reverse proxy credential harvester"
    }
  ],
  manipulationTechniques: [
    {
      name: "Time-Pressure Urgency",
      category: "psychological",
      description: "Claims corporate SSO session will expire within 2 hours if not refreshed",
      evidenceSnippet: "Your session expires in 2 hours. Click below to maintain single sign-on access."
    },
    {
      name: "Brand Impersonation",
      category: "deception",
      description: "Utilizes Microsoft 365 brand styling, typography, and logos",
      evidenceSnippet: "Microsoft Security Operations Center"
    }
  ],
  evidence: [
    {
      id: "ev_hdr_01",
      type: "header",
      finding: "DMARC authentication failed; envelope sender does not align with microsoft.com",
      rawSnippet: "Authentication-Results: spf=fail; dmarc=fail"
    },
    {
      id: "ev_lnk_01",
      type: "link",
      finding: "Destination URL points to an untrusted third-party server disguised as Azure",
      rawSnippet: "https://auth-renew-session.azure-verify.workers.dev/login"
    }
  ],
  riskInformation: {
    level: "critical",
    assessment: "Severe threat to enterprise identity perimeter with direct risk of corporate account takeover.",
    potentialImpact: ["Enterprise Identity Compromise", "Unauthorized Inbox Access", "Internal Data Exfiltration"]
  },
  entities: [
    {
      entityType: "brand",
      name: "Microsoft 365",
      role: "impersonated_target"
    },
    {
      entityType: "domain",
      name: "microsoft-compliance-portal.com",
      role: "sender_spoof_domain"
    }
  ]
};

/**
 * 2. Financial-Fraud Analysis Fixture
 * Pure social engineering Business Email Compromise (BEC). NO links, NO domains, NO attachments.
 */
export const financialFraudFixture: ThreatAnalysisInput = {
  analysisId: "threat_bec_test_002",
  analyzedAt: "2026-09-25T10:15:00Z",
  sourceType: "email",
  attackerIntent: {
    primaryGoal: "Direct Financial Wire Fraud",
    description: "Induce a finance officer to execute an unauthorized $95,000 wire transfer under executive pretext.",
    confidence: "high",
    secondaryGoals: ["Circumvent dual-control accounting checks"]
  },
  indicators: [
    {
      type: "display_name_spoofing",
      value: "Jane Smith, CFO <cfo-executive-briefing@consultant-desk.com>",
      context: "Header:From",
      severity: "critical",
      explanation: "Display name spoofing legitimate CFO while originating from external domain"
    }
  ],
  manipulationTechniques: [
    {
      name: "Executive Authority Coercion",
      category: "psychological",
      description: "Commands immediate compliance using senior executive stature",
      evidenceSnippet: "I need you to process this acquisition retainer before the bank cut-off today."
    },
    {
      name: "Forced Secrecy",
      category: "social_engineering",
      description: "Forbids discussing the transfer with internal teams under the guise of an NDA",
      evidenceSnippet: "This is strictly confidential under an NDA. Do not discuss with anyone in accounting."
    }
  ],
  evidence: [
    {
      id: "ev_bec_hdr",
      type: "header",
      finding: "Sender domain has no affiliation with company infrastructure",
      rawSnippet: "From: Jane Smith, CFO <cfo-executive-briefing@consultant-desk.com>"
    },
    {
      id: "ev_bec_body",
      type: "body",
      finding: "Direct payment instructions provided in plain text with urgency demand",
      rawSnippet: "Please wire $95,000 to the attached escrow routing details immediately."
    }
  ],
  riskInformation: {
    level: "critical",
    assessment: "Catastrophic financial loss threat with irrecoverable funds transfer if executed.",
    potentialImpact: ["Corporate Treasury Capital", "Unrecoverable Wire Transfer"]
  },
  entities: [
    {
      entityType: "person",
      name: "Jane Smith, CFO",
      role: "impersonated_executive"
    },
    {
      entityType: "organization",
      name: "Finance Department",
      role: "target_recipient"
    }
  ]
};

/**
 * 3. Impersonation / Social-Engineering Analysis Fixture
 * SMS Smishing lure mimicking a postal logistics courier with a tracking fee lure.
 */
export const impersonationSocialEngineeringFixture: ThreatAnalysisInput = {
  analysisId: "threat_smish_test_003",
  analyzedAt: "2026-09-25T10:30:00Z",
  sourceType: "sms",
  attackerIntent: {
    primaryGoal: "Personal Data & Payment Card Harvesting",
    description: "Trick recipient into paying a small redelivery fee to capture credit card and personal contact information.",
    confidence: "medium"
  },
  indicators: [
    {
      type: "suspicious_domain",
      value: "https://fedx-package-redelivery.info/track",
      context: "SMS:Body",
      severity: "high",
      explanation: "Lookalike domain mimicking FedEx courier delivery"
    }
  ],
  manipulationTechniques: [
    {
      name: "Manufactured Curiosity & Urgency",
      category: "psychological",
      description: "Claims an urgent parcel could not be delivered and will be returned to sender",
      evidenceSnippet: "Your package is held at our depot. Update address within 24h to avoid return."
    }
  ],
  evidence: [
    {
      id: "ev_sms_lnk",
      type: "link",
      finding: "SMS message contains link to newly registered unverified courier lookalike domain",
      rawSnippet: "https://fedx-package-redelivery.info/track"
    }
  ],
  riskInformation: {
    level: "medium",
    assessment: "Personal data harvesting and minor fraudulent fee charges targeting mobile users.",
    potentialImpact: ["Consumer Payment Card Fraud", "Mobile Smishing Resale"]
  },
  entities: [
    {
      entityType: "brand",
      name: "FedEx Delivery",
      role: "impersonated_brand"
    }
  ]
};

/**
 * 4. Low-Information or Benign Analysis Fixture
 * A routine internal communication with zero malicious indicators or techniques.
 */
export const lowInformationOrBenignFixture: ThreatAnalysisInput = {
  analysisId: "threat_benign_test_004",
  analyzedAt: "2026-09-25T10:45:00Z",
  sourceType: "email",
  attackerIntent: {
    primaryGoal: "Legitimate Internal Communication / No Threat",
    description: "Routine company-wide benefits informational newsletter.",
    confidence: "verified"
  },
  indicators: [],
  manipulationTechniques: [],
  evidence: [
    {
      id: "ev_legit_01",
      type: "header",
      finding: "All cryptographic signatures passed (SPF pass, DKIM pass, DMARC pass)",
      rawSnippet: "Authentication-Results: spf=pass; dkim=pass; dmarc=pass"
    }
  ],
  riskInformation: {
    level: "low",
    assessment: "Baseline inspection confirms authentic internal communication with no evidence of deception or adversarial progression.",
    potentialImpact: []
  },
  entities: [
    {
      entityType: "organization",
      name: "Corporate HR Team",
      role: "legitimate_sender"
    }
  ]
};
