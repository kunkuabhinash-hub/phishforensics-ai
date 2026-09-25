import type { MitreTactic } from '../../../../shared/types/mitre.ts';

/**
 * Authoritative MITRE ATT&CK Enterprise Matrix Catalog
 * All IDs, names, and tactics correspond directly to official MITRE ATT&CK Enterprise definitions.
 * Reference: https://attack.mitre.org/
 */

export const MITRE_TACTICS: Record<string, MitreTactic> = {
  INITIAL_ACCESS: {
    id: 'TA0001',
    name: 'Initial Access',
    description: 'The adversary is trying to get into your network.',
    referenceUrl: 'https://attack.mitre.org/tactics/TA0001/'
  },
  EXECUTION: {
    id: 'TA0002',
    name: 'Execution',
    description: 'The adversary is trying to run malicious code.',
    referenceUrl: 'https://attack.mitre.org/tactics/TA0002/'
  },
  CREDENTIAL_ACCESS: {
    id: 'TA0006',
    name: 'Credential Access',
    description: 'The adversary is trying to steal account names and passwords.',
    referenceUrl: 'https://attack.mitre.org/tactics/TA0006/'
  },
  RESOURCE_DEVELOPMENT: {
    id: 'TA0042',
    name: 'Resource Development',
    description: 'The adversary is trying to establish resources they can use to support operations.',
    referenceUrl: 'https://attack.mitre.org/tactics/TA0042/'
  },
  RECONNAISSANCE: {
    id: 'TA0043',
    name: 'Reconnaissance',
    description: 'The adversary is trying to gather information they can use to plan future operations.',
    referenceUrl: 'https://attack.mitre.org/tactics/TA0043/'
  }
};

export interface CatalogTechniqueDef {
  techniqueId: string;
  techniqueName: string;
  subTechniqueId?: string | null;
  subTechniqueName?: string | null;
  tactic: MitreTactic;
  referenceUrl: string;
  description: string;
}

export const MITRE_CATALOG: Record<string, CatalogTechniqueDef> = {
  // T1566 - Phishing (Parent)
  PHISHING_PARENT: {
    techniqueId: 'T1566',
    techniqueName: 'Phishing',
    subTechniqueId: null,
    subTechniqueName: null,
    tactic: MITRE_TACTICS.INITIAL_ACCESS,
    referenceUrl: 'https://attack.mitre.org/techniques/T1566/',
    description: 'Adversaries may send phishing messages to gain access to victim systems.'
  },
  // T1566.001 - Spearphishing Attachment
  SPEARPHISHING_ATTACHMENT: {
    techniqueId: 'T1566',
    techniqueName: 'Phishing',
    subTechniqueId: 'T1566.001',
    subTechniqueName: 'Spearphishing Attachment',
    tactic: MITRE_TACTICS.INITIAL_ACCESS,
    referenceUrl: 'https://attack.mitre.org/techniques/T1566/001/',
    description: 'Adversaries may send spearphishing messages with a malicious file attachment.'
  },
  // T1566.002 - Spearphishing Link
  SPEARPHISHING_LINK: {
    techniqueId: 'T1566',
    techniqueName: 'Phishing',
    subTechniqueId: 'T1566.002',
    subTechniqueName: 'Spearphishing Link',
    tactic: MITRE_TACTICS.INITIAL_ACCESS,
    referenceUrl: 'https://attack.mitre.org/techniques/T1566/002/',
    description: 'Adversaries may send spearphishing messages with a malicious link to credential harvesting or exploit sites.'
  },
  // T1566.003 - Spearphishing via Service
  SPEARPHISHING_SERVICE: {
    techniqueId: 'T1566',
    techniqueName: 'Phishing',
    subTechniqueId: 'T1566.003',
    subTechniqueName: 'Spearphishing via Service',
    tactic: MITRE_TACTICS.INITIAL_ACCESS,
    referenceUrl: 'https://attack.mitre.org/techniques/T1566/003/',
    description: 'Adversaries may send spearphishing messages via third-party services (e.g. SMS, social media, collaboration apps).'
  },
  // T1598 - Phishing for Information
  PHISHING_FOR_INFO: {
    techniqueId: 'T1598',
    techniqueName: 'Phishing for Information',
    subTechniqueId: null,
    subTechniqueName: null,
    tactic: MITRE_TACTICS.RECONNAISSANCE,
    referenceUrl: 'https://attack.mitre.org/techniques/T1598/',
    description: 'Adversaries may send phishing messages to elicit sensitive information rather than executing malicious payloads.'
  },
  // T1056.003 - Web Portal Capture
  WEB_PORTAL_CAPTURE: {
    techniqueId: 'T1056',
    techniqueName: 'Input Capture',
    subTechniqueId: 'T1056.003',
    subTechniqueName: 'Web Portal Capture',
    tactic: MITRE_TACTICS.CREDENTIAL_ACCESS,
    referenceUrl: 'https://attack.mitre.org/techniques/T1056/003/',
    description: 'Adversaries may install or mimic web portals to capture credentials entered by users.'
  },
  // T1204.001 - User Execution: Malicious Link
  USER_EXEC_LINK: {
    techniqueId: 'T1204',
    techniqueName: 'User Execution',
    subTechniqueId: 'T1204.001',
    subTechniqueName: 'Malicious Link',
    tactic: MITRE_TACTICS.EXECUTION,
    referenceUrl: 'https://attack.mitre.org/techniques/T1204/001/',
    description: 'An adversary may rely upon a user clicking a malicious link to execute code or deliver payloads.'
  },
  // T1204.002 - User Execution: Malicious File
  USER_EXEC_FILE: {
    techniqueId: 'T1204',
    techniqueName: 'User Execution',
    subTechniqueId: 'T1204.002',
    subTechniqueName: 'Malicious File',
    tactic: MITRE_TACTICS.EXECUTION,
    referenceUrl: 'https://attack.mitre.org/techniques/T1204/002/',
    description: 'An adversary may rely upon a user opening a malicious file attachment to initiate execution.'
  }
};
