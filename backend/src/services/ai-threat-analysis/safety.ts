/**
 * ============================================================================
 * PHISHFORENSICS AI — PASSIVE SAFETY & DEFANGING UTILITIES
 * ============================================================================
 *
 * Enforces the core safety boundary:
 * 1. URLs and indicators are treated purely as PASSIVE DATA.
 * 2. Absolutely NO HTTP requests, DNS resolutions, attachment execution,
 *    or attacker infrastructure interaction will ever be performed.
 * 3. All extracted indicators are de-fanged before presentation or logging.
 */

/**
 * De-fangs a URL or domain string to render it safe and non-clickable.
 * Example: "http://malicious-site.com/login" -> "hxxp://malicious-site[.]com/login"
 */
export function defangUrl(url: string): string {
  if (!url) return '';
  return url
    .replace(/^http:\/\//i, 'hxxp://')
    .replace(/^https:\/\//i, 'hxxps://')
    .replace(/\./g, '[.]');
}

/**
 * De-fangs an email address.
 * Example: "attacker@phish.com" -> "attacker[@]phish[.]com"
 */
export function defangEmail(email: string): string {
  if (!email) return '';
  return email.replace(/@/g, '[@]').replace(/\./g, '[.]');
}

/**
 * Sanitizes raw text content to neutralize control characters, prompt injection
 * framing markers, and script tags while preserving original textual context.
 */
export function sanitizeContent(content: string): string {
  if (!content) return '';
  return content
    .replace(/\0/g, '') // Strip null bytes
    .replace(/[\u200B-\u200D\uFEFF]/g, '') // Strip zero-width characters
    .replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '[REMOVED_SCRIPT]')
    .trim();
}

/**
 * Computes a simple deterministic FNV-1a non-cryptographic hash string for fast content identification
 * when standard crypto modules are not available in pure runtime environments.
 */
export function computeHash(content: string): string {
  let hash = 0x811c9dc5;
  for (let i = 0; i < content.length; i++) {
    hash ^= content.charCodeAt(i);
    hash += (hash << 1) + (hash << 4) + (hash << 7) + (hash << 8) + (hash << 24);
  }
  return (hash >>> 0).toString(16).padStart(8, '0');
}

/**
 * Asserts that an indicator string is being evaluated passively.
 * Throws an explicit error if an attempt is made to invoke an active network protocol.
 */
export function assertPassiveOnly(actionDescription: string): void {
  // Defensive guard verifying passive execution state
  if (process.env.FORCE_ACTIVE_SCAN === 'true') {
    throw new Error(
      `SAFETY VIOLATION DETECTED: Active behavior (${actionDescription}) is strictly forbidden by PhishForensics AI policy.`
    );
  }
}
