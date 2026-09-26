import type { UnifiedPhishForensicsContract } from '../../../shared/types/unified-contract.ts';
import { getDb } from './database.ts';
import type Database from 'better-sqlite3';

export interface InvestigationSummary {
  analysisId: string;
  createdAt: string;
  updatedAt: string;
  sourceType: string;
  inputContent: string;
  verdict: string;
  severity: string;
  riskScore: number | null;
  confidence: number;
  justification: string;
}

export interface InvestigationRecord extends InvestigationSummary {
  id: number;
  resultJson: string;
}

/**
 * Sanitizes input content for image artifacts to avoid storing large binary base64 strings in SQLite.
 */
function sanitizeInputContent(sourceType: string, content: string): string {
  if (!content) return '';
  if (sourceType === 'image' || content.trim().startsWith('data:image/')) {
    const match = content.match(/^data:(image\/[a-zA-Z0-9.+-]+);base64,([\s\S]+)$/i);
    if (match) {
      const mime = match[1];
      const approxKb = Math.round((match[2].length * 0.75) / 1024);
      return `[Image Artifact: ${mime}, ~${approxKb} KB]`;
    }
    return `[Image Artifact: ${content.substring(0, 32)}...]`;
  }
  return content;
}

/**
 * Sanitizes result object before serializing to JSON to ensure large image base64 strings
 * are not embedded inside the database JSON column.
 */
function sanitizeResultForStorage(result: UnifiedPhishForensicsContract): UnifiedPhishForensicsContract {
  const cloned = JSON.parse(JSON.stringify(result));
  if (cloned.input && (cloned.input.sourceType === 'image' || cloned.input.content?.startsWith('data:image/'))) {
    cloned.input.content = sanitizeInputContent(cloned.input.sourceType || 'image', cloned.input.content);
  }
  return cloned;
}

/**
 * Persists a unified analysis result to the SQLite database.
 * If an investigation with the same analysisId already exists, it updates it.
 */
export function saveInvestigation(
  result: UnifiedPhishForensicsContract,
  customDb?: Database.Database
): InvestigationSummary {
  const db = customDb || getDb();

  const analysisId = result.analysisId;
  const createdAt = result.timestamp || new Date().toISOString();
  const updatedAt = new Date().toISOString();
  const sourceType = result.input?.sourceType || 'artifact';
  const inputContent = sanitizeInputContent(sourceType, result.input?.content || '');
  const verdict = result.threatAssessment?.verdict || 'unknown';
  const severity = result.threatAssessment?.severity || 'unknown';
  const riskScore = typeof result.threatAssessment?.riskScore === 'number' ? result.threatAssessment.riskScore : null;
  const confidence = typeof result.threatAssessment?.confidence === 'number' ? result.threatAssessment.confidence : 0;
  const justification = result.threatAssessment?.justification || '';

  // Prepare complete JSON representation
  const sanitizedResult = sanitizeResultForStorage(result);
  const resultJson = JSON.stringify(sanitizedResult);

  const stmt = db.prepare(`
    INSERT INTO investigations (
      analysis_id,
      created_at,
      updated_at,
      source_type,
      input_content,
      verdict,
      severity,
      risk_score,
      confidence,
      justification,
      result_json
    ) VALUES (
      @analysisId,
      @createdAt,
      @updatedAt,
      @sourceType,
      @inputContent,
      @verdict,
      @severity,
      @riskScore,
      @confidence,
      @justification,
      @resultJson
    )
    ON CONFLICT(analysis_id) DO UPDATE SET
      updated_at = excluded.updated_at,
      source_type = excluded.source_type,
      input_content = excluded.input_content,
      verdict = excluded.verdict,
      severity = excluded.severity,
      risk_score = excluded.risk_score,
      confidence = excluded.confidence,
      justification = excluded.justification,
      result_json = excluded.result_json;
  `);

  stmt.run({
    analysisId,
    createdAt,
    updatedAt,
    sourceType,
    inputContent,
    verdict,
    severity,
    riskScore,
    confidence,
    justification,
    resultJson
  });

  return {
    analysisId,
    createdAt,
    updatedAt,
    sourceType,
    inputContent,
    verdict,
    severity,
    riskScore,
    confidence,
    justification
  };
}

/**
 * Retrieves a single complete investigation by its unique analysisId.
 * Reconstructs the full UnifiedPhishForensicsContract from result_json.
 */
export function getInvestigation(
  analysisId: string,
  customDb?: Database.Database
): UnifiedPhishForensicsContract | null {
  const db = customDb || getDb();

  const stmt = db.prepare(`
    SELECT result_json
    FROM investigations
    WHERE analysis_id = ?
    LIMIT 1;
  `);

  const row = stmt.get(analysisId) as { result_json: string } | undefined;
  if (!row || !row.result_json) {
    return null;
  }

  try {
    const parsed = JSON.parse(row.result_json) as UnifiedPhishForensicsContract;
    return parsed;
  } catch (error) {
    console.error(`[InvestigationRepository] Malformed result_json for analysisId: ${analysisId}`, error);
    throw new Error(`Corrupted database record for investigation ID: ${analysisId}`);
  }
}

/**
 * Lists stored investigations with lightweight metadata, sorted newest first.
 * Does NOT return the heavy result_json column.
 */
export function listInvestigations(
  limit: number = 50,
  offset: number = 0,
  customDb?: Database.Database
): InvestigationSummary[] {
  const db = customDb || getDb();

  const stmt = db.prepare(`
    SELECT
      analysis_id as analysisId,
      created_at as createdAt,
      updated_at as updatedAt,
      source_type as sourceType,
      input_content as inputContent,
      verdict,
      severity,
      risk_score as riskScore,
      confidence,
      justification
    FROM investigations
    ORDER BY created_at DESC
    LIMIT ? OFFSET ?;
  `);

  const rows = stmt.all(limit, offset) as InvestigationSummary[];
  return rows;
}

/**
 * Deletes a stored investigation by its analysisId.
 * Returns true if a record was removed, false if no record matched.
 */
export function deleteInvestigation(
  analysisId: string,
  customDb?: Database.Database
): boolean {
  const db = customDb || getDb();

  const stmt = db.prepare(`
    DELETE FROM investigations
    WHERE analysis_id = ?;
  `);

  const info = stmt.run(analysisId);
  return info.changes > 0;
}
