import fs from 'fs';
import path from 'path';
import Database from 'better-sqlite3';

let dbInstance: Database.Database | null = null;

/**
 * Resolves the SQLite database file path.
 * Default: backend/data/phishforensics.sqlite
 */
export function getDatabasePath(customPath?: string): string {
  if (customPath) return customPath;
  if (process.env.SQLITE_DB_PATH) return process.env.SQLITE_DB_PATH;
  return path.resolve(__dirname, '../../data/phishforensics.sqlite');
}

/**
 * Initializes the SQLite database, ensuring directories, schema, and indexes exist.
 */
export function initDatabase(customPath?: string): Database.Database {
  if (dbInstance && !customPath) {
    return dbInstance;
  }

  const dbPath = getDatabasePath(customPath);
  const dataDir = path.dirname(dbPath);

  // Ensure data directory exists automatically
  if (!fs.existsSync(dataDir)) {
    fs.mkdirSync(dataDir, { recursive: true });
  }

  console.log(`[Database] Connecting to SQLite at: ${dbPath}`);
  const db = new Database(dbPath);

  // Enable WAL mode for high concurrency and performance
  db.pragma('journal_mode = WAL');
  db.pragma('synchronous = NORMAL');
  db.pragma('foreign_keys = ON');

  // Create investigations table
  db.exec(`
    CREATE TABLE IF NOT EXISTS investigations (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      analysis_id TEXT UNIQUE NOT NULL,
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL,
      source_type TEXT NOT NULL,
      input_content TEXT,
      verdict TEXT NOT NULL,
      severity TEXT NOT NULL,
      risk_score INTEGER,
      confidence INTEGER NOT NULL,
      justification TEXT,
      result_json TEXT NOT NULL
    );

    CREATE UNIQUE INDEX IF NOT EXISTS idx_investigations_analysis_id 
      ON investigations(analysis_id);

    CREATE INDEX IF NOT EXISTS idx_investigations_created_at 
      ON investigations(created_at DESC);

    CREATE INDEX IF NOT EXISTS idx_investigations_verdict 
      ON investigations(verdict);

    CREATE INDEX IF NOT EXISTS idx_investigations_source_type 
      ON investigations(source_type);

    CREATE TABLE IF NOT EXISTS schema_migrations (
      version INTEGER PRIMARY KEY,
      applied_at TEXT NOT NULL
    );

    INSERT OR IGNORE INTO schema_migrations (version, applied_at)
    VALUES (1, datetime('now'));
  `);

  if (!customPath) {
    dbInstance = db;
  }

  return db;
}

/**
 * Returns the active database instance, initializing it if not already connected.
 */
export function getDb(): Database.Database {
  if (!dbInstance) {
    return initDatabase();
  }
  return dbInstance;
}

/**
 * Closes the active database connection (useful for tests and shutdown).
 */
export function closeDb(): void {
  if (dbInstance) {
    try {
      dbInstance.close();
    } catch (e) {
      console.error('[Database] Error closing SQLite connection:', e);
    }
    dbInstance = null;
  }
}
