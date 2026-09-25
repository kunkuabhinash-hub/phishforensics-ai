import * as http from 'node:http';
import { ThreatAnalysisPipeline, getAIConfiguration, ConfigurationError } from './services/ai-threat-analysis/index.ts';

// We instantiate ThreatAnalysisPipeline per request to ensure configuration hot-reloads and isolation

const PORT = process.env.PORT || 3000;

// Input size limit logic explicitly requested in Step 8 (must enforce before AI provider)
// Re-using the config's max input chars for overall request payload limit.
function getMaxPayloadSize(): number {
  try {
    return getAIConfiguration().maxInputChars + 10240; // Add 10KB overhead for JSON structure
  } catch {
    return 110240; // Safe default fallback
  }
}

function handleCors(req: http.IncomingMessage, res: http.ServerResponse): boolean {
  res.setHeader('Access-Control-Allow-Origin', process.env.CORS_ORIGIN || '*'); // Configurable CORS
  res.setHeader('Access-Control-Allow-Methods', 'POST, GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') {
    res.writeHead(204);
    res.end();
    return true;
  }
  return false;
}

function sendError(res: http.ServerResponse, statusCode: number, errorCode: string, message: string) {
  res.writeHead(statusCode, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify({ error: { code: errorCode, message } }));
}

const server = http.createServer((req, res) => {
  if (handleCors(req, res)) return;

  if (req.method === 'GET' && req.url === '/health') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ status: 'ok', service: 'phishforensics-ai-backend' }));
    return;
  }

  if (req.method === 'POST' && req.url === '/api/analyze') {
    let body = '';
    const maxPayload = getMaxPayloadSize();

    req.on('data', chunk => {
      if (body.length > maxPayload) return; // Ignore further chunks if already exceeded
      body += chunk.toString();
      if (body.length > maxPayload) {
        sendError(res, 413, 'ANALYSIS_INPUT_TOO_LARGE', 'The submitted artifacts exceed the maximum allowed size.');
        req.destroy();
      }
    });

    req.on('end', async () => {
      if (body.length > maxPayload) {
        return sendError(res, 413, 'ANALYSIS_INPUT_TOO_LARGE', 'The submitted artifacts exceed the maximum allowed size.');
      }

      let parsedBody: any;
      try {
        parsedBody = JSON.parse(body);
      } catch (err) {
        return sendError(res, 400, 'INVALID_ANALYSIS_REQUEST', 'Request body must be valid JSON.');
      }

      const { artifacts } = parsedBody;

      if (!artifacts || !Array.isArray(artifacts) || artifacts.length === 0) {
        return sendError(res, 422, 'UNPROCESSABLE_ANALYSIS_INPUT', 'Request must contain a non-empty "artifacts" array.');
      }

      // Basic structure validation for artifacts
      for (const artifact of artifacts) {
        if (!artifact || typeof artifact !== 'object' || !artifact.type || typeof artifact.content !== 'string') {
          return sendError(res, 422, 'UNPROCESSABLE_ANALYSIS_INPUT', 'Each artifact must include a "type" and string "content".');
        }
      }

      try {
        // The pipeline supports RawArtifactInput | RawArtifactInput[]. 
        // We pass the entire validated artifacts array directly.
        const pipeline = new ThreatAnalysisPipeline();
        const { canonicalResult } = await pipeline.analyzeWithAudit(artifacts);
        
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(canonicalResult));

      } catch (err: unknown) {
        // Safe Error Mapping
        if (err instanceof ConfigurationError) {
          console.error('[API] Configuration Error:', err.message);
          return sendError(res, 503, 'ANALYSIS_PROVIDER_UNAVAILABLE', 'The AI analysis provider is currently unavailable or improperly configured.');
        }

        if (err instanceof Error) {
          console.error('[API] Analysis Failed:', err.message);
          
          if (err.message.includes('Analysis Blocked: Input artifact size')) {
             return sendError(res, 413, 'ANALYSIS_INPUT_TOO_LARGE', 'The artifact content exceeds provider limits.');
          }

          if (err.message.includes('Request timed out')) {
            return sendError(res, 503, 'ANALYSIS_PROVIDER_UNAVAILABLE', 'The AI analysis provider timed out.');
          }
        }
        
        return sendError(res, 500, 'ANALYSIS_FAILED', 'An unexpected error occurred during threat analysis.');
      }
    });
    return;
  }

  res.writeHead(404, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify({ error: 'Not found' }));
});

export function startServer() {
  return server.listen(PORT, () => {
    console.log(`Backend API running on port ${PORT}`);
  });
}

// Only start the server automatically if it is run directly
if (import.meta.url.startsWith('file:') && process.argv[1] === new URL(import.meta.url).pathname) {
  startServer();
}
