/**
 * Raidu API client for PII validation.
 * Uses execFileSync (no shell injection risk).
 */

import { execFileSync } from 'node:child_process';
import * as fs from 'node:fs';
import { LEGACY_TOKEN_FILE, TOKEN_FILE, TOOL, TOWER_FILE } from './paths';
import type { APIValidationResult, BlockReport, EvidenceVerdict } from './types';

const MAX_API_INPUT = 100_000;
/** Tower's IdeValidateResponseDto cap. */
const MAX_RESPONSE_INPUT = 200_000;
// This editor's own token (src/config/token-store.ts writes the same path).
// RAI-4807: one file per editor; the old shared ~/.raidu/token let Cursor's
// hooks send Windsurf's token, and the other way round.
const DEFAULT_TOKEN_PATH = TOKEN_FILE;
const LEGACY_TOKEN_PATH = LEGACY_TOKEN_FILE;
const DEFAULT_API_BASE = 'https://sandbox.raidu.com';

/**
 * The Tower to call: an explicit config, RAIDU_API_BASE, else the Tower the
 * extension is connected to (its raidu.apiBase setting, written to
 * ~/.raidu/windsurf/tower), else the default. Before, the hooks ignored the
 * setting, so with any Tower but the default the extension paired with one
 * Tower while every scan went to another, and the pairing never showed as used.
 */
export function resolveApiBase(config?: APIClientConfig): string {
  return config?.apiBase || process.env.RAIDU_API_BASE || towerFromExtension() || DEFAULT_API_BASE;
}

function towerFromExtension(): string | null {
  try {
    const url = fs.readFileSync(TOWER_FILE, 'utf-8').trim();
    return /^https?:\/\//.test(url) ? url.replace(/\/+$/, '') : null;
  } catch {
    return null;
  }
}

export interface APIClientConfig {
  apiBase?: string;
  tokenFilePath?: string;
}

function readToken(file: string): string | null {
  try {
    return fs.readFileSync(file, 'utf-8').trim() || null;
  } catch {
    return null;
  }
}

/** The `tool` claim of an IDE token (read-only decode; Tower verifies it). */
function tokenTool(token: string): string | null {
  try {
    const json = JSON.parse(Buffer.from(token.split('.')[1] ?? '', 'base64url').toString('utf-8'));
    return typeof json?.tool === 'string' ? json.tool : null;
  } catch {
    return null;
  }
}

export function getToken(tokenFilePath?: string): string | null {
  if (tokenFilePath) return readToken(tokenFilePath);
  const own = readToken(DEFAULT_TOKEN_PATH);
  if (own) return own;
  // Until the extension has moved it: the shared file, only when its token was
  // issued to this editor. Another editor's token is never sent from here.
  const legacy = readToken(LEGACY_TOKEN_PATH);
  return legacy && tokenTool(legacy) === TOOL ? legacy : null;
}

export function hasToken(): boolean {
  return getToken() !== null;
}

export function validateViaAPI(
  input: string,
  config?: APIClientConfig,
  logger?: (msg: string) => void,
  fileContent?: string[],
): APIValidationResult | null {
  const apiBase = resolveApiBase(config);
  const token = getToken(config?.tokenFilePath);
  const log = logger || (() => {});

  if (!token) {
    log('API: no token, skipping');
    return null;
  }

  const safeInput = input.slice(0, MAX_API_INPUT);
  // Tower scans input + fileContent together (joined by '\n'); keep the
  // combined size within the same cap as a prompt alone.
  let budget = MAX_API_INPUT - safeInput.length;
  const files: string[] = [];
  for (const f of fileContent ?? []) {
    if (budget <= 1) break;
    const part = f.slice(0, budget - 1);
    files.push(part);
    budget -= part.length + 1;
  }
  const body = JSON.stringify(files.length > 0 ? { input: safeInput, fileContent: files } : { input: safeInput });
  const url = `${apiBase}/api/guardrails/ide/validate`;
  const startMs = performance.now();

  log(`API: POST ${url} (${body.length}B)`);

  try {
    const result = execFileSync(
      'curl',
      ['-fsSL', '-X', 'POST', '-H', `Authorization: Bearer ${token}`, '-H', 'Content-Type: application/json', '--data-binary', '@-', url],
      // Body over stdin, not argv: keeps prompt and file content out of the process list.
      { input: body, timeout: 8000, encoding: 'utf-8' as BufferEncoding, stdio: ['pipe', 'pipe', 'pipe'] },
    );

    const latencyMs = (performance.now() - startMs).toFixed(0);
    const parsed = JSON.parse(result as string);

    log(`API: ${latencyMs}ms | passed=${parsed.passed} | entities=${parsed.entities?.length || 0} | serverMs=${parsed.processingTimeMs || '?'}`);

    return parsed;
  } catch (err: unknown) {
    const latencyMs = (performance.now() - startMs).toFixed(0);
    log(`API: FAILED after ${latencyMs}ms | ${(err as Error).message?.slice(0, 150)}`);
    return null;
  }
}

// ---------------------------------------------------------------------------
// Block reports (called from the detached flusher, never from a hook directly)
// ---------------------------------------------------------------------------

/**
 * POST a batch of block reports. Returns per-report verdicts in request order,
 * or null on any failure (no token, network, non-2xx), so the caller requeues.
 */
export function postBlockReports(
  reports: BlockReport[],
  logger?: (msg: string) => void,
): EvidenceVerdict[] | null {
  const token = getToken();
  if (!token || reports.length === 0) return null;

  const url = `${resolveApiBase()}/api/guardrails/ide/report`;
  const body = JSON.stringify({ reports });

  try {
    const result = execFileSync(
      'curl',
      [
        '-fsSL',
        '-X',
        'POST',
        '-H',
        `Authorization: Bearer ${token}`,
        '-H',
        'Content-Type: application/json',
        '--data-binary',
        '@-',
        url,
      ],
      // Body over stdin, not argv: keeps it out of the process list.
      { input: body, timeout: 15000, encoding: 'utf-8' as BufferEncoding, stdio: ['pipe', 'pipe', 'pipe'] },
    );
    const parsed = JSON.parse(result as string) as { results?: EvidenceVerdict[] };
    if (!Array.isArray(parsed.results)) return null;
    return parsed.results;
  } catch (err: unknown) {
    logger?.(`API: report FAILED | ${(err as Error).message?.slice(0, 150)}`);
    return null;
  }
}

// ---------------------------------------------------------------------------
// Response scan (called from the detached response scanner, never from a hook)
// ---------------------------------------------------------------------------

export interface ResponseScanRequest {
  response: string;
  prompt?: string;
  ideConversationId?: string;
  ideGenerationId?: string;
}

/**
 * POST a model reply to /api/guardrails/ide/validate-response. Tower scans it
 * against the configured security policies and records the violation itself.
 * Returns false on any failure.
 */
export function postResponseScan(req: ResponseScanRequest, debug: (msg: string) => void = () => {}): boolean {
  const token = getToken();
  if (!token || !req.response) return false;

  const url = `${resolveApiBase()}/api/guardrails/ide/validate-response`;
  const body = JSON.stringify({
    response: req.response.slice(0, MAX_RESPONSE_INPUT),
    prompt: req.prompt?.slice(0, MAX_RESPONSE_INPUT),
    ideConversationId: req.ideConversationId?.slice(0, 100),
    ideGenerationId: req.ideGenerationId?.slice(0, 100),
  });

  try {
    const result = execFileSync(
      'curl',
      [
        '-fsSL',
        '-X',
        'POST',
        '-H',
        `Authorization: Bearer ${token}`,
        '-H',
        'Content-Type: application/json',
        '--data-binary',
        '@-',
        url,
      ],
      { input: body, timeout: 30000, encoding: 'utf-8' as BufferEncoding, stdio: ['pipe', 'pipe', 'pipe'] },
    );
    const parsed = JSON.parse(result as string) as { passed?: boolean; action?: string; violations?: unknown[] };
    debug(
      `API: response scan passed=${parsed.passed} action=${parsed.action} violations=${parsed.violations?.length ?? 0}`,
    );
    return true;
  } catch (err: unknown) {
    debug(`API: response scan FAILED | ${(err as Error).message?.slice(0, 150)}`);
    return false;
  }
}
