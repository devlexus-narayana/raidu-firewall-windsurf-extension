/**
 * Text scanning (API + local), redaction, formatting, clipboard.
 */

import { execFileSync } from 'node:child_process';
import { validateViaAPI, type APIClientConfig } from './api';
import { PIIScanner } from './scanner';
import type { EntityMatch, ScanResult, ScanResultWithSource } from './types';

export const MAX_SCAN_SIZE = 100_000;

const localScanner = new PIIScanner();

/**
 * Scan text for PII. API first (if configured), local fallback.
 * Returns entities, scan time, source, and optional sanitized input from API.
 */
export function scanText(
  text: string,
  apiConfig?: APIClientConfig,
  logger?: (msg: string) => void,
): ScanResultWithSource {
  if (!text || text.length > MAX_SCAN_SIZE) {
    return { entities: [], scanTimeMs: 0, source: 'local' };
  }

  const start = performance.now();
  const apiResult = validateViaAPI(text, apiConfig, logger);

  if (apiResult && !apiResult.passed && apiResult.entities && apiResult.entities.length > 0) {
    const entities: EntityMatch[] = apiResult.entities.map((e) => ({
      type: e.type || 'UNKNOWN',
      // Offsets index into the text we sent; kept in memory only, to remember
      // the blocked value (blocked-values.ts). Never logged or sent anywhere.
      value: e.end && e.end > (e.start ?? 0) ? text.slice(e.start ?? 0, e.end) : '',
      start: e.start ?? 0,
      end: e.end ?? 0,
      score: e.confidence ?? 1.0,
    }));
    logger?.(`scan: API found ${entities.length} entities (${entities.map((e) => e.type).join(', ')})`);
    return {
      entities,
      scanTimeMs: apiResult.processingTimeMs ?? performance.now() - start,
      source: 'api',
      sanitizedInput: apiResult.sanitizedInput,
      // Older servers omit `evidence`; they always attempted the write.
      detector: apiResult.evidence?.outcome === 'failed' ? 'api_unrecorded' : undefined,
    };
  }

  if (apiResult && apiResult.passed) {
    const localCheck = localScanner.scan(text);
    if (localCheck.entities.length > 0) {
      logger?.(`scan: API passed but local found ${localCheck.entities.length} entities`);
      return { ...localCheck, source: 'local', detector: 'local' };
    }
    return { entities: [], scanTimeMs: performance.now() - start, source: 'api' };
  }

  const localResult = localScanner.scan(text);
  logger?.(`scan: local fallback (${localResult.entities.length} entities, ${localResult.scanTimeMs.toFixed(1)}ms)`);
  return {
    ...localResult,
    source: 'local',
    detector: localResult.entities.length > 0 ? 'api_unavailable' : undefined,
  };
}

// ---------------------------------------------------------------------------
// Prompt + file content
// ---------------------------------------------------------------------------

/** One file whose content travels with a prompt (an attachment). */
export interface ScanFile {
  label: string;
  text: string;
}

export type FileScanResult = ScanResultWithSource & {
  /** Labels of the files entities were found in. 'prompt' for the prompt text. */
  foundIn: string[];
};

/**
 * Entity types that, found by the LOCAL scanner alone, are too noisy to block
 * a whole file on: the regexes for names, emails, phones, IPs and dates fire on
 * ordinary documents and source code (RAI-1893). Tower's own scan still decides
 * on them when it is reachable.
 */
const LOCAL_NOISY_TYPES = new Set(['PERSON', 'EMAIL', 'PHONE', 'IP_ADDRESS', 'DATE_OF_BIRTH']);

function scanLocalChunked(text: string): EntityMatch[] {
  const out: EntityMatch[] = [];
  for (let i = 0; i < text.length; i += MAX_SCAN_SIZE) {
    const chunk = text.slice(i, i + MAX_SCAN_SIZE);
    for (const e of localScanner.scan(chunk).entities) out.push({ ...e, start: e.start + i, end: e.end + i });
  }
  return out;
}

/**
 * Scan a prompt together with the content of files sent alongside it.
 *
 * Tower gets the prompt and the files in ONE /validate call (`fileContent`),
 * so a block is recorded once, with the file content in its scan. The local
 * scanner runs on each file in full as the safety net, ignoring the noisy
 * types above for files.
 */
export function scanTextWithFiles(prompt: string, files: ScanFile[], logger?: (msg: string) => void): FileScanResult {
  if (files.length === 0) {
    const r = scanText(prompt, undefined, logger);
    return { ...r, foundIn: r.entities.length > 0 ? ['prompt'] : [] };
  }

  const start = performance.now();
  const apiResult = validateViaAPI(
    prompt.slice(0, MAX_SCAN_SIZE),
    undefined,
    logger,
    files.map((f) => f.text),
  );

  if (apiResult && !apiResult.passed && apiResult.entities && apiResult.entities.length > 0) {
    // Tower joined input + files with '\n'; map offsets back to their source.
    const combined = [prompt.slice(0, MAX_SCAN_SIZE), ...files.map((f) => f.text)].join('\n');
    const bounds: Array<{ label: string; from: number; to: number }> = [];
    let pos = 0;
    for (const [label, t] of [['prompt', prompt.slice(0, MAX_SCAN_SIZE)], ...files.map((f) => [f.label, f.text])]) {
      bounds.push({ label, from: pos, to: pos + t.length });
      pos += t.length + 1;
    }
    const entities: EntityMatch[] = apiResult.entities.map((e) => ({
      type: e.type || 'UNKNOWN',
      value: e.end && e.end > (e.start ?? 0) ? combined.slice(e.start ?? 0, e.end) : '',
      start: e.start ?? 0,
      end: e.end ?? 0,
      score: e.confidence ?? 1.0,
    }));
    const foundIn = [
      ...new Set(entities.map((e) => bounds.find((b) => e.start >= b.from && e.start < b.to)?.label ?? 'attachment')),
    ];
    return {
      entities,
      foundIn,
      scanTimeMs: apiResult.processingTimeMs ?? performance.now() - start,
      source: 'api',
      // sanitizedInput covers the files too; only the prompt goes to the clipboard.
      detector: apiResult.evidence?.outcome === 'failed' ? 'api_unrecorded' : undefined,
    };
  }

  // API clean, unavailable, or not connected: local scan of the prompt and every file.
  const entities: EntityMatch[] = [];
  const foundIn: string[] = [];
  const promptHits = localScanner.scan(prompt.slice(0, MAX_SCAN_SIZE)).entities;
  if (promptHits.length > 0) {
    entities.push(...promptHits);
    foundIn.push('prompt');
  }
  for (const f of files) {
    const hits = scanLocalChunked(f.text).filter((e) => !LOCAL_NOISY_TYPES.has(e.type));
    if (hits.length > 0) {
      // Offsets are into the file, not the prompt: never used for redaction.
      entities.push(...hits.map((e) => ({ ...e, start: 0, end: 0 })));
      foundIn.push(f.label);
    }
  }
  if (entities.length === 0)
    return { entities: [], foundIn: [], scanTimeMs: performance.now() - start, source: apiResult ? 'api' : 'local' };
  logger?.(`scan: local found ${entities.length} entities in ${foundIn.length} source(s)`);
  return {
    entities,
    foundIn,
    scanTimeMs: performance.now() - start,
    source: 'local',
    detector: apiResult ? 'local' : 'api_unavailable',
  };
}

/**
 * Decide on a file's content alone (a file whose NAME only suggests it is
 * sensitive). Same API-first, local-fallback rules as scanTextWithFiles.
 */
export function scanFileContent(label: string, text: string, logger?: (msg: string) => void): FileScanResult {
  return scanTextWithFiles('', [{ label, text }], logger);
}

/** Local-only scan (for post-hoc detection where API call would be too slow). */
export function scanTextLocal(text: string): ScanResult {
  if (!text || text.length > MAX_SCAN_SIZE) return { entities: [], scanTimeMs: 0 };
  return localScanner.scan(text);
}

/** Format entities as human-readable string: "2 ssn, 1 email" */
export function formatEntities(entities: EntityMatch[]): string {
  const types = [...new Set(entities.map((e) => e.type))];
  return types.map((t) => `${entities.filter((e) => e.type === t).length} ${t.replace(/_/g, ' ').toLowerCase()}`).join(', ');
}

/** Replace entities with typed placeholders: [SSN_1], [EMAIL_1] */
export function redactText(text: string, entities: EntityMatch[]): string {
  const withPositions = entities.filter((e) => e.start !== e.end);
  if (withPositions.length === 0) return text;
  const sorted = [...withPositions].sort((a, b) => b.start - a.start);
  let out = text;
  const counters: Record<string, number> = {};
  for (const e of sorted) {
    counters[e.type] = (counters[e.type] || 0) + 1;
    out = `${out.slice(0, e.start)}[${e.type}_${counters[e.type]}]${out.slice(e.end)}`;
  }
  return out;
}

/** Copy text to system clipboard (cross-platform). */
export function copyToClipboard(text: string, logger?: (msg: string) => void): void {
  try {
    switch (process.platform) {
      case 'darwin':
        execFileSync('pbcopy', [], { input: text, timeout: 2000 });
        break;
      case 'linux':
        try { execFileSync('xclip', ['-selection', 'clipboard'], { input: text, timeout: 2000 }); }
        catch { execFileSync('xsel', ['--clipboard', '--input'], { input: text, timeout: 2000 }); }
        break;
      case 'win32':
        execFileSync('clip', [], { input: text, timeout: 2000 });
        break;
    }
  } catch {
    logger?.('clipboard: failed to copy');
  }
}

/** Extract entity type + score (no raw values, safe for audit logs). */
export function entitySummary(entities: EntityMatch[]): Array<{ type: string; score: number }> {
  return entities.map((e) => ({ type: e.type, score: e.score }));
}
