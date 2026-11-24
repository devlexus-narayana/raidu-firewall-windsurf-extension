/**
 * Response-side scanning in Tower (RAI-4807 #6).
 *
 * post_cascade_response used to scan the reply with the local regexes only and
 * write the result to the local audit log: Tower never saw it, so PII in a
 * Cascade response produced no violation. Tower's
 * POST /api/guardrails/ide/validate-response runs the configured security
 * policies on the reply (the same output enforcement as Gateway and Chat) and
 * records the violation.
 *
 * The editor has already shown the reply, and the hook has a short
 * timeout, so the call runs in a detached child process. The reply is handed
 * to the child over a pipe, never written to disk and never put in argv.
 */

import { spawn } from 'node:child_process';
import { hasToken, postResponseScan, type ResponseScanRequest } from './api';
import { createLogger } from './audit';

const { debug } = createLogger();

export const SCAN_RESPONSE_FLAG = '--scan-response';

/** Start the detached scan. Never throws, never waits on the network. */
export function scanResponseInBackground(req: ResponseScanRequest): void {
  if (!req.response?.trim() || !hasToken()) return;
  try {
    const script = process.argv[1];
    if (!script) return;
    const child = spawn(process.execPath, [script, SCAN_RESPONSE_FLAG], {
      detached: true,
      stdio: ['pipe', 'ignore', 'ignore'],
      windowsHide: true,
    });
    child.on('error', () => {});
    child.stdin?.on('error', () => {});
    child.stdin?.end(JSON.stringify(req));
    child.unref();
  } catch (err) {
    debug(`response-scan: spawn failed: ${(err as Error).message?.slice(0, 100)}`);
  }
}

/** Entry point of the detached child: read the request from stdin and post it. */
export async function runResponseScanFromStdin(): Promise<void> {
  let input = '';
  for await (const chunk of process.stdin) {
    input += chunk;
    if (input.length > 2_000_000) return;
  }
  try {
    postResponseScan(JSON.parse(input) as ResponseScanRequest);
  } catch (err) {
    debug(`response-scan: ${(err as Error).message?.slice(0, 100)}`);
  }
}
