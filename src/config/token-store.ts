/**
 * Where this editor keeps its Tower token on disk, and which tokens are its own.
 *
 * RAI-4807: Cursor and Windsurf used to share ~/.raidu/token. Whichever editor
 * paired last overwrote the other's token, the cross-window sync then adopted
 * the other editor's token as this editor's own, and Disconnect revoked the
 * other editor's pairing on Tower. Each editor now keeps its token under
 * ~/.raidu/<tool>/, and checks a token's `tool` claim before using it.
 *
 * No vscode import: kept pure so it can be checked with plain Node.
 */

import * as os from 'node:os';
import * as path from 'node:path';

/** This editor's id in Tower's tool registry. */
export const TOOL = 'windsurf';

export const RAIDU_HOME = path.join(os.homedir(), '.raidu');
/** This editor's own directory: its token and its pending-login state. */
export const TOOL_DIR = path.join(RAIDU_HOME, TOOL);
/** Read by this editor's hooks (hooks/src/lib/api.ts resolves the same path). */
export const TOKEN_FILE = path.join(TOOL_DIR, 'token');
export const PENDING_STATE_FILE = path.join(TOOL_DIR, 'login-state');
/** Shared by every editor before per-tool files. Read only to migrate this editor's own token. */
export const LEGACY_TOKEN_FILE = path.join(RAIDU_HOME, 'token');

export interface TokenClaims {
  sessionId: string | null;
  /** Registry id the token was issued for; null on a token from the legacy login, which names none. */
  tool: string | null;
}

/** Read-only decode of an IDE token's claims. Tower verifies the signature. */
export function tokenClaims(token: string): TokenClaims {
  try {
    const payload = token.split('.')[1];
    if (!payload) return { sessionId: null, tool: null };
    const json = JSON.parse(Buffer.from(payload.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf-8'));
    return {
      sessionId: typeof json?.sessionId === 'string' ? json.sessionId : null,
      tool: typeof json?.tool === 'string' ? json.tool : null,
    };
  } catch {
    return { sessionId: null, tool: null };
  }
}

/** The token was issued to a different coding tool: never use it, never revoke with it. */
export function isForeignToken(token: string, tool: string = TOOL): boolean {
  const claimed = tokenClaims(token).tool;
  return claimed !== null && claimed !== tool;
}

/** The token says it was issued to this tool. */
export function isOwnToken(token: string, tool: string = TOOL): boolean {
  return tokenClaims(token).tool === tool;
}
