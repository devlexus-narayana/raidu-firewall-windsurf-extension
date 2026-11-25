/**
 * Revoking this editor's pairing on Tower when the user disconnects.
 *
 * Which sessions: every pairing the user has for THIS tool. "Disconnect Cursor"
 * means Cursor is disconnected: an earlier version spared same-tool pairings
 * that had been used, assuming another machine, but in testing the survivor
 * was this editor's own previous login (a re-login replaced the token locally
 * and never revoked the old one), and it kept the user counted as connected in
 * Tower's Tool connections view.
 *
 * Other tools' pairings are never touched (RAI-4807). When Cursor and Windsurf
 * shared ~/.raidu/token, Cursor held Windsurf's token, took its session for
 * "own", and its Disconnect revoked the Windsurf pairing. So: a token issued
 * to another tool revokes nothing, and the own session is revoked only when
 * Tower lists it under this tool. Tower refuses a cross-tool revoke as well.
 *
 * Order: the own session is revoked LAST. Revoking it first invalidates the
 * token every later revoke call authenticates with, which is how an earlier
 * version left the rest of the user's sessions live.
 */

import { isForeignToken, tokenClaims } from '../config/token-store';

interface ServerSession {
  id: string;
  tool?: string | null;
  lastUsedAt?: string | null;
}

/** The `sessionId` claim of an IDE token. Read-only decode; Tower verifies it. */
export function sessionIdFromToken(token: string): string | null {
  return tokenClaims(token).sessionId;
}

/** The sessions to revoke, in the order to revoke them (own session last). Pure, for testing. */
export function sessionsToRevoke(sessions: ServerSession[], ownId: string | null, tool: string): string[] {
  const mine = sessions.filter((s) => s.tool === tool);
  const others = mine.filter((s) => s.id !== ownId).map((s) => s.id);
  if (ownId) return mine.some((s) => s.id === ownId) ? [...others, ownId] : others;
  // Own session unknown (token without the claim): oldest first, since the
  // list comes newest first and ours is most likely the newest.
  return others.reverse();
}

/** Best effort: never throws, never blocks the local disconnect. */
export async function revokeOnServer(apiBase: string, token: string, tool: string): Promise<void> {
  if (isForeignToken(token, tool)) return;
  try {
    const headers = { Authorization: `Bearer ${token}` };
    const res = await fetch(`${apiBase}/api/auth/ide/sessions`, { headers });
    if (!res.ok) return;
    const sessions = (await res.json()) as ServerSession[];
    for (const id of sessionsToRevoke(sessions, sessionIdFromToken(token), tool)) {
      await fetch(`${apiBase}/api/auth/ide/revoke?session_id=${encodeURIComponent(id)}`, {
        method: 'POST',
        headers,
      });
    }
  } catch {
    // Best effort: the local token is cleared either way.
  }
}

/**
 * Revoke only the session a token belongs to. Called with the PREVIOUS token
 * when a new login replaces it, so re-connecting does not leave the old
 * pairing live on Tower. A token issued to another tool is left alone: it is
 * that tool's pairing, not one this login replaces. Best effort, never throws.
 */
export async function revokeTokenSession(apiBase: string, token: string, tool: string): Promise<void> {
  if (isForeignToken(token, tool)) return;
  const id = sessionIdFromToken(token);
  if (!id) return;
  try {
    await fetch(`${apiBase}/api/auth/ide/revoke?session_id=${encodeURIComponent(id)}`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${token}` },
    });
  } catch {
    // Best effort.
  }
}
