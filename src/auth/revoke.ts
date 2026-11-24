/**
 * Revoking this editor's pairing on Tower when the user disconnects.
 *
 * Which sessions: every pairing the user has for this tool. "Disconnect Cursor"
 * means Cursor is disconnected: an earlier version spared same-tool pairings
 * that had been used, assuming another machine, but in testing the survivor
 * was this editor's own previous login (a re-login replaced the token locally
 * and never revoked the old one), and it kept the user counted as connected in
 * Tower's Tool connections view. Pairings for other tools stay connected.
 *
 * Order: the own session is revoked LAST. Revoking it first invalidates the
 * token every later revoke call authenticates with, which is how an earlier
 * version left the rest of the user's sessions live.
 */

interface ServerSession {
  id: string;
  tool?: string | null;
  lastUsedAt?: string | null;
}

/** The `sessionId` claim of an IDE token. Read-only decode; Tower verifies it. */
export function sessionIdFromToken(token: string): string | null {
  try {
    const payload = token.split('.')[1];
    if (!payload) return null;
    const json = JSON.parse(Buffer.from(payload.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf-8'));
    return typeof json?.sessionId === 'string' ? json.sessionId : null;
  } catch {
    return null;
  }
}

/** The sessions to revoke, in the order to revoke them (own session last). Pure, for testing. */
export function sessionsToRevoke(sessions: ServerSession[], ownId: string | null, tool: string): string[] {
  const others = sessions.filter((s) => s.id !== ownId && s.tool === tool).map((s) => s.id);
  if (ownId) return sessions.some((s) => s.id === ownId) ? [...others, ownId] : others;
  // Own session unknown (token without the claim): oldest first, since the
  // list comes newest first and ours is most likely the newest.
  return others.reverse();
}

/** Best effort: never throws, never blocks the local disconnect. */
export async function revokeOnServer(apiBase: string, token: string, tool: string): Promise<void> {
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
 * pairing live on Tower. Best effort, never throws.
 */
export async function revokeTokenSession(apiBase: string, token: string): Promise<void> {
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
