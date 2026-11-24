/**
 * Revoking this editor's pairing on Tower when the user disconnects.
 *
 * Which sessions: this editor's own (the `sessionId` claim in its token), and
 * any pairing for the same tool that has never been used: a login that minted
 * a token the editor never received (a second window, a console "connect with
 * a link" that did not complete). Left alone, those keep the user counted as
 * connected in Tower's Tool connections view. Pairings for other tools, and
 * same-tool pairings in use elsewhere (another machine), stay connected.
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
  const others = sessions.filter((s) => s.id !== ownId && s.tool === tool && !s.lastUsedAt).map((s) => s.id);
  if (ownId) return sessions.some((s) => s.id === ownId) ? [...others, ownId] : others;
  // Own session unknown (token without the claim): every pairing for this tool,
  // oldest first, since the list comes newest first and ours is the newest.
  return sessions
    .filter((s) => s.tool === tool)
    .map((s) => s.id)
    .reverse();
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
