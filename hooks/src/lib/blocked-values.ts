/**
 * Values the firewall has blocked, remembered so they cannot come back later.
 *
 * Blocking a prompt stops that request, but the editor keeps the conversation:
 * the next turn can still carry the blocked API key in its trajectory, and the
 * agent can write it into a file or a command without the user pasting it
 * again (RAI-4807 #7). Every value a block was decided on is remembered here,
 * and every later tool call, command, MCP call and prompt is checked against
 * the list.
 *
 * Security:
 * - Only keyed hashes are stored (HMAC-SHA256 with a random per-install key),
 *   never the value. The key and the list are 0600 under ~/.raidu/logs.
 * - Entries expire after BLOCKED_VALUE_TTL_MS and the list is capped.
 */

import * as crypto from 'node:crypto';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { createLogger } from './audit';
import { LOG_DIR } from './paths';

const { debug } = createLogger(LOG_DIR);

const STORE_FILE = path.join(LOG_DIR, 'blocked-values.json');
const KEY_FILE = path.join(LOG_DIR, 'blocked-values.key');
export const BLOCKED_VALUE_TTL_MS = 7 * 24 * 60 * 60_000;
const MAX_ENTRIES = 1000;
/** Shorter values are too likely to recur by accident (ports, short ids). */
const MIN_VALUE_LENGTH = 8;

interface StoredValue {
  /** HMAC of the value. */
  h: string;
  /** Entity type, for the deny message and the Tower report. */
  type: string;
  /** Unix ms when first blocked. */
  at: number;
}

let cachedKey: Buffer | null = null;

function getKey(): Buffer | null {
  if (cachedKey) return cachedKey;
  try {
    cachedKey = Buffer.from(fs.readFileSync(KEY_FILE, 'utf-8').trim(), 'hex');
    if (cachedKey.length === 32) return cachedKey;
  } catch {}
  try {
    const key = crypto.randomBytes(32);
    // wx: never overwrite a key another hook process just created.
    fs.writeFileSync(KEY_FILE, key.toString('hex'), { mode: 0o600, flag: 'wx' });
    cachedKey = key;
    return key;
  } catch {
    try {
      cachedKey = Buffer.from(fs.readFileSync(KEY_FILE, 'utf-8').trim(), 'hex');
      return cachedKey.length === 32 ? cachedKey : null;
    } catch {
      return null;
    }
  }
}

function hmac(key: Buffer, value: string): string {
  return crypto.createHmac('sha256', key).update(value).digest('hex');
}

function load(): StoredValue[] {
  try {
    const list = JSON.parse(fs.readFileSync(STORE_FILE, 'utf-8')) as StoredValue[];
    if (!Array.isArray(list)) return [];
    const cutoff = Date.now() - BLOCKED_VALUE_TTL_MS;
    return list.filter((v) => v && typeof v.h === 'string' && v.at > cutoff);
  } catch {
    return [];
  }
}

/** Normalize the way a value may be re-quoted when it is reused. */
function normalize(value: string): string {
  return value.trim().replace(/^["'`]+|["'`,;]+$/g, '');
}

/** Remember the values a block was decided on. Never throws. */
export function rememberBlockedValues(values: Array<{ type: string; value: string }>): void {
  const key = getKey();
  if (!key) return;
  const fresh = values
    .map((v) => ({ type: v.type, value: normalize(v.value || '') }))
    .filter((v) => v.value.length >= MIN_VALUE_LENGTH);
  if (fresh.length === 0) return;

  try {
    const list = load();
    const known = new Set(list.map((v) => v.h));
    const now = Date.now();
    for (const v of fresh) {
      const h = hmac(key, v.value);
      if (!known.has(h)) {
        list.push({ h, type: v.type, at: now });
        known.add(h);
      }
    }
    fs.writeFileSync(STORE_FILE, JSON.stringify(list.slice(-MAX_ENTRIES)), { mode: 0o600 });
    debug(`blocked-values: remembered ${fresh.length}`);
  } catch (err) {
    debug(`blocked-values: write failed: ${(err as Error).message?.slice(0, 100)}`);
  }
}

/**
 * Candidate values in a piece of text: whitespace / quote / assignment
 * separated tokens, plus the substrings after `=` or `:` so that
 * OPENAI_API_KEY=sk-... and "key": "sk-..." both yield the bare value.
 */
export function candidateTokens(text: string): Set<string> {
  const out = new Set<string>();
  for (const raw of text.split(/[\s"'`(){}[\]<>,;|&\\]+/)) {
    if (raw.length < MIN_VALUE_LENGTH) continue;
    out.add(normalize(raw));
    for (const part of raw.split(/[=:]/)) {
      if (part.length >= MIN_VALUE_LENGTH) out.add(normalize(part));
    }
    // A URL or connection string may carry the value after '@' or '/'.
    if (raw.includes('://')) out.add(raw);
  }
  return out;
}

/**
 * Previously blocked values found in `text`, by entity type. Pass any values
 * a scanner extracted as `extra` so values containing separators still match.
 */
export function findBlockedValues(text: string, extra: string[] = []): string[] {
  return [...new Set(matchBlockedValues(text, extra).map((m) => m.type))];
}

/** The previously blocked values in `text`, with their entity types. */
export function matchBlockedValues(text: string, extra: string[] = []): Array<{ type: string; value: string }> {
  if (!text) return [];
  const list = load();
  if (list.length === 0) return [];
  const key = getKey();
  if (!key) return [];

  const byHash = new Map(list.map((v) => [v.h, v.type]));
  const found: Array<{ type: string; value: string }> = [];
  const tokens = candidateTokens(text);
  for (const e of extra) if (e) tokens.add(normalize(e));
  for (const t of tokens) {
    const type = byHash.get(hmac(key, t));
    if (type) found.push({ type, value: t });
  }
  return found;
}

/**
 * Remember the secret values in a protected file that was blocked by name.
 * Only values under a secret-sounding key, or long mixed-character values, so
 * ordinary settings (PORT=3000, HOST=localhost) never become "blocked".
 */
const SECRET_KEY_NAME = /key|secret|token|passw|pwd|credential|auth|dsn|database_url|conn/i;

export function rememberSecretsIn(text: string): void {
  try {
    const values: Array<{ type: string; value: string }> = [];
    for (const m of text.matchAll(/^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_.-]*)\s*[=:]\s*["']?([^"'\s#]+)/gm)) {
      const [, name, value] = m;
      const looksRandom = value.length >= 20 && /[0-9]/.test(value) && /[A-Za-z]/.test(value);
      if (SECRET_KEY_NAME.test(name) || looksRandom) values.push({ type: 'PROTECTED_FILE_VALUE', value });
    }
    rememberBlockedValues(values);
  } catch {}
}

// ---------------------------------------------------------------------------
// Conversations that still hold a blocked prompt
// ---------------------------------------------------------------------------

/**
 * Blocking a prompt does not take it out of the conversation. The editor keeps
 * the blocked message in the chat and sends it as history with the NEXT
 * prompt, so "give me our conversation context" got the blocked SSN, email and
 * phone back from the model without the user typing them again. A hook cannot
 * edit that history, so once a prompt is blocked, later prompts in the same
 * conversation are blocked while the blocked message is still in it.
 *
 * "Still in it" is read from the editor's transcript when the hook is given
 * one: the user can edit the blocked message to take the data out, and the
 * conversation carries on. The transcript is trusted to show a blocked message
 * only once it has been seen to (TRANSCRIPT_VERIFIED_FILE); until then, and
 * whenever the transcript cannot be read, or the block was decided on a file
 * or image rather than values, the conversation stays blocked as before.
 */
const TAINT_FILE = path.join(LOG_DIR, 'blocked-conversations.json');
const TRANSCRIPT_VERIFIED_FILE = path.join(LOG_DIR, 'transcript-verified');
const MAX_TAINTED = 500;
/** A larger transcript is not read; the conversation stays blocked. */
const MAX_TRANSCRIPT_BYTES = 10_000_000;

interface TaintedConversation {
  /** Unix ms when the first prompt was blocked. */
  at: number;
  /** Entity types that were blocked, for the message and the Tower report. */
  types: string[];
  /** HMACs of the blocked values, to look for in the transcript. */
  h?: string[];
  /** A block was decided on something other than values (a file, an image). */
  opaque?: boolean;
}

function loadTaint(): Record<string, TaintedConversation> {
  try {
    const all = JSON.parse(fs.readFileSync(TAINT_FILE, 'utf-8')) as Record<string, TaintedConversation>;
    const cutoff = Date.now() - BLOCKED_VALUE_TTL_MS;
    return Object.fromEntries(Object.entries(all).filter(([, v]) => v && v.at > cutoff));
  } catch {
    return {};
  }
}

function saveTaint(all: Record<string, TaintedConversation>): void {
  const kept = Object.entries(all)
    .sort((a, b) => a[1].at - b[1].at)
    .slice(-MAX_TAINTED);
  fs.writeFileSync(TAINT_FILE, JSON.stringify(Object.fromEntries(kept)), { mode: 0o600 });
}

/**
 * Record that a prompt in this conversation was blocked. Pass the blocked
 * values when the block was decided on values; without them (a protected file,
 * an image) the transcript cannot show the message is gone. Never throws.
 */
export function markConversationBlocked(conversationId: string | undefined, types: string[], values?: string[]): void {
  if (!conversationId) return;
  try {
    const all = loadTaint();
    const prev = all[conversationId];
    const key = getKey();
    const fresh =
      key && values
        ? values
            .map(normalize)
            .filter((v) => v.length >= MIN_VALUE_LENGTH)
            .map((v) => hmac(key, v))
        : [];
    const h = [...new Set([...(prev?.h ?? []), ...fresh])].slice(0, 50);
    all[conversationId] = {
      at: prev?.at ?? Date.now(),
      types: [...new Set([...(prev?.types ?? []), ...types])].slice(0, 20),
      h,
      // Values that could not be hashed (too short) cannot be looked for either.
      opaque: prev?.opaque || !values || fresh.length < values.length || h.length === 0,
    };
    saveTaint(all);
  } catch (err) {
    debug(`blocked-values: taint write failed: ${(err as Error).message?.slice(0, 100)}`);
  }
}

/** Every string in a transcript, JSON-unescaped where the transcript is JSON or JSON lines. */
function transcriptStrings(raw: string): string[] {
  const out: string[] = [];
  const walk = (v: unknown): void => {
    if (typeof v === 'string') out.push(v);
    else if (Array.isArray(v)) for (const x of v) walk(x);
    else if (v && typeof v === 'object') for (const x of Object.values(v)) walk(x);
  };
  try {
    walk(JSON.parse(raw));
    return out;
  } catch {}
  for (const line of raw.split('\n')) {
    if (!line.trim()) continue;
    try {
      walk(JSON.parse(line));
    } catch {
      out.push(line);
    }
  }
  return out;
}

/** Why a conversation is or is not still blocked, for the audit log. */
export type HeldCheck =
  | 'no_transcript'
  | 'transcript_unreadable'
  | 'transcript_too_large'
  | 'not_values'
  | 'held'
  | 'transcript_unverified'
  | 'cleared';

/**
 * Whether this conversation still holds a blocked prompt. `types` is null when
 * it does not (never blocked, or the blocked message has been edited out, in
 * which case the record is dropped).
 */
export function blockedConversation(
  conversationId: string | undefined,
  transcriptPath?: string | null,
): { types: string[] | null; check: HeldCheck | null } {
  if (!conversationId) return { types: null, check: null };
  const all = loadTaint();
  const taint = all[conversationId];
  if (!taint) return { types: null, check: null };
  const held = (check: HeldCheck) => ({ types: taint.types, check });

  if (taint.opaque || !taint.h?.length) return held('not_values');
  if (!transcriptPath) return held('no_transcript');
  const key = getKey();
  if (!key) return held('transcript_unreadable');

  let raw: string;
  try {
    const size = fs.statSync(transcriptPath).size;
    // TEMP RAI-4807 probe: what the transcript looks like, metadata only.
    debug(`transcript: ${size} bytes, ${path.extname(transcriptPath) || 'no ext'}`);
    if (size > MAX_TRANSCRIPT_BYTES) return held('transcript_too_large');
    raw = fs.readFileSync(transcriptPath, 'utf-8');
  } catch (err) {
    debug(`transcript: unreadable: ${(err as Error).message?.slice(0, 100)}`);
    return held('transcript_unreadable');
  }

  const wanted = new Set(taint.h);
  let found = false;
  for (const s of transcriptStrings(raw)) {
    for (const t of candidateTokens(s)) {
      // A value at the end of a sentence carries its full stop.
      for (const v of [t, t.replace(/[.!?)\]]+$/, '')]) {
        if (wanted.has(hmac(key, v))) found = true;
      }
      if (found) break;
    }
    if (found) break;
  }

  if (found) {
    // The transcript does show blocked messages: its silence can be trusted from now on.
    try {
      fs.writeFileSync(TRANSCRIPT_VERIFIED_FILE, String(Date.now()), { mode: 0o600 });
    } catch {}
    return held('held');
  }
  if (!fs.existsSync(TRANSCRIPT_VERIFIED_FILE)) return held('transcript_unverified');

  // The blocked message was edited out of the conversation.
  try {
    delete all[conversationId];
    saveTaint(all);
  } catch {}
  return { types: null, check: 'cleared' };
}
