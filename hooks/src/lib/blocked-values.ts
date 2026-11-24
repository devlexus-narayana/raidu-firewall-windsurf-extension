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
import * as os from 'node:os';
import * as path from 'node:path';
import { createLogger } from './audit';

const LOG_DIR = path.join(os.homedir(), '.raidu', 'logs');
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
  if (!text) return [];
  const list = load();
  if (list.length === 0) return [];
  const key = getKey();
  if (!key) return [];

  const byHash = new Map(list.map((v) => [v.h, v.type]));
  const found = new Set<string>();
  const tokens = candidateTokens(text);
  for (const e of extra) if (e) tokens.add(normalize(e));
  for (const t of tokens) {
    const type = byHash.get(hmac(key, t));
    if (type) found.add(type);
  }
  return [...found];
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
 * edit that history, so once a prompt is blocked, every later prompt in the
 * same conversation is blocked until the user starts a new chat.
 */
const TAINT_FILE = path.join(LOG_DIR, 'blocked-conversations.json');
const MAX_TAINTED = 500;

interface TaintedConversation {
  /** Unix ms when the first prompt was blocked. */
  at: number;
  /** Entity types that were blocked, for the message and the Tower report. */
  types: string[];
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

/** Record that a prompt in this conversation was blocked. Never throws. */
export function markConversationBlocked(conversationId: string | undefined, types: string[]): void {
  if (!conversationId) return;
  try {
    const all = loadTaint();
    const prev = all[conversationId];
    all[conversationId] = { at: prev?.at ?? Date.now(), types: [...new Set([...(prev?.types ?? []), ...types])].slice(0, 20) };
    const kept = Object.entries(all)
      .sort((a, b) => a[1].at - b[1].at)
      .slice(-MAX_TAINTED);
    fs.writeFileSync(TAINT_FILE, JSON.stringify(Object.fromEntries(kept)), { mode: 0o600 });
  } catch (err) {
    debug(`blocked-values: taint write failed: ${(err as Error).message?.slice(0, 100)}`);
  }
}

/** The blocked entity types if this conversation still holds a blocked prompt. */
export function blockedConversation(conversationId: string | undefined): string[] | null {
  if (!conversationId) return null;
  return loadTaint()[conversationId]?.types ?? null;
}
