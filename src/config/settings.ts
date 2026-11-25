/**
 * Typed wrapper around vscode.workspace.getConfiguration('raidu').
 *
 * Security:
 * - IDE token stored in SecretStorage (OS keychain) for the extension
 * - Token also written to ~/.raidu/<tool>/token (0600 perms) for hooks to read;
 *   one file per editor, so Cursor and Windsurf never overwrite or adopt each
 *   other's token (see token-store.ts)
 * - Token NEVER stored in settings.json (plaintext, world-readable)
 */

import * as fs from 'node:fs';
import * as vscode from 'vscode';
import { isForeignToken, isOwnToken, LEGACY_TOKEN_FILE, PENDING_STATE_FILE, TOKEN_FILE, TOOL_DIR } from './token-store';

export { TOKEN_FILE } from './token-store';

const SECTION = 'raidu';
const PENDING_STATE_TTL_MS = 15 * 60 * 1000;

let _secrets: vscode.SecretStorage | undefined;

/** Call once during activation to hand in the SecretStorage instance. */
export function initSecretStorage(secrets: vscode.SecretStorage): void {
  _secrets = secrets;
}

function cfg(): vscode.WorkspaceConfiguration {
  return vscode.workspace.getConfiguration(SECTION);
}

// ---- Readers ---------------------------------------------------------------

export function getApiBase(): string {
  return cfg().get<string>('apiBase', 'https://sandbox.raidu.com');
}

export async function getToken(): Promise<string | undefined> {
  if (_secrets) {
    const secret = await _secrets.get('ideToken');
    if (secret && isForeignToken(secret)) {
      // Adopted from another editor through the old shared token file. It is
      // that editor's pairing: drop it here, and never revoke with it.
      await _secrets.delete('ideToken');
    } else if (secret) {
      return secret;
    }
  }
  return readTokenFile();
}

export function getWorkspaceId(): string | undefined {
  return cfg().get<string>('workspaceId') || undefined;
}

export function getEnvironmentId(): string | undefined {
  return cfg().get<string>('environmentId') || undefined;
}

export async function isConnected(): Promise<boolean> {
  return !!(await getToken());
}

// ---- Writers ---------------------------------------------------------------

export async function setToken(token: string): Promise<void> {
  // Primary: OS keychain via SecretStorage
  if (_secrets) {
    await _secrets.store('ideToken', token);
  }

  // Secondary: token file with restricted perms for hooks to read
  // Hooks run as standalone Node.js and can't access SecretStorage
  writeTokenFile(token);

  // Remove any legacy token from settings.json
  await cfg().update('ideToken', undefined, vscode.ConfigurationTarget.Global);
}

export async function setWorkspaceId(id: string): Promise<void> {
  await cfg().update('workspaceId', id, vscode.ConfigurationTarget.Global);
}

export async function setEnvironmentId(id: string): Promise<void> {
  await cfg().update('environmentId', id, vscode.ConfigurationTarget.Global);
}

function writeTokenFile(token: string): void {
  try {
    fs.mkdirSync(TOOL_DIR, { recursive: true, mode: 0o700 });
    fs.writeFileSync(TOKEN_FILE, token, { mode: 0o600 });
  } catch {}
}

function readFileToken(file: string): string | undefined {
  try {
    return fs.readFileSync(file, 'utf-8').trim() || undefined;
  } catch {
    return undefined;
  }
}

/** Reads this editor's token file, shared by its windows (never by another editor). */
export function readTokenFile(): string | undefined {
  const token = readFileToken(TOKEN_FILE);
  return token && !isForeignToken(token) ? token : undefined;
}

/**
 * Move this editor's token off the shared ~/.raidu/token, once, at activation.
 *
 * The hooks read only ~/.raidu/<tool>/token now, so it is written from
 * SecretStorage (or from the shared file, when that token says it is ours).
 * The shared file is removed only when it holds this editor's token; another
 * editor's token stays for that editor, which may not have updated yet.
 */
export async function migrateTokenStorage(): Promise<void> {
  const legacy = readFileToken(LEGACY_TOKEN_FILE);
  const current = await getToken();
  if (!current && legacy && isOwnToken(legacy)) {
    await setToken(legacy);
  } else if (current && !readFileToken(TOKEN_FILE)) {
    writeTokenFile(current);
  }
  if (legacy && (isOwnToken(legacy) || legacy === current)) {
    try {
      fs.unlinkSync(LEGACY_TOKEN_FILE);
    } catch {}
  }
}

/** Mirror a token written by another window into this window's SecretStorage. */
export async function adoptToken(token: string): Promise<void> {
  if (_secrets) {
    await _secrets.store('ideToken', token);
  }
}

// ---- Pending login state (shared across editor windows) -------------------
// The OAuth redirect is delivered by the OS to whichever editor window it
// chooses, not necessarily the one that started login. Persisting the state
// lets any window running the extension validate and complete the callback.

export function savePendingState(state: string): void {
  try {
    fs.mkdirSync(TOOL_DIR, { recursive: true, mode: 0o700 });
    fs.writeFileSync(PENDING_STATE_FILE, JSON.stringify({ state, createdAt: Date.now() }), { mode: 0o600 });
  } catch {}
}

export function readPendingState(): string | undefined {
  try {
    const { state, createdAt } = JSON.parse(fs.readFileSync(PENDING_STATE_FILE, 'utf-8'));
    if (typeof state === 'string' && Date.now() - createdAt < PENDING_STATE_TTL_MS) return state;
  } catch {}
  return undefined;
}

export function clearPendingState(): void {
  try {
    fs.unlinkSync(PENDING_STATE_FILE);
  } catch {}
}

/** Clears all stored credentials and identifiers. */
export async function clearAll(): Promise<void> {
  if (_secrets) {
    await _secrets.delete('ideToken');
  }
  // Delete this editor's token file (never another editor's)
  try {
    fs.unlinkSync(TOKEN_FILE);
  } catch {}

  const config = cfg();
  await config.update('ideToken', undefined, vscode.ConfigurationTarget.Global);
  await config.update('workspaceId', undefined, vscode.ConfigurationTarget.Global);
  await config.update('environmentId', undefined, vscode.ConfigurationTarget.Global);
}
