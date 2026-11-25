/**
 * This editor's files under ~/.raidu. Mirrors src/config/token-store.ts, which
 * the extension host writes them through (the two builds cannot share a module).
 *
 * RAI-4807: one directory per editor. Cursor and Windsurf used to share
 * ~/.raidu/token and ~/.raidu/logs, so each sent the other's token and each
 * editor's activity panel showed the other editor's events.
 */

import * as os from 'node:os';
import * as path from 'node:path';

export const TOOL = 'windsurf';
export const RAIDU_HOME = path.join(os.homedir(), '.raidu');
export const TOOL_DIR = path.join(RAIDU_HOME, TOOL);
export const TOKEN_FILE = path.join(TOOL_DIR, 'token');
/** The Tower the extension is connected to (its raidu.apiBase setting). */
export const TOWER_FILE = path.join(TOOL_DIR, 'tower');
export const LOG_DIR = path.join(TOOL_DIR, 'logs');
/** Shared by every editor before per-editor files; read only for this editor's own token. */
export const LEGACY_TOKEN_FILE = path.join(RAIDU_HOME, 'token');
