/**
 * Complete uninstall. Removes every trace of Raidu from the system.
 *
 *  1. Clears credentials (SecretStorage + token file + settings)
 *  2. Removes hooks from ~/.codeium/windsurf/hooks.json
 *  3. Deletes this editor's ~/.raidu/<tool>/ (token, login state), and the
 *     whole ~/.raidu/ (logs, policy cache) only when no other editor is still
 *     paired through it
 *  4. Removes plugin directory if present
 */

import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { clearAll } from '../config/settings';
import { LEGACY_TOKEN_FILE, RAIDU_HOME, TOOL_DIR } from '../config/token-store';
import { removeHooks } from './hooks-installer';

const PLUGIN_DIR = path.join(os.homedir(), '.codeium', 'windsurf', 'plugins', 'local', 'raidu-firewall');

export async function cleanup(): Promise<void> {
  const cleaned: string[] = [];

  // 1. Clear credentials and settings
  try {
    await clearAll();
    cleaned.push('credentials cleared');
  } catch (err) {
    console.warn('[Raidu cleanup] credentials:', err);
  }

  // 2. Remove hooks from ~/.codeium/windsurf/hooks.json
  try {
    removeHooks();
    cleaned.push('hooks removed');
  } catch (err) {
    console.warn('[Raidu cleanup] hooks:', err);
  }

  // 3. Delete this editor's ~/.raidu/<tool>/, then ~/.raidu/ itself unless
  //    another editor (Windsurf, say) still keeps its token there.
  try {
    fs.rmSync(TOOL_DIR, { recursive: true, force: true });
    if (fs.existsSync(RAIDU_HOME) && !otherEditorPaired()) {
      fs.rmSync(RAIDU_HOME, { recursive: true, force: true });
      cleaned.push('~/.raidu deleted');
    } else {
      cleaned.push(`${TOOL_DIR} deleted`);
    }
  } catch (err) {
    console.warn('[Raidu cleanup] ~/.raidu:', err);
  }

  // 4. Remove plugin directory
  try {
    if (fs.existsSync(PLUGIN_DIR)) {
      fs.rmSync(PLUGIN_DIR, { recursive: true, force: true });
      cleaned.push('plugin dir deleted');
    }
  } catch (err) {
    console.warn('[Raidu cleanup] plugin dir:', err);
  }

  console.log(`[Raidu cleanup] ${cleaned.length > 0 ? cleaned.join(', ') : 'nothing to clean'}`);
}

/** Another editor's token is still under ~/.raidu: its own directory, or the old shared file. */
function otherEditorPaired(): boolean {
  if (fs.existsSync(LEGACY_TOKEN_FILE)) return true;
  try {
    return fs
      .readdirSync(RAIDU_HOME, { withFileTypes: true })
      .some(
        (d) =>
          d.isDirectory() &&
          path.join(RAIDU_HOME, d.name) !== TOOL_DIR &&
          fs.existsSync(path.join(RAIDU_HOME, d.name, 'token')),
      );
  } catch {
    return false;
  }
}
