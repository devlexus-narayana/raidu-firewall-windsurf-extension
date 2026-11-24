/**
 * Content decisions for files whose NAME only suggests sensitivity
 * (secret_notes.pdf, credentials-guide.md, a file under a `secrets*` match).
 *
 * RAI-4807 #9: these used to be blocked on the name alone, so safe files were
 * unreadable. Now the content decides:
 * - sensitive data found  -> block (and remember the values, see blocked-values.ts)
 * - nothing found         -> allow
 * - cannot be read as text (PDF, image, other binary) -> allow and audit it as
 *   unscanned. The name alone is not evidence; the formats that are sensitive by
 *   nature (.env, keys, certificates) are still blocked by name in policy.ts.
 */

import * as path from 'node:path';
import { rememberBlockedValues } from './blocked-values';
import { isScannableText, readTextForScan } from './content';
import { type FileScanResult, scanFileContent } from './redaction';

export type InspectionResult =
  | { block: true; scan: FileScanResult; fileName: string; rule: string }
  | { block: false; outcome: 'clean' | 'unscanned'; fileName: string; rule: string };

/**
 * @param content the file content when the editor already handed it to us
 *                (beforeReadFile); otherwise the file is read from disk.
 */
export function inspectFile(filePath: string, rule: string, content?: string, cwd?: string): InspectionResult {
  const fileName = path.basename(filePath);
  let text: string | undefined;
  if (typeof content === 'string') {
    if (isScannableText(content)) text = content;
  } else {
    const read = readTextForScan(path.resolve(cwd || process.env.ROOT_WORKSPACE_PATH || process.cwd(), filePath));
    if (read.ok) text = read.text;
  }
  if (text === undefined) return { block: false, outcome: 'unscanned', fileName, rule };
  if (!text.trim()) return { block: false, outcome: 'clean', fileName, rule };

  const scan = scanFileContent(fileName, text);
  if (scan.entities.length === 0) return { block: false, outcome: 'clean', fileName, rule };
  rememberBlockedValues(scan.entities);
  return { block: true, scan, fileName, rule };
}
