/**
 * Bounded, text-only file reads for content inspection.
 *
 * Used where a decision needs what is IN a file, not just its name:
 * attachments on a prompt, and files whose name only suggests sensitivity
 * (secrets_notes.pdf, credentials-guide.md). Never logs or returns more than
 * MAX_READ_BYTES, and never treats binary data as text.
 */

import * as fs from 'node:fs';

/** Read at most this much of a file for scanning. */
export const MAX_READ_BYTES = 1_000_000;

export type FileReadResult =
  | { ok: true; text: string; truncated: boolean }
  | { ok: false; reason: 'unreadable' | 'binary' | 'not_a_file' };

export function readTextForScan(filePath: string, maxBytes = MAX_READ_BYTES): FileReadResult {
  let fd: number | undefined;
  try {
    const st = fs.statSync(filePath);
    if (!st.isFile()) return { ok: false, reason: 'not_a_file' };
    fd = fs.openSync(filePath, 'r');
    const size = Math.min(st.size, maxBytes);
    const buf = Buffer.alloc(size);
    const read = fs.readSync(fd, buf, 0, size, 0);
    const data = buf.subarray(0, read);
    if (isBinary(data)) return { ok: false, reason: 'binary' };
    return { ok: true, text: data.toString('utf-8'), truncated: st.size > maxBytes };
  } catch {
    return { ok: false, reason: 'unreadable' };
  } finally {
    if (fd !== undefined) {
      try {
        fs.closeSync(fd);
      } catch {}
    }
  }
}

/** A NUL byte in the first 8KB, or a PDF/ZIP/image magic number, means binary. */
export function isBinary(data: Buffer): boolean {
  const head = data.subarray(0, 8192);
  if (head.includes(0)) return true;
  const sig = head.subarray(0, 4).toString('latin1');
  return sig.startsWith('%PDF') || sig.startsWith('PK\u0003\u0004') || sig.startsWith('\u0089PNG');
}

/** Is this string content we can scan as text? (beforeReadFile hands us the content.) */
export function isScannableText(text: string): boolean {
  return !text.slice(0, 8192).includes('\u0000') && !text.startsWith('%PDF');
}
