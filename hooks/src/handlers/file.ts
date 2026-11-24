/**
 * Handlers: pre_read_code, pre_write_code, post_write_code
 *
 * Files that are sensitive by nature (.env, keys, certificates, cloud
 * credentials) are blocked by NAME. Files whose name only suggests sensitivity
 * (`secrets*`, `credentials*`) are decided by their CONTENT (RAI-4807 #9).
 * Writes that carry a value the firewall blocked earlier are blocked (#7).
 */

import * as path from 'node:path';
import { classifySensitiveFile, isSensitiveFile, loadPolicy, createLogger, scanTextLocal, entitySummary, formatEntities, inspectFile, findBlockedValues, reportBlock, reportScanBlockIfUnrecorded, WINDSURF_EVENT } from '../lib';
import type { WindsurfHookEvent } from '../types';

const logger = createLogger();
const policy = loadPolicy(undefined, process.env.ROOT_WORKSPACE_PATH);

export function handlePreReadCode(event: WindsurfHookEvent): { block: boolean; message?: string } {
  const filePath = event.tool_info?.file_path || '';
  const match = classifySensitiveFile(filePath, policy);

  if (match?.mode === 'inspect') {
    logger.incStat('totalScans');
    const r = inspectFile(filePath, match.rule, undefined, event.tool_info?.root_workspace_path);
    if (r.block) {
      logger.incStat('commandsBlocked');
      logger.audit({ event: 'pre_read_code', action: 'blocked', filePath, reason: `content (${match.rule})`, entities: entitySummary(r.scan.entities), trajectoryId: event.trajectory_id });
      reportScanBlockIfUnrecorded(event, r.scan, { event: WINDSURF_EVENT.pre_read_code });
      return { block: true, message: `Raidu Firewall: Blocked reading ${r.fileName}: it contains ${formatEntities(r.scan.entities)}.` };
    }
    logger.audit({ event: 'pre_read_code', action: 'allowed', filePath, inspected: r.outcome, rule: match.rule, trajectoryId: event.trajectory_id });
    return { block: false };
  }

  const hit = match?.rule;
  if (hit) {
    logger.incStat('commandsBlocked');
    logger.audit({ event: 'pre_read_code', action: 'blocked', filePath, reason: hit, trajectoryId: event.trajectory_id });
    reportBlock(event, {
      event: WINDSURF_EVENT.pre_read_code,
      kind: 'sensitive_file',
      detector: 'local',
      rule: hit,
      fileName: path.basename(filePath),
    });
    return { block: true, message: `Raidu Firewall: Blocked reading ${filePath.split('/').pop()} (policy: ${hit}).` };
  }

  logger.audit({ event: 'pre_read_code', action: 'allowed', filePath, trajectoryId: event.trajectory_id });
  return { block: false };
}

export function handlePreWriteCode(event: WindsurfHookEvent): { block: boolean; message?: string } {
  const filePath = event.tool_info?.file_path || '';

  // The agent must not write a value the firewall blocked earlier.
  const written = (event.tool_info?.edits || []).map((e) => e.new_string || '').join('\n');
  const reused = findBlockedValues(written);
  if (reused.length > 0) {
    logger.incStat('commandsBlocked');
    logger.audit({ event: 'pre_write_code', action: 'blocked', filePath, reason: 'previously_blocked_value', entities: reused.map((type) => ({ type, score: 1 })), trajectoryId: event.trajectory_id });
    reportBlock(event, { event: WINDSURF_EVENT.pre_write_code, kind: 'sensitive_data', detector: 'local', tool: 'write', entityTypes: reused, rule: 'previously_blocked_value' });
    return { block: true, message: `Raidu Firewall: Blocked writing to ${filePath.split('/').pop()}: it uses a value Raidu Firewall blocked earlier (${reused.join(', ')}). Ask the user to provide it through an approved workflow instead.` };
  }

  // Writing to a file named after a topic (`secrets*`) is not a leak; only
  // files sensitive by nature are protected from writes.
  const hit = isSensitiveFile(filePath, policy);

  if (hit) {
    logger.incStat('commandsBlocked');
    logger.audit({ event: 'pre_write_code', action: 'blocked', filePath, reason: hit, trajectoryId: event.trajectory_id });
    reportBlock(event, {
      event: WINDSURF_EVENT.pre_write_code,
      kind: 'sensitive_file',
      detector: 'local',
      tool: 'write',
      rule: hit,
      fileName: path.basename(filePath),
    });
    return { block: true, message: `Raidu Firewall: Blocked writing to ${filePath.split('/').pop()} (policy: ${hit}).` };
  }

  return { block: false };
}

export function handlePostWriteCode(event: WindsurfHookEvent): { block: false } {
  const edits = event.tool_info?.edits || [];
  const leaked: Array<{ type: string; score: number }> = [];

  for (const edit of edits) {
    if (edit.new_string) {
      leaked.push(...entitySummary(scanTextLocal(edit.new_string).entities));
    }
  }

  if (leaked.length > 0) {
    logger.incStat('secretsFound', leaked.length);
    logger.audit({ event: 'post_write_code', action: 'secret_written', filePath: event.tool_info?.file_path, entities: leaked, trajectoryId: event.trajectory_id });
  }

  return { block: false };
}
