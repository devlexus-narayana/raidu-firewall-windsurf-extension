/**
 * Handlers: pre_run_command, post_run_command
 * Scan shell commands, block exfiltration, detect PII in output.
 */

import { scanText, scanTextLocal, formatEntities, entitySummary, isExfiltrationCommand, findSensitiveAccess, loadPolicy, createLogger, reportBlock, reportScanBlockIfUnrecorded, findBlockedValues, rememberBlockedValues, inspectFile, WINDSURF_EVENT } from '../lib';
import type { FileToInspect } from '../lib';
import type { WindsurfHookEvent } from '../types';

const logger = createLogger();
const policy = loadPolicy();

export function handlePreRunCommand(event: WindsurfHookEvent): { block: boolean; message?: string } {
  const command = event.tool_info?.command_line || '';
  if (!command) return { block: false };

  logger.incStat('totalScans');

  // A value blocked earlier must not be run by the agent (RAI-4807 #7).
  const reused = findBlockedValues(command);
  if (reused.length > 0) {
    logger.incStat('commandsBlocked');
    logger.audit({ event: 'pre_run_command', action: 'blocked', reason: 'previously_blocked_value', entities: reused.map((type) => ({ type, score: 1 })), trajectoryId: event.trajectory_id });
    reportBlock(event, { event: WINDSURF_EVENT.pre_run_command, kind: 'sensitive_data', detector: 'local', tool: 'Shell', entityTypes: reused, rule: 'previously_blocked_value' });
    return { block: true, message: `Raidu Firewall: Blocked command. It uses a value Raidu Firewall blocked earlier (${reused.join(', ')}).` };
  }

  // Check if command references sensitive files
  const toInspect: FileToInspect[] = [];
  const hit = findSensitiveAccess({ command }, policy, toInspect);
  if (hit) {
    logger.incStat('commandsBlocked');
    logger.audit({ event: 'pre_run_command', action: 'blocked', command: command.slice(0, 500), reason: hit.message, trajectoryId: event.trajectory_id });
    reportBlock(event, {
      event: WINDSURF_EVENT.pre_run_command,
      kind: hit.kind,
      detector: 'local',
      tool: 'Shell',
      rule: hit.rule,
      fileName: hit.fileName,
    });
    return { block: true, message: `Raidu Firewall: ${hit.message}` };
  }

  // Files whose name only suggests sensitivity: their content decides (RAI-4807 #9).
  for (const f of toInspect.slice(0, 5)) {
    const r = inspectFile(f.filePath, f.rule, undefined, event.tool_info?.cwd);
    if (r.block) {
      logger.incStat('commandsBlocked');
      logger.audit({ event: 'pre_run_command', action: 'blocked', command: command.slice(0, 500), reason: `content (${f.rule})`, entities: entitySummary(r.scan.entities), trajectoryId: event.trajectory_id });
      reportScanBlockIfUnrecorded(event, r.scan, { event: WINDSURF_EVENT.pre_run_command, tool: 'Shell' });
      return { block: true, message: `Raidu Firewall: Blocked access to ${r.fileName}: it contains ${formatEntities(r.scan.entities)}.` };
    }
  }

  // Scan for secrets in command
  const scan = scanText(command, undefined, logger.debug);
  const { entities } = scan;
  if (entities.length > 0) {
    logger.incStat('piiFound', entities.length);
    logger.incStat('commandsBlocked');
    rememberBlockedValues(entities);
    logger.audit({ event: 'pre_run_command', action: 'blocked', command: command.slice(0, 500), entities: entitySummary(entities), trajectoryId: event.trajectory_id });
    reportScanBlockIfUnrecorded(event, scan, { event: WINDSURF_EVENT.pre_run_command, tool: 'Shell' });
    return { block: true, message: `Raidu Firewall: Blocked command. Contains ${formatEntities(entities)}.` };
  }

  // Check exfiltration
  if (isExfiltrationCommand(command)) {
    logger.incStat('commandsBlocked');
    logger.audit({ event: 'pre_run_command', action: 'blocked', command: command.slice(0, 500), reason: 'data exfiltration', trajectoryId: event.trajectory_id });
    reportBlock(event, { event: WINDSURF_EVENT.pre_run_command, kind: 'exfiltration', detector: 'local', tool: 'Shell' });
    return { block: true, message: 'Raidu Firewall: Blocked command. Data exfiltration pattern detected.' };
  }

  logger.audit({ event: 'pre_run_command', action: 'allowed', command: command.slice(0, 200), trajectoryId: event.trajectory_id });
  return { block: false };
}

export function handlePostRunCommand(event: WindsurfHookEvent): { block: false } {
  // post hooks can't block, just detect leaks
  const output = (event.tool_info as Record<string, unknown>)?.output as string || '';
  if (output) {
    const { entities } = scanTextLocal(output);
    if (entities.length > 0) {
      logger.incStat('piiFound', entities.length);
      logger.audit({ event: 'post_run_command', action: 'leak_detected', entities: entitySummary(entities), trajectoryId: event.trajectory_id });
    }
  }
  return { block: false };
}
