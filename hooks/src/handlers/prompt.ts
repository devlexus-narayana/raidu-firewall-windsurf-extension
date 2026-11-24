/**
 * Handler: pre_user_prompt
 * Scans prompt for PII via API + local fallback.
 */

import { scanText, formatEntities, redactText, copyToClipboard, entitySummary, createLogger, reportBlock, reportScanBlockIfUnrecorded, findBlockedValues, rememberBlockedValues, WINDSURF_EVENT } from '../lib';

const NEW_CHAT_HINT = 'Start a new chat so the blocked value is not reused from this conversation.';
import type { WindsurfHookEvent } from '../types';

const logger = createLogger();

export function handlePreUserPrompt(event: WindsurfHookEvent): { block: boolean; message?: string } {
  const prompt = event.tool_info?.user_prompt || '';
  if (!prompt) return { block: false };

  logger.incStat('totalScans');
  const result = scanText(prompt, undefined, logger.debug);

  if (result.entities.length > 0) {
    logger.incStat('piiFound', result.entities.length);
    logger.incStat('promptsBlocked');
    // Remembered so the agent cannot reuse them later in the trajectory (RAI-4807 #7).
    rememberBlockedValues(result.entities);

    const safeVersion = result.sanitizedInput || redactText(prompt, result.entities);
    if (safeVersion !== prompt) copyToClipboard(safeVersion, logger.debug);

    logger.audit({
      event: 'pre_user_prompt',
      action: 'blocked',
      source: result.source,
      entities: entitySummary(result.entities),
      scanTimeMs: result.scanTimeMs,
      trajectoryId: event.trajectory_id,
    });
    reportScanBlockIfUnrecorded(event, result, { event: WINDSURF_EVENT.pre_user_prompt });

    return {
      block: true,
      message: `Raidu Firewall: Detected ${formatEntities(result.entities)} in your prompt. A compliant version is in your clipboard. ${NEW_CHAT_HINT}`,
    };
  }

  // A value blocked earlier must not come back in a later prompt either.
  const reused = findBlockedValues(prompt);
  if (reused.length > 0) {
    logger.incStat('promptsBlocked');
    logger.audit({ event: 'pre_user_prompt', action: 'blocked', reason: 'previously_blocked_value', entities: reused.map((type) => ({ type, score: 1 })), trajectoryId: event.trajectory_id });
    reportBlock(event, { event: WINDSURF_EVENT.pre_user_prompt, kind: 'sensitive_data', detector: 'local', entityTypes: reused, rule: 'previously_blocked_value' });
    return { block: true, message: `Raidu Firewall: This prompt contains a value Raidu Firewall blocked earlier (${reused.join(', ')}). ${NEW_CHAT_HINT}` };
  }

  logger.audit({ event: 'pre_user_prompt', action: 'allowed', scanTimeMs: result.scanTimeMs, trajectoryId: event.trajectory_id });
  return { block: false };
}
