/**
 * Handler: pre_user_prompt
 * Scans prompt for PII via API + local fallback.
 */

import { scanText, scanTextLocal, formatEntities, redactText, copyToClipboard, entitySummary, createLogger, reportBlock, reportScanBlockIfUnrecorded, findBlockedValues, rememberBlockedValues, blockedConversation, markConversationBlocked, WINDSURF_EVENT } from '../lib';

const NEW_CHAT_HINT = 'Start a new conversation: this one now holds the blocked message, and further prompts here are blocked.';
import type { WindsurfHookEvent } from '../types';

const logger = createLogger();

export function handlePreUserPrompt(event: WindsurfHookEvent): { block: boolean; message?: string } {
  const prompt = event.tool_info?.user_prompt || '';
  if (!prompt) return { block: false };

  // Windsurf keeps a blocked prompt in the trajectory and sends it as history
  // with every later prompt, so the model still sees the blocked data. A hook
  // cannot edit that history: block the conversation until a new one.
  const heldTypes = blockedConversation(event.trajectory_id);
  if (heldTypes) {
    logger.incStat('promptsBlocked');
    // Not sent anywhere, but remember what it carries so the values stay blocked.
    rememberBlockedValues(scanTextLocal(prompt).entities);
    logger.audit({ event: 'pre_user_prompt', action: 'blocked', reason: 'conversation_holds_blocked_prompt', trajectoryId: event.trajectory_id });
    reportBlock(event, { event: WINDSURF_EVENT.pre_user_prompt, kind: 'sensitive_data', detector: 'local', entityTypes: heldTypes, rule: 'conversation_holds_blocked_prompt' });
    return { block: true, message: 'Raidu Firewall: This conversation still contains a message Raidu Firewall blocked, and it would be sent to the model again with this prompt. Start a new conversation to continue.' };
  }

  logger.incStat('totalScans');
  const result = scanText(prompt, undefined, logger.debug);

  if (result.entities.length > 0) {
    logger.incStat('piiFound', result.entities.length);
    logger.incStat('promptsBlocked');
    // Remembered so the agent cannot reuse them later in the trajectory (RAI-4807 #7).
    rememberBlockedValues(result.entities);
    markConversationBlocked(event.trajectory_id, result.entities.map((e) => e.type));

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
    markConversationBlocked(event.trajectory_id, reused);
    logger.audit({ event: 'pre_user_prompt', action: 'blocked', reason: 'previously_blocked_value', entities: reused.map((type) => ({ type, score: 1 })), trajectoryId: event.trajectory_id });
    reportBlock(event, { event: WINDSURF_EVENT.pre_user_prompt, kind: 'sensitive_data', detector: 'local', entityTypes: reused, rule: 'previously_blocked_value' });
    return { block: true, message: `Raidu Firewall: This prompt contains a value Raidu Firewall blocked earlier (${reused.join(', ')}). ${NEW_CHAT_HINT}` };
  }

  logger.audit({ event: 'pre_user_prompt', action: 'allowed', scanTimeMs: result.scanTimeMs, trajectoryId: event.trajectory_id });
  return { block: false };
}
