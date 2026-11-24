/**
 * Handler: post_cascade_response
 * Sends the reply to Tower's response scan (RAI-4807 #6) and scans it locally
 * for PII leaks (post-hoc, can't block).
 */

import { scanTextLocal, entitySummary, createLogger, findBlockedValues, scanResponseInBackground } from '../lib';
import type { WindsurfHookEvent } from '../types';

const logger = createLogger();

const RESPONSE_BLOCKED = [
  /permission denied/i,
  /access is blocked/i,
  /excluded/i,
  /can't read.*\.env/i,
  /cannot read.*\.env/i,
  /blocked.*\.env/i,
];

export function handlePostCascadeResponse(event: WindsurfHookEvent): { block: false } {
  const text = event.tool_info?.response || '';
  if (!text) return { block: false };

  // Tower scans the reply against the configured security policies and
  // records the violation. Runs detached: the reply is already shown.
  scanResponseInBackground({ response: text, ideConversationId: event.trajectory_id, ideGenerationId: event.execution_id });

  // A value blocked earlier in a reply means the trajectory still carries it
  // (RAI-4807 #7). The reply cannot be blocked; record it.
  const reused = findBlockedValues(text);
  if (reused.length > 0) {
    logger.audit({ event: 'post_cascade_response', action: 'blocked_value_in_response', entities: reused.map((type) => ({ type, score: 1 })), trajectoryId: event.trajectory_id });
  }

  // Detect file access blocks from response text
  if (RESPONSE_BLOCKED.some((p) => p.test(text))) {
    logger.incStat('commandsBlocked');
    logger.audit({ event: 'post_cascade_response', action: 'data_blocked', reason: 'Raidu Firewall blocked sensitive file access', trajectoryId: event.trajectory_id });
    return { block: false };
  }

  // Scan for PII leaks
  const { entities } = scanTextLocal(text);
  if (entities.length > 0) {
    logger.incStat('piiFound', entities.length);
    logger.audit({ event: 'post_cascade_response', action: 'leak_in_response', entities: entitySummary(entities), trajectoryId: event.trajectory_id });
  }

  return { block: false };
}
