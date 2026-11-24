/**
 * Handlers: pre_mcp_tool_use, post_mcp_tool_use
 */

import { scanText, formatEntities, entitySummary, createLogger, reportBlock, reportScanBlockIfUnrecorded, findBlockedValues, rememberBlockedValues, WINDSURF_EVENT } from '../lib';
import type { WindsurfHookEvent } from '../types';

const logger = createLogger();

export function handlePreMCPToolUse(event: WindsurfHookEvent): { block: boolean; message?: string } {
  const input = JSON.stringify(event.tool_info?.mcp_tool_arguments || '');
  const toolName = `${event.tool_info?.mcp_server_name}:${event.tool_info?.mcp_tool_name}`;

  // A value blocked earlier must not be sent by the agent (RAI-4807 #7).
  const reused = findBlockedValues(input);
  if (reused.length > 0) {
    logger.incStat('commandsBlocked');
    logger.audit({ event: 'pre_mcp_tool_use', action: 'blocked', tool: toolName, reason: 'previously_blocked_value', entities: reused.map((type) => ({ type, score: 1 })), trajectoryId: event.trajectory_id });
    reportBlock(event, { event: WINDSURF_EVENT.pre_mcp_tool_use, kind: 'sensitive_data', detector: 'local', tool: toolName, entityTypes: reused, rule: 'previously_blocked_value' });
    return { block: true, message: `Raidu Firewall: Blocked MCP tool ${toolName}. Its input uses a value Raidu Firewall blocked earlier (${reused.join(', ')}).` };
  }

  const scan = scanText(input, undefined, logger.debug);
  const { entities } = scan;

  if (entities.length > 0) {
    logger.incStat('commandsBlocked');
    rememberBlockedValues(entities);
    logger.audit({ event: 'pre_mcp_tool_use', action: 'blocked', tool: toolName, entities: entitySummary(entities), trajectoryId: event.trajectory_id });
    reportScanBlockIfUnrecorded(event, scan, { event: WINDSURF_EVENT.pre_mcp_tool_use, tool: toolName });
    return { block: true, message: `Raidu Firewall: Blocked MCP tool ${toolName}. Input contains ${formatEntities(entities)}.` };
  }

  return { block: false };
}

export function handlePostMCPToolUse(event: WindsurfHookEvent): { block: false } {
  logger.audit({ event: 'post_mcp_tool_use', action: 'logged', trajectoryId: event.trajectory_id });
  return { block: false };
}
