import { detectHardcodedSecret } from '../core/call-guard.js';
import { inspectAndSanitizeToolsList } from '../core/poison-detector.js';
import type {
  McpConfigFile,
  McpServerConfig,
  McpToolDefinition,
  SecurityFinding
} from '../core/types.js';

function maskSecretPreview(val: string): string {
  if (val.length <= 8) return `${val.slice(0, 2)}***`;
  return `${val.slice(0, 4)}...${val.slice(-3)} (${val.length} chars)`;
}

function auditServerEntry(
  serverName: string,
  server: McpServerConfig
): SecurityFinding[] {
  const findings: SecurityFinding[] = [];
  const prefix = `mcpServers.${serverName}`;

  // 1. Check env block for hardcoded plaintext secrets
  if (server.env && typeof server.env === 'object') {
    for (const [k, v] of Object.entries(server.env)) {
      if (typeof v !== 'string') continue;
      const check = detectHardcodedSecret(k, v);
      if (check.isSecret) {
        findings.push({
          severity: 'critical',
          category: 'hardcoded_secret',
          target: `${prefix}.env.${k}`,
          message: `Hardcoded plaintext secret in MCP config (${check.reason})`,
          evidence: `${k}=${maskSecretPreview(v)}`
        });
      }
    }
  }

  // 2. Check args array for inline tokens/passwords or unpinned npx packages
  if (Array.isArray(server.args)) {
    server.args.forEach((arg, idx) => {
      if (typeof arg !== 'string') return;
      const check = detectHardcodedSecret(`arg_${idx}`, arg);
      if (check.isSecret) {
        findings.push({
          severity: 'critical',
          category: 'hardcoded_secret',
          target: `${prefix}.args[${idx}]`,
          message: `Hardcoded secret passed in CLI argument (${check.reason})`,
          evidence: maskSecretPreview(arg)
        });
      }
    });

    const dashIdx = server.args.indexOf('--');
    const effectiveCmd =
      server.args.includes('mcp-shield') && dashIdx !== -1
        ? server.args[dashIdx + 1]
        : server.command;
    const effectiveArgs =
      server.args.includes('mcp-shield') && dashIdx !== -1
        ? server.args.slice(dashIdx + 2)
        : server.args;

    if (effectiveCmd === 'npx' && effectiveArgs.includes('-y')) {
      const pkgArg = effectiveArgs.find(
        (a) => typeof a === 'string' && !a.startsWith('-')
      );
      if (pkgArg && !/@\d/.test(pkgArg)) {
        findings.push({
          severity: 'medium',
          category: 'unpinned_package',
          target: `${prefix}.args`,
          message: `Unpinned npm package "${pkgArg}" executed with "npx -y" (supply-chain risk)`,
          evidence: `${effectiveCmd} ${effectiveArgs.join(' ')}`
        });
      }
    }
  }

  return findings;
}

export function auditMcpJsonString(rawJson: string): SecurityFinding[] {
  const parsed = JSON.parse(rawJson) as Record<string, unknown>;
  const findings: SecurityFinding[] = [];

  // Case 1: MCP config file (.mcp.json / claude_desktop_config.json / settings.json)
  const serversMap = (parsed.mcpServers ?? parsed.servers) as
    | Record<string, McpServerConfig>
    | undefined;

  if (serversMap && typeof serversMap === 'object') {
    for (const [serverName, serverConfig] of Object.entries(serversMap)) {
      if (serverConfig && typeof serverConfig === 'object') {
        findings.push(...auditServerEntry(serverName, serverConfig));
      }
    }
  }

  // Case 2: tools/list JSON payload or array of tool definitions
  const toolsArray = Array.isArray(parsed)
    ? (parsed as McpToolDefinition[])
    : Array.isArray(parsed.tools)
      ? (parsed.tools as McpToolDefinition[])
      : Array.isArray((parsed.result as Record<string, unknown> | undefined)?.tools)
        ? ((parsed.result as Record<string, unknown>).tools as McpToolDefinition[])
        : null;

  if (toolsArray) {
    const { findings: poisonFindings } = inspectAndSanitizeToolsList(toolsArray);
    findings.push(...poisonFindings);
  }

  return findings;
}
