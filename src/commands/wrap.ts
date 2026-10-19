import { spawn } from 'node:child_process';
import readline from 'node:readline';
import {
  evaluateToolCallRequest,
  scrubToolCallResponseText
} from '../core/call-guard.js';
import { inspectAndSanitizeToolsList } from '../core/poison-detector.js';
import type {
  FirewallOptions,
  JsonRpcMessage,
  McpToolDefinition,
  SecurityFinding
} from '../core/types.js';

export function processClientToServerMessage(
  rawLine: string,
  options: FirewallOptions = {}
): {
  forwardLine: string | null;
  immediateClientReply: string | null;
  findings: SecurityFinding[];
} {
  const trimmed = rawLine.trim();
  if (!trimmed.startsWith('{')) {
    return { forwardLine: rawLine, immediateClientReply: null, findings: [] };
  }

  try {
    const msg = JSON.parse(trimmed) as JsonRpcMessage;
    if (msg.method === 'tools/call' && msg.params && typeof msg.params === 'object') {
      const toolName =
        typeof msg.params.name === 'string' ? msg.params.name : 'unknown_tool';
      const args = msg.params.arguments as Record<string, unknown> | undefined;

      const evalRes = evaluateToolCallRequest(toolName, args, options);
      if (!evalRes.allowed) {
        const reasons = evalRes.findings.map((f) => f.message).join('; ');
        const blockedReply: JsonRpcMessage = {
          jsonrpc: '2.0',
          id: msg.id ?? null,
          result: {
            isError: true,
            content: [
              {
                type: 'text',
                text: `[mcp-shield] Blocked unsafe tool call to "${toolName}": ${reasons}`
              }
            ]
          }
        };
        return {
          forwardLine: null,
          immediateClientReply: JSON.stringify(blockedReply),
          findings: evalRes.findings
        };
      }
    }

    return { forwardLine: rawLine, immediateClientReply: null, findings: [] };
  } catch {
    return { forwardLine: rawLine, immediateClientReply: null, findings: [] };
  }
}

export function processServerToClientMessage(
  rawLine: string,
  options: FirewallOptions = {}
): {
  forwardLine: string;
  findings: SecurityFinding[];
} {
  const trimmed = rawLine.trim();
  if (!trimmed.startsWith('{')) {
    return { forwardLine: rawLine, findings: [] };
  }

  try {
    const msg = JSON.parse(trimmed) as JsonRpcMessage;
    const allFindings: SecurityFinding[] = [];
    let modified = false;

    if (msg.result && typeof msg.result === 'object') {
      // 1. Inspect tools/list response
      if (Array.isArray(msg.result.tools)) {
        const { tools, findings } = inspectAndSanitizeToolsList(
          msg.result.tools as McpToolDefinition[],
          { strictTools: options.strictTools }
        );
        if (findings.length > 0) {
          msg.result.tools = tools;
          allFindings.push(...findings);
          modified = true;
        }
      }

      // 2. Inspect tools/call response content[].text for leaked secrets
      if (!options.disableOutputScrub && Array.isArray(msg.result.content)) {
        for (const item of msg.result.content as Array<Record<string, unknown>>) {
          if (item && item.type === 'text' && typeof item.text === 'string') {
            const { scrubbed, findings } = scrubToolCallResponseText(item.text);
            if (findings.length > 0) {
              item.text = scrubbed;
              allFindings.push(...findings);
              modified = true;
            }
          }
        }
      }
    }

    return {
      forwardLine: modified ? JSON.stringify(msg) : rawLine,
      findings: allFindings
    };
  } catch {
    return { forwardLine: rawLine, findings: [] };
  }
}

export function runStdioFirewallProxy(
  command: string,
  args: string[],
  childEnv: Record<string, string>,
  options: FirewallOptions & { quiet?: boolean } = {}
): Promise<number> {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, {
      env: childEnv,
      stdio: ['pipe', 'pipe', 'inherit'],
      shell: process.platform === 'win32' && /\.(?:cmd|bat)$/i.test(command)
    });

    child.on('error', (err) => {
      reject(err);
    });

    const clientRl = readline.createInterface({
      input: process.stdin,
      terminal: false
    });

    const serverRl = readline.createInterface({
      input: child.stdout,
      terminal: false
    });

    clientRl.on('line', (line) => {
      const { forwardLine, immediateClientReply, findings } =
        processClientToServerMessage(line, options);

      if (!options.quiet && findings.length > 0) {
        for (const f of findings) {
          process.stderr.write(
            `[mcp-shield][${f.severity.toUpperCase()}] ${f.message} (${f.target})\n`
          );
        }
      }

      if (immediateClientReply) {
        process.stdout.write(immediateClientReply + '\n');
      } else if (forwardLine !== null && child.stdin.writable) {
        child.stdin.write(forwardLine + '\n');
      }
    });

    clientRl.on('close', () => {
      if (child.stdin.writable) {
        child.stdin.end();
      }
    });

    serverRl.on('line', (line) => {
      const { forwardLine, findings } = processServerToClientMessage(line, options);

      if (!options.quiet && findings.length > 0) {
        for (const f of findings) {
          process.stderr.write(
            `[mcp-shield][${f.severity.toUpperCase()}] ${f.message} (${f.target})\n`
          );
        }
      }

      process.stdout.write(forwardLine + '\n');
    });

    child.on('close', (code) => {
      clientRl.close();
      serverRl.close();
      resolve(code ?? 0);
    });
  });
}
