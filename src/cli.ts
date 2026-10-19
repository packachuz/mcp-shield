#!/usr/bin/env node
import fs from 'node:fs';
import { parseArgs } from 'node:util';
import { auditMcpJsonString } from './commands/audit.js';
import { migrateMcpConfigObject } from './commands/migrate.js';
import { runStdioFirewallProxy } from './commands/wrap.js';
import {
  encryptEnvVault,
  formatDotEnv,
  loadSecretsFromSources
} from './core/env-loader.js';
import type { McpConfigFile, SecurityFinding } from './core/types.js';

const HELP_TEXT = `
mcp-shield — MCP Server Secret Injector (envFile), Tool-Poisoning Scanner & JSON-RPC Firewall

USAGE:
  mcp-shield <command> [options]

COMMANDS:
  wrap [options] -- <cmd> [args...]   Wrap an MCP server with .env/vault secret injection & real-time JSON-RPC firewall
  audit <file>                        Scan .mcp.json, claude_desktop_config.json, or tools/list JSON for secrets & tool poisoning
  migrate <file>                      Extract plaintext secrets from .mcp.json into .env (or encrypted vault) and rewrite config

OPTIONS:
  -e, --env-file <file>       Load environment variables from .env file (can be repeated)
      --vault <file>          Load or save AES-256-GCM encrypted secret vault (.mcp-vault.json)
  -p, --passphrase <secret>   Passphrase for encrypting/decrypting --vault (or set MCP_SHIELD_PASSPHRASE)
  -o, --output <file>         Output file for migrated config (defaults to in-place or stdout)
      --strict-tools          Drop poisoned tools completely from tools/list instead of sanitizing descriptions
      --allow-path <pattern>  Allow specific path pattern in tools/call (can be repeated)
      --json                  Output audit findings as JSON
      --fail-on-findings      Exit with code 1 if audit detects any security findings
  -q, --quiet                 Suppress stderr firewall warning logs during wrap
  -h, --help                  Show this help message
  -v, --version               Show version

EXAMPLES:
  # 1. Audit an existing .mcp.json or claude_desktop_config.json for hardcoded secrets & risks
  mcp-shield audit .mcp.json --fail-on-findings

  # 2. Auto-migrate hardcoded secrets out of .mcp.json into .env (or encrypted .mcp-vault.json)
  mcp-shield migrate .mcp.json --env-file .env -o .mcp.safe.json

  # 3. Wrap any stdio MCP server with .env secret injection and real-time JSON-RPC firewall
  mcp-shield wrap --env-file .env -- npx -y @modelcontextprotocol/server-github
`.trim();

function formatFindingsTable(findings: SecurityFinding[], sourceLabel: string): string {
  const lines: string[] = [];
  lines.push(`\n=== mcp-shield Security Audit (${sourceLabel}) ===`);
  lines.push(`Total Findings: ${findings.length}`);

  if (findings.length === 0) {
    lines.push('✓ No hardcoded secrets, tool poisoning, or risky configurations detected.');
    return lines.join('\n');
  }

  lines.push('');
  lines.push(
    `${'SEVERITY'.padEnd(10)} ${'CATEGORY'.padEnd(23)} ${'TARGET'.padEnd(36)} ${'MESSAGE'}`
  );
  lines.push('-'.repeat(105));

  for (const f of findings) {
    const sev = f.severity.toUpperCase().padEnd(10);
    const cat = f.category.padEnd(23);
    const tgt =
      f.target.length > 34
        ? `${f.target.slice(0, 31)}...`.padEnd(36)
        : f.target.padEnd(36);
    lines.push(`${sev} ${cat} ${tgt} ${f.message}`);
  }
  lines.push('');
  return lines.join('\n');
}

export async function runCli(argv: string[] = process.argv.slice(2)): Promise<number> {
  // Split argv around "--" for the `wrap` command
  const doubleDashIdx = argv.indexOf('--');
  const shieldArgs = doubleDashIdx === -1 ? argv : argv.slice(0, doubleDashIdx);
  const childCmdArgs = doubleDashIdx === -1 ? [] : argv.slice(doubleDashIdx + 1);

  const { values, positionals } = parseArgs({
    args: shieldArgs,
    allowPositionals: true,
    options: {
      env: { type: 'string', short: 'e', multiple: true },
      'env-file': { type: 'string', multiple: true },
      vault: { type: 'string' },
      passphrase: { type: 'string', short: 'p' },
      output: { type: 'string', short: 'o' },
      'strict-tools': { type: 'boolean', default: false },
      'allow-path': { type: 'string', multiple: true },
      json: { type: 'boolean', default: false },
      'fail-on-findings': { type: 'boolean', default: false },
      quiet: { type: 'boolean', short: 'q', default: false },
      help: { type: 'boolean', short: 'h', default: false },
      version: { type: 'boolean', short: 'v', default: false }
    }
  });

  if (values.help || positionals.length === 0) {
    process.stdout.write(HELP_TEXT + '\n');
    return 0;
  }

  if (values.version) {
    process.stdout.write('0.1.0\n');
    return 0;
  }

  const command = positionals[0]!;

  try {
    if (command === 'audit') {
      const targetFile = positionals[1];
      if (!targetFile) {
        throw new Error('Usage: mcp-shield audit <config-or-tools-json-file>');
      }
      const raw = fs.readFileSync(targetFile, 'utf8');
      const findings = auditMcpJsonString(raw);

      if (values.json) {
        process.stdout.write(
          JSON.stringify({ file: targetFile, count: findings.length, findings }, null, 2) + '\n'
        );
      } else {
        process.stdout.write(formatFindingsTable(findings, targetFile) + '\n');
      }

      if (values['fail-on-findings'] && findings.length > 0) {
        return 1;
      }
      return 0;
    }

    const envFiles = [...(values.env ?? []), ...(values['env-file'] ?? [])];

    if (command === 'migrate') {
      const targetFile = positionals[1];
      if (!targetFile) {
        throw new Error('Usage: mcp-shield migrate <.mcp.json>');
      }
      const raw = fs.readFileSync(targetFile, 'utf8');
      const config = JSON.parse(raw) as McpConfigFile;
      const envFilePath = envFiles[0] ?? '.env';
      const vaultFilePath = values.vault;

      const { migratedConfig, extractedSecrets, migratedServerCount } =
        migrateMcpConfigObject(config, { envFilePath, vaultFilePath });

      const secretCount = Object.keys(extractedSecrets).length;
      if (secretCount > 0) {
        if (vaultFilePath) {
          const pass = values.passphrase ?? process.env.MCP_SHIELD_PASSPHRASE;
          if (!pass) {
            throw new Error(
              'Migrating to an encrypted --vault requires --passphrase or MCP_SHIELD_PASSPHRASE.'
            );
          }
          const encrypted = encryptEnvVault(extractedSecrets, pass);
          fs.writeFileSync(vaultFilePath, JSON.stringify(encrypted, null, 2) + '\n', {
            encoding: 'utf8',
            mode: 0o600
          });
        } else {
          const dotEnvContent = formatDotEnv(extractedSecrets);
          fs.writeFileSync(envFilePath, dotEnvContent, {
            encoding: 'utf8',
            mode: 0o600
          });
        }
      }

      const formattedConfig = JSON.stringify(migratedConfig, null, 2) + '\n';
      if (values.output) {
        fs.writeFileSync(values.output, formattedConfig, 'utf8');
      } else {
        process.stdout.write(formattedConfig);
      }

      process.stderr.write(
        `✓ Extracted ${secretCount} secret(s) across ${migratedServerCount} MCP server(s).\n`
      );
      return 0;
    }

    if (command === 'wrap' || command === 'run') {
      const cmdToSpawn = childCmdArgs.length > 0 ? childCmdArgs : positionals.slice(1);
      if (cmdToSpawn.length === 0) {
        throw new Error(
          'Usage: mcp-shield wrap [-e .env] -- <command> [args...]'
        );
      }

      const childEnv = loadSecretsFromSources({
        envFiles,
        vaultFile: values.vault,
        passphrase: values.passphrase
      });

      const exitCode = await runStdioFirewallProxy(
        cmdToSpawn[0]!,
        cmdToSpawn.slice(1),
        childEnv,
        {
          strictTools: Boolean(values['strict-tools']),
          allowPaths: values['allow-path'],
          quiet: Boolean(values.quiet)
        }
      );
      return exitCode;
    }

    throw new Error(`Unknown command "${command}". Run "mcp-shield --help" for usage.`);
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    process.stderr.write(`Error: ${msg}\n`);
    return 1;
  }
}

const isMain =
  process.argv[1] &&
  (process.argv[1].endsWith('cli.js') || process.argv[1].endsWith('cli.ts'));

if (isMain) {
  runCli().then((code) => {
    process.exitCode = code;
  });
}
