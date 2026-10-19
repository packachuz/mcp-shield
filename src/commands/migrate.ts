import { detectHardcodedSecret } from '../core/call-guard.js';
import type { McpConfigFile, McpServerConfig } from '../core/types.js';

export interface MigrationResult {
  migratedConfig: McpConfigFile;
  extractedSecrets: Record<string, string>;
  migratedServerCount: number;
}

export function migrateMcpConfigObject(
  config: McpConfigFile,
  options: {
    envFilePath?: string;
    vaultFilePath?: string;
  } = {}
): MigrationResult {
  const clone = structuredClone(config);
  const extractedSecrets: Record<string, string> = {};
  let migratedServerCount = 0;

  const serversKey = clone.mcpServers ? 'mcpServers' : clone.servers ? 'servers' : null;
  if (!serversKey) {
    return { migratedConfig: clone, extractedSecrets, migratedServerCount: 0 };
  }

  const serversMap = clone[serversKey] as Record<string, McpServerConfig>;
  const targetFlag = options.vaultFilePath
    ? ['--vault', options.vaultFilePath]
    : ['-e', options.envFilePath ?? '.env'];

  for (const [serverName, server] of Object.entries(serversMap)) {
    if (!server || typeof server !== 'object' || !server.command) continue;

    // Skip if already wrapped with mcp-shield
    const existingArgs = Array.isArray(server.args) ? server.args : [];
    if (
      server.command === 'mcp-shield' ||
      (server.command === 'npx' && existingArgs.includes('mcp-shield'))
    ) {
      continue;
    }

    let hasExtractedSecret = false;
    const remainingEnv: Record<string, string> = {};

    if (server.env && typeof server.env === 'object') {
      for (const [envKey, envVal] of Object.entries(server.env)) {
        if (typeof envVal !== 'string') continue;
        const check = detectHardcodedSecret(envKey, envVal);
        if (check.isSecret) {
          // Namespace collision protection if two servers use the same env var name with different values
          const secretVarName =
            extractedSecrets[envKey] && extractedSecrets[envKey] !== envVal
              ? `${serverName.toUpperCase().replace(/[^A-Z0-9]/g, '_')}_${envKey}`
              : envKey;
          extractedSecrets[secretVarName] = envVal;
          hasExtractedSecret = true;
        } else {
          remainingEnv[envKey] = envVal;
        }
      }
    }

    if (hasExtractedSecret) {
      const origCmd = server.command;
      const origArgs = existingArgs;

      server.command = 'npx';
      server.args = [
        '-y',
        'mcp-shield',
        'wrap',
        ...targetFlag,
        '--',
        origCmd,
        ...origArgs
      ];

      if (Object.keys(remainingEnv).length > 0) {
        server.env = remainingEnv;
      } else {
        delete server.env;
      }

      migratedServerCount += 1;
    }
  }

  return {
    migratedConfig: clone,
    extractedSecrets,
    migratedServerCount
  };
}
